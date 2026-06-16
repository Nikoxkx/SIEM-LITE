"""
Base collector classes and collector registry.

All collectors inherit from BaseCollector and implement the collect() method
to gather log data from their source and emit events into the pipeline.
"""

import time
import logging
import threading
from abc import ABC, abstractmethod
from collections import deque
from datetime import datetime, timezone
from enum import Enum

logger = logging.getLogger(__name__)


class CollectorStatus(Enum):
    """Collector lifecycle status."""
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    PAUSED = "paused"
    ERROR = "error"
    STOPPING = "stopping"


class CollectorResult:
    """Result of a collection operation."""

    __slots__ = ("success", "events_collected", "bytes_collected",
                 "error", "duration", "metadata")

    def __init__(self, success=True, events_collected=0, bytes_collected=0,
                 error=None, duration=0.0, metadata=None):
        self.success = success
        self.events_collected = events_collected
        self.bytes_collected = bytes_collected
        self.error = error
        self.duration = duration
        self.metadata = metadata or {}

    def to_dict(self):
        return {
            "success": self.success,
            "events_collected": self.events_collected,
            "bytes_collected": self.bytes_collected,
            "error": self.error,
            "duration": self.duration,
            "metadata": self.metadata,
        }


class BaseCollector(ABC):
    """Abstract base class for all log collectors.

    Collectors gather log data from a source and pass it to a handler callback
    which processes it into events.

    Attributes:
        name: Collector name.
        source: Source identifier for collected logs.
        status: Current collector status.
        config: Collector configuration dict.
    """

    def __init__(self, name, source=None, config=None):
        self.name = name
        self.source = source or name
        self.config = config or {}
        self.status = CollectorStatus.STOPPED
        self._event_handler = None
        self._error_handler = None
        self._stop_event = threading.Event()
        self._thread = None
        self._lock = threading.RLock()

        # Statistics
        self._stats = {
            "events_collected": 0,
            "bytes_collected": 0,
            "errors": 0,
            "last_collection": None,
            "started_at": None,
            "uptime": 0,
        }

        # Event buffer for batching
        self._buffer = deque(maxlen=self.config.get("buffer_size", 10000))
        self._buffer_lock = threading.Lock()

    def set_event_handler(self, handler):
        """Set the callback for processing collected events.

        The handler should accept (raw_data, metadata) and return processed events.
        """
        self._event_handler = handler

    def set_error_handler(self, handler):
        """Set the error handler callback."""
        self._error_handler = handler

    @abstractmethod
    def collect(self):
        """Perform a single collection operation.

        Returns:
            CollectorResult
        """
        pass

    def start(self, blocking=False):
        """Start the collector.

        Args:
            blocking: If True, run in the current thread; otherwise spawn a thread.
        """
        if self.status in (CollectorStatus.RUNNING, CollectorStatus.STARTING):
            logger.warning("Collector %s already running", self.name)
            return

        self.status = CollectorStatus.STARTING
        self._stop_event.clear()
        self._stats["started_at"] = datetime.now(timezone.utc)

        if blocking:
            self.status = CollectorStatus.RUNNING
            self._run_loop()
        else:
            self._thread = threading.Thread(target=self._run_loop, daemon=True,
                                            name=f"collector-{self.name}")
            self._thread.start()
            self.status = CollectorStatus.RUNNING

        logger.info("Collector %s started", self.name)

    def stop(self, timeout=5.0):
        """Stop the collector."""
        if self.status == CollectorStatus.STOPPED:
            return
        self.status = CollectorStatus.STOPPING
        self._stop_event.set()

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)

        self.status = CollectorStatus.STOPPED
        self._on_stop()
        logger.info("Collector %s stopped", self.name)

    def pause(self):
        """Pause the collector."""
        self.status = CollectorStatus.PAUSED

    def resume(self):
        """Resume a paused collector."""
        if self.status == CollectorStatus.PAUSED:
            self.status = CollectorStatus.RUNNING

    def _run_loop(self):
        """Main collection loop."""
        try:
            self._on_start()
            poll_interval = self.config.get("poll_interval", 1.0)

            while not self._stop_event.is_set():
                if self.status == CollectorStatus.PAUSED:
                    time.sleep(0.5)
                    continue

                try:
                    result = self.collect()
                    if result and result.success:
                        self._update_stats(result)
                    elif result and not result.success:
                        self._stats["errors"] += 1
                        if self._error_handler:
                            self._error_handler(result.error, self)
                except Exception as exc:
                    self._stats["errors"] += 1
                    logger.error("Collector %s error: %s", self.name, exc, exc_info=True)
                    if self._error_handler:
                        self._error_handler(exc, self)

                if self._stop_event.wait(poll_interval):
                    break

        except Exception as exc:
            self.status = CollectorStatus.ERROR
            logger.error("Collector %s fatal error: %s", self.name, exc, exc_info=True)
        finally:
            self.status = CollectorStatus.STOPPED

    def _on_start(self):
        """Called when collector starts. Override in subclasses."""
        pass

    def _on_stop(self):
        """Called when collector stops. Override in subclasses."""
        pass

    def _emit(self, raw_data, metadata=None):
        """Emit collected data to the event handler."""
        if metadata is None:
            metadata = {}
        metadata.setdefault("source", self.source)
        metadata.setdefault("collector", self.name)
        metadata.setdefault("collected_at", datetime.now(timezone.utc).isoformat())

        # Buffer for batching
        self._buffer.append((raw_data, metadata))

        if self._event_handler:
            try:
                self._event_handler(raw_data, metadata)
            except Exception as exc:
                logger.error("Event handler error for collector %s: %s", self.name, exc)
                self._stats["errors"] += 1
        else:
            logger.debug("Collector %s: no event handler set, data buffered", self.name)

    def _emit_batch(self, items):
        """Emit multiple items at once."""
        for raw_data, metadata in items:
            self._emit(raw_data, metadata or {})

    def _update_stats(self, result):
        """Update collection statistics."""
        self._stats["events_collected"] += result.events_collected
        self._stats["bytes_collected"] += result.bytes_collected
        self._stats["last_collection"] = datetime.now(timezone.utc).isoformat()
        if self._stats["started_at"]:
            delta = datetime.now(timezone.utc) - self._stats["started_at"]
            self._stats["uptime"] = delta.total_seconds()

    def get_stats(self):
        """Get collector statistics."""
        stats = dict(self._stats)
        stats["status"] = self.status.value
        stats["name"] = self.name
        stats["source"] = self.source
        stats["buffer_size"] = len(self._buffer)
        if stats["started_at"]:
            delta = datetime.now(timezone.utc) - stats["started_at"]
            stats["uptime"] = delta.total_seconds()
        return stats

    def reset_stats(self):
        """Reset collector statistics."""
        self._stats = {
            "events_collected": 0,
            "bytes_collected": 0,
            "errors": 0,
            "last_collection": None,
            "started_at": datetime.now(timezone.utc) if self.status == CollectorStatus.RUNNING else None,
            "uptime": 0,
        }

    def flush_buffer(self):
        """Flush buffered events. Returns list of (raw_data, metadata)."""
        with self._buffer_lock:
            items = list(self._buffer)
            self._buffer.clear()
        return items

    @property
    def is_running(self):
        return self.status == CollectorStatus.RUNNING


class CollectorRegistry:
    """Registry of collectors."""

    def __init__(self):
        self._collectors = {}
        self._lock = threading.RLock()

    def register(self, collector):
        """Register a collector."""
        with self._lock:
            self._collectors[collector.name] = collector
        logger.info("Registered collector: %s", collector.name)
        return collector

    def unregister(self, name):
        """Unregister a collector."""
        with self._lock:
            collector = self._collectors.pop(name, None)
            if collector:
                collector.stop()
            return collector is not None

    def get(self, name):
        """Get a collector by name."""
        return self._collectors.get(name)

    def start_all(self):
        """Start all registered collectors."""
        for collector in self._collectors.values():
            if not collector.is_running:
                collector.start()

    def stop_all(self):
        """Stop all registered collectors."""
        for collector in list(self._collectors.values()):
            collector.stop()

    def get_all_stats(self):
        """Get statistics for all collectors."""
        return {name: c.get_stats() for name, c in self._collectors.items()}

    def list_collectors(self):
        """List all collectors."""
        return [
            {"name": name, "source": c.source, "status": c.status.value,
             "running": c.is_running}
            for name, c in self._collectors.items()
        ]
