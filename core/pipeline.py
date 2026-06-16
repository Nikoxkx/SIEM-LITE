"""
Processing pipeline: orchestrates the event processing flow.

The pipeline connects collectors -> parsers -> normalizer -> enrichment ->
threat intel -> rules -> correlation -> anomaly -> risk scoring -> storage.

Events flow through the pipeline stages, each adding or modifying data.
"""

import time
import logging
import threading
from datetime import datetime, timezone
from collections import deque
from concurrent.futures import ThreadPoolExecutor

from ..models.event import Event, EventStatus
from ..parsers.base import ParserRegistry
from ..parsers.syslog_parser import SyslogParser, RFC3164Parser, RFC5424Parser
from ..parsers.json_parser import JSONParser, KeyValueParser
from ..parsers.cef_parser import CEFParser
from ..parsers.leef_parser import LEEFParser
from ..parsers.apache_parser import ApacheAccessParser, NginxAccessParser, ApacheErrorParser
from ..parsers.regex_parser import RegexParser, GrokParser

logger = logging.getLogger(__name__)


class PipelineStage:
    """A single stage in the processing pipeline."""

    def __init__(self, name, processor, config=None):
        self.name = name
        self.processor = processor
        self.config = config or {}
        self._events_processed = 0
        self._errors = 0
        self._total_time = 0.0

    def process(self, event):
        """Process an event through this stage."""
        start = time.perf_counter()
        try:
            result = self.processor(event)
            self._events_processed += 1
            self._total_time += time.perf_counter() - start
            return result if result is not None else event
        except Exception as exc:
            self._errors += 1
            logger.error("Pipeline stage '%s' error: %s", self.name, exc, exc_info=True)
            return event

    def get_stats(self):
        avg_time = self._total_time / max(self._events_processed, 1) * 1000
        return {
            "name": self.name,
            "events_processed": self._events_processed,
            "errors": self._errors,
            "avg_time_ms": avg_time,
        }


class ProcessingPipeline:
    """Event processing pipeline.

    Manages the flow of events through processing stages:
    1. Parse: Convert raw data to structured fields
    2. Normalize: Map to canonical schema
    3. Enrich: Add contextual data (GeoIP, assets, etc.)
    4. Threat Intel: Match against known threats
    5. Rules: Evaluate detection rules
    6. Correlation: Check correlation patterns
    7. Anomaly: Statistical anomaly detection
    8. Risk Score: Compute risk score
    9. Store: Persist the event

    The pipeline can run in synchronous or asynchronous mode.
    """

    def __init__(self, parser_registry=None, normalizer=None, enrichment_engine=None,
                 threat_intel=None, rules_engine=None, correlation_engine=None,
                 anomaly_engine=None, risk_scorer=None, storage=None,
                 aggregation_engine=None, config=None):
        self.config = config or {}
        self.parser_registry = parser_registry or self._create_default_parser_registry()
        self.normalizer = normalizer
        self.enrichment = enrichment_engine
        self.threat_intel = threat_intel
        self.rules_engine = rules_engine
        self.correlation_engine = correlation_engine
        self.anomaly_engine = anomaly_engine
        self.risk_scorer = risk_scorer
        self.storage = storage
        self.aggregation_engine = aggregation_engine

        self._stages = []
        self._lock = threading.RLock()
        self._queue = deque(maxlen=self.config.get("queue_size", 100000))
        self._worker_thread = None
        self._running = False
        self._batch_size = self.config.get("batch_size", 100)
        self._flush_interval = self.config.get("flush_interval", 1.0)

        # Statistics
        self._stats = {
            "events_ingested": 0,
            "events_processed": 0,
            "events_stored": 0,
            "events_dropped": 0,
            "errors": 0,
            "queue_size": 0,
            "processing_rate": 0.0,
        }
        self._rate_window = deque(maxlen=60)  # events per second window

        self._build_stages()

    def _create_default_parser_registry(self):
        """Create the default parser registry with all built-in parsers."""
        registry = ParserRegistry()
        registry.register(JSONParser())
        registry.register(CEFParser())
        registry.register(LEEFParser())
        registry.register(RFC5424Parser())
        registry.register(RFC3164Parser())
        registry.register(SyslogParser())
        registry.register(ApacheAccessParser())
        registry.register(NginxAccessParser())
        registry.register(ApacheErrorParser())
        registry.register(KeyValueParser())
        return registry

    def _build_stages(self):
        """Build the pipeline stages."""
        if self.normalizer:
            self._stages.append(PipelineStage("normalize", self._stage_normalize))
        if self.enrichment:
            self._stages.append(PipelineStage("enrich", self._stage_enrich))
        if self.threat_intel:
            self._stages.append(PipelineStage("threat_intel", self._stage_threat_intel))
        if self.rules_engine:
            self._stages.append(PipelineStage("rules", self._stage_rules))
        if self.correlation_engine:
            self._stages.append(PipelineStage("correlation", self._stage_correlation))
        if self.anomaly_engine:
            self._stages.append(PipelineStage("anomaly", self._stage_anomaly))
        if self.risk_scorer:
            self._stages.append(PipelineStage("risk_score", self._stage_risk_score))
        if self.aggregation_engine:
            self._stages.append(PipelineStage("aggregate", self._stage_aggregate))

    # --- Stage processors ---

    def _stage_normalize(self, event):
        """Normalization stage."""
        if self.normalizer and event.get("raw_data") and not event.get("event_type"):
            # Re-normalize from raw if needed
            pass
        return event

    def _stage_enrich(self, event):
        """Enrichment stage."""
        if self.enrichment:
            return self.enrichment.enrich(event)
        return event

    def _stage_threat_intel(self, event):
        """Threat intelligence stage."""
        if self.threat_intel:
            return self.threat_intel.enrich_event(event)
        return event

    def _stage_rules(self, event):
        """Rules evaluation stage."""
        if self.rules_engine:
            self.rules_engine.evaluate(event)
        return event

    def _stage_correlation(self, event):
        """Correlation stage."""
        if self.correlation_engine:
            self.correlation_engine.process(event)
        return event

    def _stage_anomaly(self, event):
        """Anomaly detection stage."""
        if self.anomaly_engine:
            self.anomaly_engine.process(event)
        return event

    def _stage_risk_score(self, event):
        """Risk scoring stage."""
        if self.risk_scorer:
            score = self.risk_scorer.score(event)
            event.set("risk_score", score)
        return event

    def _stage_aggregate(self, event):
        """Aggregation stage."""
        if self.aggregation_engine:
            self.aggregation_engine.process(event)
        return event

    # --- Ingestion ---

    def ingest(self, raw_data, metadata=None):
        """Ingest raw log data into the pipeline.

        Args:
            raw_data: Raw log string.
            metadata: Optional metadata dict.

        Returns:
            The processed Event, or None on failure.
        """
        self._stats["events_ingested"] += 1

        if metadata is None:
            metadata = {}

        try:
            # Parse raw data
            parsed = self.parser_registry.auto_parse(raw_data)
            if not parsed or not parsed.is_valid:
                # Store as raw event
                parsed_fields = {"raw_data": str(raw_data), "event_type": "unknown"}
            else:
                parsed_fields = parsed.fields

            # Create event from parsed data
            if self.normalizer:
                event = self.normalizer.normalize(
                    parsed_fields,
                    source_log=metadata.get("source", "unknown")
                )
            else:
                event = Event(data=parsed_fields, source_log=metadata.get("source", "unknown"))

            # Add collection metadata
            for key, value in metadata.items():
                if key not in ("source", "collector", "collected_at"):
                    event.set(f"_meta_{key}", value)

            event.set("collection_method", metadata.get("collection_method", "unknown"))

            # Process through stages
            return self.process(event)

        except Exception as exc:
            self._stats["errors"] += 1
            logger.error("Pipeline ingestion error: %s", exc, exc_info=True)
            return None

    def ingest_event(self, event):
        """Ingest a pre-constructed Event into the pipeline."""
        self._stats["events_ingested"] += 1
        return self.process(event)

    def ingest_batch(self, items):
        """Ingest a batch of raw data items.

        Args:
            items: List of (raw_data, metadata) tuples.

        Returns:
            List of processed events.
        """
        results = []
        for raw_data, metadata in items:
            event = self.ingest(raw_data, metadata)
            if event:
                results.append(event)
        return results

    def process(self, event):
        """Process an event through all pipeline stages.

        Args:
            event: Event object to process.

        Returns:
            The processed event.
        """
        start_time = time.perf_counter()

        # Run through stages
        for stage in self._stages:
            event = stage.process(event)

        # Set process time
        event.set("process_time", datetime.now(timezone.utc))

        # Store event
        if self.storage:
            try:
                self.storage.store_event(event)
                self._stats["events_stored"] += 1
            except Exception as exc:
                self._stats["errors"] += 1
                logger.error("Storage error: %s", exc)

        self._stats["events_processed"] += 1

        # Track processing rate
        elapsed = time.perf_counter() - start_time
        self._rate_window.append(elapsed)

        return event

    def start_async(self, num_workers=1):
        """Start asynchronous processing mode.

        Events are queued and processed by background workers.
        """
        if self._running:
            return

        self._running = True
        self._worker_thread = threading.Thread(target=self._async_loop, daemon=True)
        self._worker_thread.start()
        logger.info("Pipeline async mode started with %d workers", num_workers)

    def stop_async(self):
        """Stop asynchronous processing."""
        self._running = False
        if self._worker_thread:
            self._worker_thread.join(timeout=5.0)

    def _async_loop(self):
        """Async processing loop."""
        while self._running:
            try:
                if self._queue:
                    batch = []
                    for _ in range(min(self._batch_size, len(self._queue))):
                        if self._queue:
                            batch.append(self._queue.popleft())

                    for raw_data, metadata in batch:
                        self.ingest(raw_data, metadata)
                else:
                    time.sleep(self._flush_interval)
            except Exception as exc:
                logger.error("Async loop error: %s", exc)
                time.sleep(0.1)

    def enqueue(self, raw_data, metadata=None):
        """Enqueue data for async processing."""
        self._queue.append((raw_data, metadata or {}))
        self._stats["queue_size"] = len(self._queue)

    def get_stage_stats(self):
        """Get statistics for each pipeline stage."""
        return [stage.get_stats() for stage in self._stages]

    def get_stats(self):
        """Get pipeline statistics."""
        self._stats["queue_size"] = len(self._queue)
        # Compute processing rate
        if self._rate_window:
            avg_time = sum(self._rate_window) / len(self._rate_window)
            self._stats["processing_rate"] = 1.0 / avg_time if avg_time > 0 else 0
        return dict(self._stats)

    def reset_stats(self):
        """Reset statistics."""
        self._stats = {
            "events_ingested": 0,
            "events_processed": 0,
            "events_stored": 0,
            "events_dropped": 0,
            "errors": 0,
            "queue_size": 0,
            "processing_rate": 0.0,
        }
        for stage in self._stages:
            stage._events_processed = 0
            stage._errors = 0
            stage._total_time = 0.0

    def flush(self):
        """Process all queued events (async mode)."""
        while self._queue:
            if self._queue:
                raw_data, metadata = self._queue.popleft()
                self.ingest(raw_data, metadata)

    def set_parser(self, name, parser):
        """Set or replace a parser in the registry."""
        self.parser_registry.register(parser, priority=parser.priority)
