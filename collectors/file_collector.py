"""
File-based log collectors.

Supports tailing individual log files and monitoring directories for
new log files. Handles log rotation and position tracking.
"""

import os
import time
import gzip
import logging
import threading
from pathlib import Path
from datetime import datetime, timezone
from .base import BaseCollector, CollectorResult

logger = logging.getLogger(__name__)


class FileCollector(BaseCollector):
    """Collector that tails a log file.

    Tracks file position to avoid re-reading and handles log rotation
    (file truncation and inode changes).
    """

    def __init__(self, name, file_path, encoding="utf-8", from_beginning=False,
                 config=None):
        super().__init__(name=name, source=f"file://{file_path}", config=config or {})
        self.file_path = file_path
        self.encoding = encoding
        self.from_beginning = from_beginning
        self._file_handle = None
        self._position = 0
        self._inode = None
        self._line_buffer = ""

    def _on_start(self):
        """Open the file for reading."""
        self._open_file(from_beginning=self.from_beginning)

    def _open_file(self, from_beginning=False):
        """Open the file and seek to appropriate position."""
        try:
            if not os.path.exists(self.file_path):
                logger.warning("File %s does not exist yet, will wait", self.file_path)
                return

            stat = os.stat(self.file_path)

            # Check for log rotation (inode changed)
            if self._inode and self._inode != stat.st_ino:
                logger.info("Log rotation detected for %s", self.file_path)
                self._position = 0

            self._file_handle = open(self.file_path, "r", encoding=self.encoding, errors="replace")

            if from_beginning or self._position == 0:
                self._position = 0
                self._file_handle.seek(0)
            else:
                self._file_handle.seek(self._position)

            self._inode = stat.st_ino
            logger.info("File collector %s opened %s at position %d",
                       self.name, self.file_path, self._position)

        except (IOError, OSError) as exc:
            logger.error("Failed to open file %s: %s", self.file_path, exc)
            self._file_handle = None

    def _on_stop(self):
        """Close the file handle."""
        if self._file_handle:
            try:
                self._file_handle.close()
            except Exception:
                pass
            self._file_handle = None

    def collect(self):
        """Read new lines from the file."""
        if not self._file_handle:
            self._open_file()
            if not self._file_handle:
                return CollectorResult(success=False, error="File not available")

        lines_read = 0
        bytes_read = 0

        try:
            # Check for rotation
            current_stat = os.stat(self.file_path)
            if self._inode != current_stat.st_ino:
                self._close_file()
                self._open_file(from_beginning=True)
            elif current_stat.st_size < self._position:
                # File was truncated
                logger.info("File %s truncated, re-reading from start", self.file_path)
                self._position = 0
                self._file_handle.seek(0)

            # Read new lines
            for line in self._file_handle:
                line = line.rstrip("\n\r")
                if line:
                    metadata = {
                        "file_path": self.file_path,
                        "file_name": os.path.basename(self.file_path),
                        "line_number": self._stats["events_collected"] + lines_read + 1,
                    }
                    self._emit(line, metadata)
                    lines_read += 1
                    bytes_read += len(line)

            self._position = self._file_handle.tell()

        except (IOError, OSError) as exc:
            logger.error("Error reading file %s: %s", self.file_path, exc)
            self._close_file()
            return CollectorResult(success=False, error=str(exc))

        return CollectorResult(
            success=True,
            events_collected=lines_read,
            bytes_collected=bytes_read
        )

    def _close_file(self):
        """Close the current file handle."""
        if self._file_handle:
            try:
                self._file_handle.close()
            except Exception:
                pass
            self._file_handle = None

    def get_position(self):
        """Get current read position."""
        return self._position


class DirectoryCollector(BaseCollector):
    """Collector that monitors a directory for log files.

    Watches a directory for new files matching a pattern and tails them all.
    """

    def __init__(self, name, directory, pattern="*.log", recursive=False,
                 encoding="utf-8", config=None):
        super().__init__(name=name, source=f"dir://{directory}/{pattern}",
                         config=config or {})
        self.directory = directory
        self.pattern = pattern
        self.recursive = recursive
        self.encoding = encoding
        self._file_collectors = {}  # path -> FileCollector
        self._poll_interval = config.get("poll_interval", 5.0)

    def _on_start(self):
        """Initialize directory monitoring."""
        if not os.path.isdir(self.directory):
            logger.warning("Directory %s does not exist", self.directory)
            os.makedirs(self.directory, exist_ok=True)
        logger.info("Directory collector %s monitoring %s for %s",
                    self.name, self.directory, self.pattern)

    def _on_stop(self):
        """Stop all file collectors."""
        for fc in self._file_collectors.values():
            fc._on_stop()
        self._file_collectors.clear()

    def collect(self):
        """Scan directory and collect from all matching files."""
        import fnmatch

        total_events = 0
        total_bytes = 0
        errors = 0

        # Find matching files
        matching_files = set()
        try:
            if self.recursive:
                for root, dirs, files in os.walk(self.directory):
                    for filename in files:
                        if fnmatch.fnmatch(filename, self.pattern):
                            matching_files.add(os.path.join(root, filename))
            else:
                for filename in os.listdir(self.directory):
                    full_path = os.path.join(self.directory, filename)
                    if os.path.isfile(full_path) and fnmatch.fnmatch(filename, self.pattern):
                        matching_files.add(full_path)
        except OSError as exc:
            logger.error("Error scanning directory %s: %s", self.directory, exc)
            return CollectorResult(success=False, error=str(exc))

        # Remove collectors for deleted files
        for path in list(self._file_collectors.keys()):
            if path not in matching_files:
                logger.debug("Removing collector for deleted file: %s", path)
                self._file_collectors[path]._on_stop()
                del self._file_collectors[path]

        # Collect from existing files
        for file_path in matching_files:
            if file_path not in self._file_collectors:
                # Create new file collector
                fc = FileCollector(
                    name=f"{self.name}_{os.path.basename(file_path)}",
                    file_path=file_path,
                    encoding=self.encoding,
                )
                fc.set_event_handler(self._file_event_handler)
                fc._on_start()
                self._file_collectors[file_path] = fc
                logger.debug("Started tracking new file: %s", file_path)

            fc = self._file_collectors[file_path]
            result = fc.collect()
            if result.success:
                total_events += result.events_collected
                total_bytes += result.bytes_collected
            elif result.error:
                errors += 1

        self._stats["events_collected"] += total_events
        self._stats["bytes_collected"] += total_bytes
        self._stats["errors"] += errors
        self._stats["last_collection"] = datetime.now(timezone.utc).isoformat()

        return CollectorResult(
            success=True,
            events_collected=total_events,
            bytes_collected=total_bytes,
            metadata={"files_monitored": len(matching_files)}
        )

    def _file_event_handler(self, raw_data, metadata):
        """Handle events from child file collectors."""
        metadata.setdefault("directory", self.directory)
        self._emit(raw_data, metadata)

    def get_monitored_files(self):
        """Get list of monitored files."""
        return list(self._file_collectors.keys())


class GzipFileCollector(FileCollector):
    """Collector for gzip-compressed log files."""

    def _open_file(self, from_beginning=False):
        """Open gzip file."""
        try:
            if not os.path.exists(self.file_path):
                return
            self._file_handle = gzip.open(self.file_path, "rt", encoding=self.encoding,
                                          errors="replace")
            self._position = 0
            logger.info("Gzip file collector %s opened %s", self.name, self.file_path)
        except (IOError, OSError) as exc:
            logger.error("Failed to open gzip file %s: %s", self.file_path, exc)
            self._file_handle = None
