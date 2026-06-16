"""
Windows Event Log collectors.

Supports collecting Windows Security, System, Application, and other
event logs. Uses pywin32/winevt if available, or processes exported
files.
"""

import os
import time
import logging
import subprocess
from datetime import datetime, timezone
from .base import BaseCollector, CollectorResult

logger = logging.getLogger(__name__)

# Windows event log channels
WINDOWS_CHANNELS = [
    "Security",
    "System",
    "Application",
    "Setup",
    "ForwardedEvents",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-Sysmon/Operational",
    "Microsoft-Windows-Windows Defender/Operational",
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "Microsoft-Windows-TaskScheduler/Operational",
]


class WindowsEventCollector(BaseCollector):
    """Collector for Windows Event Logs.

    Uses winevt (Windows Event Command Line) to query event logs.
    Falls back to pywin32 if available.
    """

    def __init__(self, name="windows_events", channels=None, max_events=100,
                 config=None):
        super().__init__(name=name, source="winevt://localhost", config=config or {})
        self.channels = channels or ["Security", "System", "Application"]
        self.max_events = max_events
        self._last_event_time = None
        self._bookmark = {}  # channel -> last event record ID

    def _on_start(self):
        """Initialize Windows event collection."""
        self._check_wevtutil()
        logger.info("Windows event collector %s monitoring channels: %s",
                    self.name, ", ".join(self.channels))

    def _check_wevtutil(self):
        """Check if wevtutil is available."""
        try:
            result = subprocess.run(["wevtutil", "ep"], capture_output=True, timeout=5)
            if result.returncode != 0:
                logger.warning("wevtutil not available; Windows event collection may fail")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            logger.warning("wevtutil not found; running on non-Windows system?")
        except Exception as exc:
            logger.warning("Error checking wevtutil: %s", exc)

    def collect(self):
        """Collect events from Windows event logs."""
        total_events = 0
        total_bytes = 0
        errors = 0

        for channel in self.channels:
            try:
                events, event_bytes = self._query_channel(channel)
                total_events += events
                total_bytes += event_bytes
            except Exception as exc:
                logger.error("Error collecting from channel %s: %s", channel, exc)
                errors += 1

        self._stats["events_collected"] += total_events
        self._stats["bytes_collected"] += total_bytes
        self._stats["errors"] += errors
        self._stats["last_collection"] = datetime.now(timezone.utc).isoformat()

        return CollectorResult(
            success=errors < len(self.channels),
            events_collected=total_events,
            bytes_collected=total_bytes,
            metadata={"channels": self.channels, "errors": errors}
        )

    def _query_channel(self, channel):
        """Query a single Windows event channel using wevtutil."""
        events = 0
        bytes_collected = 0

        # Build query with time filter
        query_args = ["wevtutil", "qe", channel, "/c:%d" % self.max_events,
                       "/f:xml", "/rd:true"]  # reverse direction (newest first)

        last_record = self._bookmark.get(channel)
        if last_record:
            query_args.append(f"/q:*[System/EventRecordID>{last_record}]")

        try:
            result = subprocess.run(query_args, capture_output=True, timeout=30,
                                    text=True, errors="replace")
            if result.returncode != 0:
                logger.warning("wevtutil query failed for %s: %s", channel,
                               result.stderr[:200])
                return 0, 0

            output = result.stdout.strip()
            if not output:
                return 0, 0

            # Split XML events
            xml_events = output.split("\n")
            max_record_id = 0

            for xml_event in xml_events:
                xml_event = xml_event.strip()
                if not xml_event or not xml_event.startswith("<"):
                    continue

                metadata = {
                    "channel": channel,
                    "collection_method": "winevt",
                    "source_host": "localhost",
                }

                self._emit(xml_event, metadata)
                events += 1
                bytes_collected += len(xml_event)

                # Extract record ID for bookmarking
                try:
                    import re
                    rid_match = re.search(r'<EventRecordID>(\d+)</EventRecordID>', xml_event)
                    if rid_match:
                        rid = int(rid_match.group(1))
                        max_record_id = max(max_record_id, rid)
                except (ValueError, AttributeError):
                    pass

            if max_record_id > 0:
                self._bookmark[channel] = max_record_id

        except subprocess.TimeoutExpired:
            logger.warning("wevtutil query timed out for channel %s", channel)
        except FileNotFoundError:
            logger.debug("wevtutil not available")
        except Exception as exc:
            logger.error("Error querying channel %s: %s", channel, exc)

        return events, bytes_collected


class WinevtCollector(WindowsEventCollector):
    """Alias for WindowsEventCollector using winevt Python bindings.

    If pywin32 is available, uses the native winevt API instead of
    shelling out to wevtutil.
    """

    def __init__(self, name="winevt", channels=None, max_events=100, config=None):
        super().__init__(name=name, channels=channels, max_events=max_events, config=config)
        self._use_native = False
        try:
            import win32evtlog  # noqa: F401
            self._use_native = True
            logger.info("Using native pywin32 for Windows event collection")
        except ImportError:
            logger.info("pywin32 not available; falling back to wevtutil")

    def _query_channel(self, channel):
        """Query channel using native API if available."""
        if self._use_native:
            return self._query_native(channel)
        return super()._query_channel(channel)

    def _query_native(self, channel):
        """Query using pywin32 winevt API."""
        try:
            import win32evtlog
            import win32con
            import xml.etree.ElementTree as ET

            events = 0
            bytes_collected = 0

            server = "localhost"
            hand = win32evtlog.OpenEventLog(server, channel)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

            try:
                while events < self.max_events:
                    objects = win32evtlog.ReadEventLog(hand, flags, 0)
                    if not objects:
                        break

                    for obj in objects:
                        # Convert event to XML
                        event_xml = self._event_to_xml(obj, channel)
                        if event_xml:
                            metadata = {
                                "channel": channel,
                                "collection_method": "winevt",
                                "source_host": server,
                            }
                            self._emit(event_xml, metadata)
                            events += 1
                            bytes_collected += len(event_xml)
            finally:
                win32evtlog.CloseEventLog(hand)

            return events, bytes_collected

        except Exception as exc:
            logger.error("Native winevt query failed: %s", exc)
            return 0, 0

    def _event_to_xml(self, event, channel):
        """Convert a pywin32 event object to XML string."""
        try:
            xml_str = f"""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="{event.SourceName}"/>
    <EventID>{event.EventID}</EventID>
    <Channel>{channel}</Channel>
    <Computer>{event.ComputerName}</Computer>
    <TimeCreated SystemTime="{event.TimeGenerated.isoformat()}"/>
  </System>
  <EventData>"""
            if hasattr(event, "InsertionStrings") and event.InsertionStrings:
                for s in event.InsertionStrings:
                    xml_str += f"\n    <Data>{s}</Data>"
            xml_str += "\n  </EventData>\n</Event>"
            return xml_str
        except Exception as exc:
            logger.debug("Failed to convert event to XML: %s", exc)
            return None
