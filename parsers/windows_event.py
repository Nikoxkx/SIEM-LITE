"""
Windows Event Log parsers.

Supports:
- Windows Event Log XML format (Evtx exported)
- Windows Event Log JSON format
- Common Windows Security Event IDs
"""

import re
import json
import logging
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from .base import BaseParser, ParseError, ParserResult

logger = logging.getLogger(__name__)


# Windows Security Event ID mappings
WINDOWS_EVENT_MAP = {
    # Authentication events
    4624: {"event_type": "authentication", "action": "logon", "description": "Successful logon"},
    4625: {"event_type": "authentication", "action": "logon_failed", "description": "Failed logon"},
    4634: {"event_type": "authentication", "action": "logoff", "description": "Logoff"},
    4647: {"event_type": "authentication", "action": "logoff", "description": "User initiated logoff"},
    4648: {"event_type": "authentication", "action": "logon_explicit", "description": "Logon with credentials"},
    4672: {"event_type": "authentication", "action": "special_privileges", "description": "Special privileges assigned"},
    # Account management
    4720: {"event_type": "authorization", "action": "user_created", "description": "User account created"},
    4722: {"event_type": "authorization", "action": "user_enabled", "description": "User account enabled"},
    4723: {"event_type": "authorization", "action": "password_change_attempt", "description": "Password change attempt"},
    4724: {"event_type": "authorization", "action": "password_reset", "description": "Password reset"},
    4725: {"event_type": "authorization", "action": "user_disabled", "description": "User account disabled"},
    4726: {"event_type": "authorization", "action": "user_deleted", "description": "User account deleted"},
    4732: {"event_type": "authorization", "action": "member_added", "description": "Member added to group"},
    4733: {"event_type": "authorization", "action": "member_removed", "description": "Member removed from group"},
    # Process tracking
    4688: {"event_type": "process", "action": "process_created", "description": "Process created"},
    4689: {"event_type": "process", "action": "process_terminated", "description": "Process terminated"},
    # File/Registry access
    4663: {"event_type": "file", "action": "object_access", "description": "Object access attempt"},
    4656: {"event_type": "file", "action": "handle_requested", "description": "Handle requested"},
    # Policy changes
    4719: {"event_type": "audit", "action": "policy_changed", "description": "Audit policy changed"},
    1102: {"event_type": "audit", "action": "log_cleared", "description": "Security log cleared"},
    # Service / Task
    7045: {"event_type": "system", "action": "service_installed", "description": "Service installed"},
    4698: {"event_type": "system", "action": "task_created", "description": "Scheduled task created"},
    4699: {"event_type": "system", "action": "task_deleted", "description": "Scheduled task deleted"},
    # RDP
    4778: {"event_type": "authentication", "action": "rdp_reconnect", "description": "RDP session reconnected"},
    4779: {"event_type": "authentication", "action": "rdp_disconnect", "description": "RDP session disconnected"},
    # PowerShell
    4104: {"event_type": "process", "action": "powershell_script", "description": "PowerShell script block"},
    4103: {"event_type": "process", "action": "powershell_command", "description": "PowerShell module logging"},
}

# Windows logon type mapping
LOGON_TYPES = {
    2: "Interactive",
    3: "Network",
    4: "Batch",
    5: "Service",
    7: "Unlock",
    8: "NetworkCleartext",
    9: "NewCredentials",
    10: "RemoteInteractive",
    11: "CachedInteractive",
}


class WindowsEventParser(BaseParser):
    """Base Windows event log parser."""

    def __init__(self):
        super().__init__(
            name="windows_event",
            description="Windows Event Log parser",
            priority=42,
        )

    def parse(self, raw_data):
        """Auto-detect format."""
        data = self._decode(raw_data).strip()
        if data.startswith("<"):
            return WindowsXMLParser().parse(raw_data)
        elif data.startswith("{"):
            return WindowsJSONParser().parse(raw_data)
        else:
            raise ParseError("Unknown Windows event format")

    def can_parse(self, raw_data):
        data = self._decode(raw_data).strip()
        return data.startswith("<Event") or (data.startswith("{") and "EventID" in data)


class WindowsXMLParser(BaseParser):
    """Parser for Windows Event Log XML format."""

    def __init__(self):
        super().__init__(
            name="windows_xml",
            description="Windows Event XML parser",
            priority=42,
        )

    def parse(self, raw_data):
        data = self._decode(raw_data).strip()

        try:
            root = ET.fromstring(data)
        except ET.ParseError as exc:
            raise ParseError(f"Invalid XML: {exc}")

        fields = {"raw_data": data, "vendor": "Microsoft", "collection_method": "xml"}

        # Parse EventID
        event_id_elem = root.find(".//{http://schemas.microsoft.com/win/2004/08/events/event}EventID")
        if event_id_elem is None:
            event_id_elem = root.find(".//EventID")
        if event_id_elem is not None and event_id_elem.text:
            event_id = int(event_id_elem.text)
            fields["rule_id"] = str(event_id)
            fields["status_code"] = event_id

            # Look up event metadata
            event_meta = WINDOWS_EVENT_MAP.get(event_id, {})
            fields["event_type"] = event_meta.get("event_type", "system")
            fields["action"] = event_meta.get("action", f"event_{event_id}")
            fields["message"] = event_meta.get("description", f"Windows Event {event_id}")

        # Parse TimeCreated
        time_elem = root.find(".//{http://schemas.microsoft.com/win/2004/08/events/event}TimeCreated")
        if time_elem is None:
            time_elem = root.find(".//TimeCreated")
        if time_elem is not None:
            system_time = time_elem.get("SystemTime")
            if system_time:
                fields["timestamp"] = self._parse_windows_time(system_time)

        # Parse Computer
        computer_elem = root.find(".//{http://schemas.microsoft.com/win/2004/08/events/event}Computer")
        if computer_elem is None:
            computer_elem = root.find(".//Computer")
        if computer_elem is not None and computer_elem.text:
            fields["source_host"] = computer_elem.text

        # Parse Level
        level_elem = root.find(".//{http://schemas.microsoft.com/win/2004/08/events/event}Level")
        if level_elem is None:
            level_elem = root.find(".//Level")
        if level_elem is not None and level_elem.text:
            fields["severity"] = self._level_to_severity(int(level_elem.text))

        # Parse EventData
        event_data = root.find(".//{http://schemas.microsoft.com/win/2004/08/events/event}EventData")
        if event_data is None:
            event_data = root.find(".//EventData")
        if event_data is not None:
            self._parse_event_data(event_data, fields)

        # Determine result based on event ID
        event_id = fields.get("status_code")
        if event_id in (4625, 4723):
            fields["result"] = "failure"
        elif event_id == 4624:
            fields["result"] = "success"
        elif event_id in (4688,):
            fields["result"] = "success"

        fields.setdefault("severity", "info")
        fields.setdefault("event_type", "system")
        fields = self._clean_fields(fields)
        return ParserResult(fields=fields, parser_name=self.name, confidence=0.9)

    def _parse_event_data(self, event_data_elem, fields):
        """Parse EventData Name/Value pairs."""
        for data_elem in event_data_elem:
            name = data_elem.get("Name", "")
            value = data_elem.text or ""
            name_lower = name.lower().replace(" ", "_")

            # Map common Windows fields
            field_map = {
                "targetusername": "source_user", "subjectusername": "source_user",
                "accountname": "source_user", "targetuser": "source_user",
                "ipaddress": "source_ip", "workstationname": "source_host",
                "workstation": "source_host", "logontype": "logon_type",
                "processname": "process_name", "processid": "source_pid",
                "commandline": "command_line", "objectname": "file_name",
                "objecttype": "category",
            }

            canonical = field_map.get(name_lower, f"win_{name_lower}")

            if canonical == "logon_type" and value:
                try:
                    logon_num = int(value)
                    fields["logon_type"] = LOGON_TYPES.get(logon_num, str(logon_num))
                except ValueError:
                    fields["logon_type"] = value
            elif value:
                if canonical not in fields:
                    fields[canonical] = value

    def _parse_windows_time(self, time_str):
        """Parse Windows SystemTime."""
        try:
            if time_str.endswith("Z"):
                time_str = time_str[:-1] + "+00:00"
            dt = datetime.fromisoformat(time_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            return time_str

    def _level_to_severity(self, level):
        """Map Windows level to severity."""
        levels = {
            0: "info",     # Information
            1: "critical",  # Critical
            2: "error",     # Error
            3: "warning",   # Warning
            4: "info",      # Information
            5: "debug",     # Verbose
        }
        return levels.get(level, "info")

    def can_parse(self, raw_data):
        data = self._decode(raw_data).strip()
        return data.startswith("<Event")


class WindowsJSONParser(BaseParser):
    """Parser for Windows Event Log in JSON format."""

    def __init__(self):
        super().__init__(
            name="windows_json",
            description="Windows Event JSON parser",
            priority=43,
        )

    def parse(self, raw_data):
        data = self._decode(raw_data).strip()

        try:
            parsed = json.loads(data)
        except json.JSONDecodeError as exc:
            raise ParseError(f"Invalid JSON: {exc}")

        fields = {
            "raw_data": data,
            "vendor": "Microsoft",
            "collection_method": "json",
        }

        # Extract event ID
        event_id = parsed.get("EventID") or parsed.get("event_id")
        if event_id:
            event_id = int(event_id)
            fields["rule_id"] = str(event_id)
            fields["status_code"] = event_id
            event_meta = WINDOWS_EVENT_MAP.get(event_id, {})
            fields["event_type"] = event_meta.get("event_type", "system")
            fields["action"] = event_meta.get("action", f"event_{event_id}")
            fields["message"] = event_meta.get("description", f"Windows Event {event_id}")

        # Extract common fields
        field_mappings = {
            "TimeCreated": "timestamp", "SystemTime": "timestamp", "time": "timestamp",
            "Computer": "source_host", "computer": "source_host",
            "ComputerName": "source_host",
            "Level": "severity", "level": "severity", "EventType": "event_type",
            "TargetUserName": "source_user", "SubjectUserName": "source_user",
            "IpAddress": "source_ip", "ip_address": "source_ip",
            "WorkstationName": "source_host",
            "ProcessName": "process_name", "process_name": "process_name",
            "CommandLine": "command_line",
            "LogonType": "logon_type",
            "ProviderName": "product",
        }

        for win_key, canon_key in field_mappings.items():
            if win_key in parsed and parsed[win_key]:
                value = parsed[win_key]
                if canon_key == "logon_type":
                    try:
                        logon_num = int(value)
                        fields["logon_type"] = LOGON_TYPES.get(logon_num, str(logon_num))
                    except (ValueError, TypeError):
                        fields["logon_type"] = str(value)
                elif canon_key == "severity":
                    fields["severity"] = self._level_to_severity(value)
                elif canon_key == "timestamp":
                    fields["timestamp"] = self._parse_timestamp(value)
                else:
                    fields[canon_key] = str(value)

        # Handle EventData
        event_data = parsed.get("EventData") or parsed.get("event_data") or parsed.get("Properties", {})
        if isinstance(event_data, dict):
            for key, value in event_data.items():
                canon = key.lower().replace(" ", "_")
                if canon not in fields and value:
                    fields[f"win_{canon}"] = str(value)

        # Determine result
        if event_id:
            if event_id in (4625, 4723):
                fields["result"] = "failure"
            elif event_id == 4624:
                fields["result"] = "success"
            elif event_id == 4688:
                fields["result"] = "success"

        fields.setdefault("severity", "info")
        fields.setdefault("event_type", "system")
        fields.setdefault("product", "Windows")
        fields = self._clean_fields(fields)
        return ParserResult(fields=fields, parser_name=self.name, confidence=0.9)

    def _parse_timestamp(self, value):
        """Parse timestamp."""
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value, tz=timezone.utc)
        if isinstance(value, str):
            try:
                if value.endswith("Z"):
                    value = value[:-1] + "+00:00"
                dt = datetime.fromisoformat(value)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except ValueError:
                return value
        return value

    def _level_to_severity(self, level):
        """Map level to severity."""
        if isinstance(level, str):
            level_lower = level.lower()
            mapping = {"information": "info", "informational": "info",
                       "warning": "warning", "error": "error",
                       "critical": "critical", "verbose": "debug"}
            return mapping.get(level_lower, "info")
        try:
            levels = {0: "info", 1: "critical", 2: "error", 3: "warning", 4: "info", 5: "debug"}
            return levels.get(int(level), "info")
        except (ValueError, TypeError):
            return "info"

    def can_parse(self, raw_data):
        data = self._decode(raw_data).strip()
        return data.startswith("{") and "EventID" in data
