"""
JSON and key-value parsers.

Handles logs in JSON format (single object, arrays, and JSONL/NDJSON),
as well as space-separated key=value format.
"""

import json
import logging
from .base import BaseParser, ParseError, ParserResult

logger = logging.getLogger(__name__)


class JSONParser(BaseParser):
    """Parser for JSON-formatted log entries.

    Handles:
    - Single JSON objects
    - JSON arrays (returns first element or merged)
    - JSONL/NDJSON (one JSON object per line)
    - Nested JSON (flattened)
    """

    def __init__(self):
        super().__init__(
            name="json",
            description="JSON log format parser",
            priority=60,
        )
        # Common field name mappings from various JSON log formats
        self.field_map = {
            "timestamp": "timestamp", "time": "timestamp", "@timestamp": "timestamp",
            "ts": "timestamp", "datetime": "timestamp", "date": "timestamp",
            "event_time": "timestamp", "created": "timestamp",
            "src_ip": "source_ip", "source_ip": "source_ip", "srcip": "source_ip",
            "source": "source_ip", "client_ip": "source_ip", "remote_addr": "source_ip",
            "dst_ip": "dest_ip", "dest_ip": "dest_ip", "dstip": "dest_ip",
            "destination": "dest_ip", "target": "dest_ip",
            "src_port": "source_port", "sport": "source_port", "source_port": "source_port",
            "dst_port": "dest_port", "dport": "dest_port", "dest_port": "dest_port",
            "src_host": "source_host", "source_host": "source_host", "hostname": "source_host",
            "user": "source_user", "username": "source_user", "src_user": "source_user",
            "event_type": "event_type", "type": "event_type", "category": "category",
            "severity": "severity", "level": "severity", "priority": "severity",
            "action": "action", "result": "result", "outcome": "result",
            "protocol": "protocol", "proto": "protocol",
            "process": "process_name", "process_name": "process_name",
            "command": "command_line", "cmd": "command_line", "command_line": "command_line",
            "file": "file_name", "filename": "file_name", "file_name": "file_name",
            "filepath": "file_path", "file_path": "file_path", "path": "file_path",
            "hash": "file_hash", "file_hash": "file_hash", "md5": "file_hash",
            "url": "url", "uri": "uri_path", "request": "uri_path",
            "method": "http_method", "http_method": "http_method",
            "status": "status_code", "status_code": "status_code", "http_status": "status_code",
            "user_agent": "user_agent", "ua": "user_agent",
            "message": "message", "msg": "message", "detail": "message",
            "description": "message", "reason": "reason",
        }

    def parse(self, raw_data):
        data = self._decode(raw_data).strip()
        if not data:
            raise ParseError("Empty JSON data")

        try:
            parsed = json.loads(data)
        except json.JSONDecodeError as exc:
            raise ParseError(f"Invalid JSON: {exc}")

        # Handle JSON array
        if isinstance(parsed, list):
            if not parsed:
                raise ParseError("Empty JSON array")
            # Parse first element primarily
            parsed = parsed[0]

        if not isinstance(parsed, dict):
            raise ParseError(f"JSON is not an object: {type(parsed)}")

        # Flatten nested structure
        flat = self._flatten_json(parsed)

        # Map fields
        fields = {}
        for key, value in flat.items():
            mapped_key = self._map_key(key)
            if mapped_key in fields:
                if isinstance(fields[mapped_key], list):
                    fields[mapped_key].append(value)
                else:
                    fields[mapped_key] = [fields[mapped_key], value]
            else:
                fields[mapped_key] = value

        # Ensure required fields
        fields.setdefault("raw_data", data)
        fields.setdefault("event_type", self._infer_event_type(fields))
        fields.setdefault("vendor", "json")
        fields.setdefault("collection_method", "json")
        fields.setdefault("timestamp", fields.get("timestamp"))

        fields = self._clean_fields(fields)
        return ParserResult(fields=fields, parser_name=self.name, confidence=0.95)

    def _flatten_json(self, data, prefix="", max_depth=10):
        """Flatten nested JSON objects."""
        if max_depth <= 0:
            return {prefix: data} if prefix else data

        result = {}
        for key, value in data.items():
            new_key = f"{prefix}.{key}" if prefix else key
            if isinstance(value, dict) and len(value) <= 20:
                result.update(self._flatten_json(value, new_key, max_depth - 1))
            elif isinstance(value, list):
                # Keep list as-is or join
                if value and isinstance(value[0], str):
                    result[new_key] = ",".join(str(v) for v in value)
                else:
                    result[new_key] = value
            else:
                result[new_key] = value
        return result

    def _map_key(self, key):
        """Map a JSON key to canonical field name."""
        key_lower = key.lower().replace("-", "_").replace(" ", "_")
        return self.field_map.get(key_lower, key_lower)

    def _infer_event_type(self, fields):
        """Infer event type from field values."""
        action = str(fields.get("action", "")).lower()
        category = str(fields.get("category", "")).lower()
        event_type = str(fields.get("event_type", "")).lower()

        if event_type and event_type != "none":
            return event_type

        type_mappings = {
            "login": "authentication", "logout": "authentication",
            "auth": "authentication", "logon": "authentication",
            "connection": "network", "connect": "network",
            "firewall": "firewall", "deny": "firewall",
            "dns": "dns", "query": "dns",
            "process": "process", "exec": "process",
            "file": "file", "create_file": "file",
            "alert": "ids_ips", "intrusion": "ids_ips",
            "malware": "av_malware", "virus": "av_malware",
            "vpn": "vpn",
        }

        for keyword, event_type in type_mappings.items():
            if keyword in action or keyword in category:
                return event_type

        return "system"

    def can_parse(self, raw_data):
        data = self._decode(raw_data).strip()
        return data.startswith("{")


class KeyValueParser(BaseParser):
    """Parser for space-separated key=value format.

    Example: date=2024-01-15 time=10:30:00 src=192.168.1.1 dst=10.0.0.1 action=allow
    """

    PATTERN_KV = r'(\w[\w\-\.]*)=(?:"([^"]*)"|\'([^\']*)\'|(\S+))'

    def __init__(self):
        super().__init__(
            name="keyvalue",
            description="Key=value pair parser",
            priority=30,
        )
        self.field_map = {
            "src": "source_ip", "source": "source_ip", "srcip": "source_ip",
            "src_ip": "source_ip", "clientip": "source_ip",
            "dst": "dest_ip", "dest": "dest_ip", "dstip": "dest_ip",
            "dst_ip": "dest_ip", "target": "dest_ip",
            "spt": "source_port", "srcport": "source_port", "src_port": "source_port",
            "dpt": "dest_port", "dstport": "dest_port", "dst_port": "dest_port",
            "proto": "protocol", "protocol": "protocol",
            "action": "action", "act": "action",
            "user": "source_user", "srcuser": "source_user",
            "status": "result", "result": "result",
            "msg": "message", "message": "message",
            "severity": "severity", "level": "severity",
            "reason": "reason",
            "bytes": "bytes_sent",
            "duration": "duration",
            "iface": "interface",
            "mac": "source_mac", "srcmac": "source_mac",
            "dstmac": "dest_mac",
            "type": "event_type",
            "category": "category",
            "fac": "facility", "facility": "facility",
            "pri": "priority",
        }

    def parse(self, raw_data):
        data = self._decode(raw_data).strip()
        if "=" not in data:
            raise ParseError("No key=value pairs found")

        import re
        fields = {"raw_data": data}

        # Find all key=value pairs
        for match in re.finditer(self.PATTERN_KV, data):
            key = match.group(1).lower()
            value = match.group(2) or match.group(3) or match.group(4)
            value = self._clean_value(value)
            if value is not None:
                mapped = self.field_map.get(key, key)
                if mapped not in fields:
                    fields[mapped] = value
                else:
                    # Multiple values -> list
                    if isinstance(fields[mapped], list):
                        fields[mapped].append(value)
                    else:
                        fields[mapped] = [fields[mapped], value]

        # Try to extract timestamp from date + time fields
        if "date" in fields and "time" in fields:
            ts_str = f"{fields['date']} {fields['time']}"
            fields["timestamp"] = ts_str
        elif "date" in fields:
            fields["timestamp"] = fields["date"]

        # Try to extract a leading timestamp/message before the key=value pairs
        first_kv = data.find("=")
        if first_kv > 0:
            prefix = data[:first_kv].rsplit(" ", 1)[0].strip()
            if prefix and not fields.get("message"):
                # Try to parse as timestamp
                from ..utils.time_utils import parse_timestamp
                ts = parse_timestamp(prefix)
                if ts:
                    fields["timestamp"] = ts

        fields.setdefault("event_type", "system")
        fields.setdefault("vendor", "keyvalue")
        fields.setdefault("collection_method", "keyvalue")

        if len(fields) < 3:  # Need at least raw_data + some fields
            raise ParseError("Insufficient key=value pairs parsed")

        fields = self._clean_fields(fields)
        return ParserResult(fields=fields, parser_name=self.name, confidence=0.75)

    def can_parse(self, raw_data):
        data = self._decode(raw_data)
        import re
        pairs = re.findall(self.PATTERN_KV, data)
        return len(pairs) >= 2


class CEFJSONParser(BaseParser):
    """Parser for CEF-formatted data embedded in JSON.

    Example: {"cef": "CEF:0|Vendor|Product|1.0|100|Event|5|src=1.2.3.4 ..."}
    """

    def __init__(self):
        super().__init__(
            name="cef_json",
            description="CEF data within JSON wrapper",
            priority=55,
        )

    def parse(self, raw_data):
        data = self._decode(raw_data).strip()
        try:
            parsed = json.loads(data)
        except json.JSONDecodeError:
            raise ParseError("Invalid JSON")

        if not isinstance(parsed, dict):
            raise ParseError("Expected JSON object")

        # Find CEF string
        cef_str = None
        for key in ("cef", "message", "raw", "event"):
            if key in parsed and isinstance(parsed[key], str) and parsed[key].startswith("CEF:"):
                cef_str = parsed[key]
                break

        if not cef_str:
            raise ParseError("No CEF data found in JSON")

        # Parse CEF
        from .cef_parser import CEFParser
        cef_parser = CEFParser()
        cef_result = cef_parser.parse(cef_str)

        fields = cef_result.fields
        # Add JSON metadata
        for key, value in parsed.items():
            if key not in ("cef", "message", "raw", "event"):
                fields[f"_json_{key}"] = value

        fields["raw_data"] = data
        return ParserResult(fields=fields, parser_name=self.name, confidence=0.9)
