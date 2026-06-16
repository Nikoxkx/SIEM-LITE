"""
LEEF (Log Event Extended Format) parser.

LEEF Format: LEEF:Version|Vendor|Product|Version|EventID|key=value\tkey=value...

IBM QRadar's log format. Fields are tab-separated in the header and
key=value pairs are tab-separated in the body.

Example:
    LEEF:1.0|IBM|Probemssg|6.1.0.2|1108|src=10.0.0.1\tdst=192.168.1.1\tsev=5
"""

import re
import logging
from .base import BaseParser, ParseError, ParserResult

logger = logging.getLogger(__name__)


class LEEFParser(BaseParser):
    """Parser for Log Event Extended Format (LEEF)."""

    # LEEF header can use | or ^ as delimiter
    HEADER_PATTERN = re.compile(
        r'^LEEF:(?P<version>[\d\.]+)'
        r'(?P<delim>\||\^)'
        r'(?P<vendor>[^|^\r\n]*)'
        r'(?P=delim)'
        r'(?P<product>[^|^\r\n]*)'
        r'(?P=delim)'
        r'(?P<dev_version>[^|^\r\n]*)'
        r'(?P=delim)'
        r'(?P<event_id>[^|^\r\n]*)'
        r'(?P=delim)?'
        r'(?P<extension>.*)$',
        re.DOTALL
    )

    # LEEF extension field mappings
    FIELD_MAP = {
        "src": "source_ip", "sourceAddress": "source_ip", "srcip": "source_ip",
        "dst": "dest_ip", "destinationAddress": "dest_ip", "dstip": "dest_ip",
        "sport": "source_port", "srcport": "source_port", "sourcePort": "source_port",
        "dport": "dest_port", "dstport": "dest_port", "destinationPort": "dest_port",
        "proto": "protocol", "protocol": "protocol",
        "action": "action", "act": "action",
        "sev": "severity", "severity": "severity",
        "user": "source_user", "usr": "source_user", "username": "source_user",
        "msg": "message", "message": "message",
        "reason": "reason",
        "result": "result",
        "bytes": "bytes_sent",
        "duration": "duration",
        "mac": "source_mac", "srcmac": "source_mac",
        "dstmac": "dest_mac",
        "type": "event_type",
        "group": "category",
    }

    def __init__(self):
        super().__init__(
            name="leef",
            description="Log Event Extended Format (LEEF) parser",
            priority=65,
        )

    def parse(self, raw_data):
        data = self._decode(raw_data).strip()
        if not data.startswith("LEEF:"):
            raise ParseError("Not a LEEF message: missing LEEF: prefix")

        # Detect header delimiter (default tab, but can be specified)
        # LEEF:2.0 allows custom header delimiter: LEEF:2.0^...
        match = self.HEADER_PATTERN.match(data)
        if not match:
            raise ParseError("Failed to parse LEEF header")

        version = match.group("version")
        delim = match.group("delim")
        vendor = match.group("vendor").strip()
        product = match.group("product").strip()
        dev_version = match.group("dev_version").strip()
        event_id = match.group("event_id").strip()
        extension = match.group("extension") or ""

        # Parse version
        try:
            major_version = int(version.split(".")[0])
        except (ValueError, IndexError):
            major_version = 1

        fields = {
            "leef_version": version,
            "vendor": vendor or "Unknown",
            "product": product or "Unknown",
            "device_version": dev_version,
            "rule_id": event_id,
            "raw_data": data,
            "collection_method": "leef",
            "event_type": self._classify_event(vendor, product, event_id),
        }

        # Parse extension fields (tab-separated key=value)
        ext_fields = self._parse_extension(extension, major_version)
        fields.update(ext_fields)

        # Set default message if not provided
        if "message" not in fields:
            fields["message"] = f"{vendor} {product}: Event {event_id}"

        # Map severity
        if "severity" in fields:
            fields["severity"] = self._normalize_severity(fields["severity"])

        fields = self._clean_fields(fields)
        return ParserResult(fields=fields, parser_name=self.name, confidence=0.95)

    def _parse_extension(self, extension, version):
        """Parse LEEF extension fields.

        LEEF 1.0: tab-separated key=value pairs
        LEEF 2.0: tab-separated key=value pairs (possibly with different escaping)
        """
        if not extension:
            return {}

        fields = {}

        # In LEEF 2.0, the extension can start with a custom delimiter
        if version >= 2:
            # First char might be the delimiter
            if extension and extension[0] == "\t":
                extension = extension[1:]

        # Split by tab (and sometimes by \x09)
        parts = re.split(r'\t|\\t', extension)

        for part in parts:
            part = part.strip()
            if "=" not in part:
                # Could be a standalone value
                if part and "message" not in fields:
                    fields["message"] = part
                continue

            # Split on first =
            eq_pos = part.index("=")
            key = part[:eq_pos].strip()
            value = part[eq_pos + 1:].strip()

            # Unescape
            value = self._unescape(value)

            if key and value:
                mapped = self.FIELD_MAP.get(key.lower(), key.lower())
                if mapped not in fields:
                    fields[mapped] = value
                else:
                    if isinstance(fields[mapped], list):
                        fields[mapped].append(value)
                    else:
                        fields[mapped] = [fields[mapped], value]

        return fields

    def _unescape(self, value):
        """Unescape LEEF special characters."""
        if not value:
            return value
        value = value.replace("\\|", "|")
        value = value.replace("\\=", "=")
        value = value.replace("\\n", "\n")
        value = value.replace("\\t", "\t")
        value = value.replace("\\\\", "\\")
        value = value.replace("\\r", "\r")
        return value

    def _normalize_severity(self, severity):
        """Normalize LEEF severity to canonical values."""
        try:
            sev_num = int(severity)
            if sev_num <= 0:
                return "info"
            elif sev_num <= 2:
                return "low"
            elif sev_num <= 5:
                return "medium"
            elif sev_num <= 8:
                return "high"
            else:
                return "critical"
        except ValueError:
            sev_lower = str(severity).lower()
            mapping = {
                "info": "info", "debug": "info", "informational": "info",
                "low": "low", "minor": "low",
                "medium": "medium", "moderate": "medium", "warning": "medium",
                "high": "high", "major": "high", "error": "high",
                "critical": "critical", "severe": "critical", "emergency": "critical",
            }
            return mapping.get(sev_lower, "medium")

    def _classify_event(self, vendor, product, event_id):
        """Classify event type from vendor/product."""
        combined = f"{vendor} {product} {event_id}".lower()

        type_keywords = {
            "authentication": ["auth", "login", "logon", "credential"],
            "network": ["connection", "socket", "packet"],
            "firewall": ["firewall", "deny", "permit"],
            "dns": ["dns", "domain", "resolve"],
            "av_malware": ["malware", "virus", "antivirus"],
            "ids_ips": ["intrusion", "ids", "ips"],
            "vpn": ["vpn", "tunnel"],
            "file": ["file", "integrity"],
            "process": ["process", "exec"],
        }

        for event_type, keywords in type_keywords.items():
            if any(kw in combined for kw in keywords):
                return event_type

        return "system"

    def can_parse(self, raw_data):
        data = self._decode(raw_data).strip()
        return data.startswith("LEEF:")
