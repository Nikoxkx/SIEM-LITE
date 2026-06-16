"""
Syslog parsers for RFC 3164 and RFC 5424 formats.

RFC 3164 (BSD syslog): <PRI>TIMESTAMP HOSTNAME TAG: MESSAGE
RFC 5424 (syslog protocol): <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
"""

import re
import logging
from datetime import datetime, timezone, timedelta
from .base import BaseParser, ParseError, ParserResult

logger = logging.getLogger(__name__)

# Syslog month abbreviation map
MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

# Severity names (RFC 5424)
SEVERITY_NAMES = [
    "emergency", "alert", "critical", "error",
    "warning", "notice", "info", "debug",
]

# Facility names
FACILITY_NAMES = [
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
    "uucp", "cron", "authpriv", "ftp", "ntp", "audit", "alert", "clock",
    "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
]


class SyslogParser(BaseParser):
    """Base syslog parser with auto-detection between RFC 3164 and 5424."""

    def __init__(self):
        super().__init__(
            name="syslog",
            description="Auto-detecting syslog parser (RFC 3164/5424)",
            priority=50,
        )
        self._rfc3164 = RFC3164Parser()
        self._rfc5424 = RFC5424Parser()

    def parse(self, raw_data):
        """Parse syslog message, auto-detecting format."""
        data = self._decode(raw_data).strip()
        if not data:
            raise ParseError("Empty syslog message")

        # Check for version number (RFC 5424)
        match = re.match(r'^<(\d+)>(\d+)\s', data)
        if match:
            return self._rfc5424.parse(raw_data)
        elif data.startswith("<"):
            return self._rfc3164.parse(raw_data)
        else:
            raise ParseError("Not a valid syslog message")

    def can_parse(self, raw_data):
        data = self._decode(raw_data).strip()
        return data.startswith("<")


class RFC3164Parser(BaseParser):
    """Parser for RFC 3164 (BSD) syslog format.

    Format: <PRI>TIMESTAMP HOSTNAME TAG: MESSAGE
    Example: <34>Oct 11 22:14:15 mymachine su: 'su root' failed
    """

    PATTERN = re.compile(
        r'^<(?P<priority>\d{1,3})>'
        r'(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<hostname>\S+)\s+'
        r'(?P<rest>.*)$',
        re.DOTALL
    )

    # Extended pattern with optional TAG
    PATTERN_EXTENDED = re.compile(
        r'^<(?P<priority>\d{1,3})>'
        r'(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'
        r'(?:\s+(?P<hostname>\S+))?'
        r'(?:\s+(?P<rest>.*))?$',
        re.DOTALL
    )

    def __init__(self):
        super().__init__(
            name="rfc3164",
            description="RFC 3164 (BSD) syslog parser",
            priority=45,
        )

    def parse(self, raw_data):
        data = self._decode(raw_data).strip()
        if not data.startswith("<"):
            raise ParseError("Not an RFC 3164 message: missing priority")

        match = self.PATTERN_EXTENDED.match(data)
        if not match:
            raise ParseError(f"Failed to parse RFC 3164 message")

        priority = int(match.group("priority"))
        facility = priority // 8
        severity_num = priority % 8

        fields = {
            "priority": priority,
            "facility": FACILITY_NAMES[facility] if facility < len(FACILITY_NAMES) else f"local{facility}",
            "facility_num": facility,
            "severity": SEVERITY_NAMES[severity_num] if severity_num < 8 else "debug",
            "severity_num": severity_num,
            "timestamp": self._parse_timestamp(match.group("timestamp")),
            "source_host": match.group("hostname"),
            "raw_data": data,
        }

        rest = match.group("rest") or ""

        # Try to extract TAG and message
        tag_match = re.match(r'^(?P<tag>[a-zA-Z0-9_\-\.\/]+)(\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$',
                             rest, re.DOTALL)
        if tag_match:
            fields["product"] = tag_match.group("tag")
            fields["source_process"] = tag_match.group("tag")
            if tag_match.group("pid"):
                fields["source_pid"] = int(tag_match.group("pid"))
            fields["message"] = tag_match.group("message").strip()
        else:
            fields["message"] = rest.strip()

        # Try to extract key=value pairs from message
        kv_pairs = self._extract_key_values(fields.get("message", ""))
        fields.update(kv_pairs)

        # Classify event type from content
        fields["event_type"] = self._classify_event(fields)
        fields["vendor"] = "syslog"
        fields["collection_method"] = "syslog"

        fields = self._clean_fields(fields)
        return ParserResult(fields=fields, parser_name=self.name, confidence=0.9)

    def _parse_timestamp(self, ts_str):
        """Parse RFC 3164 timestamp (no year)."""
        if not ts_str:
            return None
        try:
            parts = ts_str.split()
            if len(parts) >= 3:
                month = MONTH_MAP.get(parts[0])
                day = int(parts[1])
                time_parts = parts[2].split(":")
                hour = int(time_parts[0])
                minute = int(time_parts[1])
                second = int(time_parts[2]) if len(time_parts) > 2 else 0

                # Infer year (assume current year, adjust if future date)
                now = datetime.now(timezone.utc)
                year = now.year
                dt = datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
                # If the date is more than 1 day in the future, assume previous year
                if dt - now > timedelta(days=1):
                    dt = dt.replace(year=year - 1)
                return dt
        except (ValueError, IndexError) as exc:
            logger.debug("Failed to parse RFC 3164 timestamp '%s': %s", ts_str, exc)
        return ts_str

    def _extract_key_values(self, message):
        """Extract key=value pairs from message."""
        pairs = {}
        # Match key=value or key="value"
        pattern = re.compile(r'(\w+)=((?:"[^"]*")|(?:\S+))')
        for match in pattern.finditer(message):
            key = match.group(1)
            value = match.group(2)
            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1]
            # Map known keys
            key_lower = key.lower()
            field_map = {
                "src": "source_ip", "dst": "dest_ip", "spt": "source_port",
                "dpt": "dest_port", "proto": "protocol", "user": "source_user",
                "action": "action", "status": "result", "reason": "reason",
            }
            canonical = field_map.get(key_lower, key_lower)
            if canonical not in pairs:
                pairs[canonical] = value
        return pairs

    def _classify_event(self, fields):
        """Classify event type from content."""
        message = (fields.get("message") or "").lower()
        product = (fields.get("product") or "").lower()

        if any(w in message for w in ["login", "logon", "authentication", "auth"]):
            return "authentication"
        if any(w in message for w in ["firewall", "blocked", "permitted", "deny"]):
            return "firewall"
        if any(w in message for w in ["connection", "tcp", "udp", "port"]):
            return "network"
        if any(w in message for w in ["ssh", "sshd"]):
            return "authentication"
        if any(w in message for w in ["sudo", "su ", "root"]):
            return "authorization"
        if "cron" in product:
            return "system"
        return "system"


class RFC5424Parser(BaseParser):
    """Parser for RFC 5424 syslog format.

    Format: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG
    Example: <34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 [exampleSDID@32473 ...] 'su root' failed
    """

    PATTERN = re.compile(
        r'^<(?P<priority>\d{1,3})>'
        r'(?P<version>\d+)\s+'
        r'(?P<timestamp>\S+)\s+'
        r'(?P<hostname>\S+)\s+'
        r'(?P<app_name>\S+)\s+'
        r'(?P<proc_id>\S+)\s+'
        r'(?P<msg_id>\S+)'
        r'(?:\s+(?P<structured_data>(?:-)|(?:\[[^\]]*\])+))?'
        r'(?:\s+(?P<message>.*))?$',
        re.DOTALL
    )

    def __init__(self):
        super().__init__(
            name="rfc5424",
            description="RFC 5424 syslog protocol parser",
            priority=48,
        )

    def parse(self, raw_data):
        data = self._decode(raw_data).strip()

        match = self.PATTERN.match(data)
        if not match:
            raise ParseError("Failed to parse RFC 5424 message")

        priority = int(match.group("priority"))
        facility = priority // 8
        severity_num = priority % 8

        fields = {
            "priority": priority,
            "facility": FACILITY_NAMES[facility] if facility < len(FACILITY_NAMES) else f"local{facility}",
            "facility_num": facility,
            "severity": SEVERITY_NAMES[severity_num] if severity_num < 8 else "debug",
            "severity_num": severity_num,
            "version": int(match.group("version")),
            "timestamp": self._parse_timestamp(match.group("timestamp")),
            "source_host": self._clean_value(match.group("hostname")),
            "product": self._clean_value(match.group("app_name")),
            "msg_id": self._clean_value(match.group("msg_id")),
            "raw_data": data,
            "vendor": "syslog",
            "collection_method": "syslog",
        }

        proc_id = match.group("proc_id")
        if proc_id and proc_id != "-":
            fields["source_pid"] = self._clean_value(proc_id)

        # Parse structured data
        sd = match.group("structured_data")
        if sd and sd != "-":
            sd_fields = self._parse_structured_data(sd)
            fields.update(sd_fields)
            fields["structured_data"] = sd

        # Parse message
        message = match.group("message")
        if message:
            # Handle BOM (Byte Order Mark) for UTF-8
            if message.startswith("\ufeff"):
                message = message[1:]
            fields["message"] = message.strip()

        fields["event_type"] = self._classify_event(fields)
        fields = self._clean_fields(fields)
        return ParserResult(fields=fields, parser_name=self.name, confidence=0.95)

    def _parse_timestamp(self, ts_str):
        """Parse RFC 5424 timestamp (ISO 8601)."""
        if not ts_str or ts_str == "-":
            return None
        try:
            # Handle Z timezone
            if ts_str.endswith("Z"):
                ts_str = ts_str[:-1] + "+00:00"
            dt = datetime.fromisoformat(ts_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            return ts_str

    def _parse_structured_data(self, sd_str):
        """Parse RFC 5424 structured data.

        Format: [SD-ID PARAM1="val1" PARAM2="val2"][SD-ID2 ...]
        """
        fields = {}
        # Find all SD elements
        sd_elements = re.findall(r'\[([^\[\]]+)\]', sd_str)
        for element in sd_elements:
            parts = element.split(None, 1)
            if not parts:
                continue
            sd_id = parts[0].split("@")[0]  # Remove enterprise ID
            if len(parts) > 1:
                # Parse parameters
                params = re.findall(r'(\w+)="([^"]*)"', parts[1])
                for key, value in params:
                    field_key = f"{sd_id}.{key}" if sd_id != "exampleSDID" else key
                    fields[field_key.lower()] = value
                    # Also map common fields
                    if key.lower() in ("src", "source_ip"):
                        fields["source_ip"] = value
                    elif key.lower() in ("dst", "dest_ip"):
                        fields["dest_ip"] = value
        return fields

    def _classify_event(self, fields):
        """Classify event type from content."""
        app = (fields.get("product") or "").lower()
        msg = (fields.get("message") or "").lower()
        if app in ("sshd", "login", "pam", "auth"):
            return "authentication"
        if app in ("iptables", "ufw", "firewalld", "pf"):
            return "firewall"
        if app in ("named", "dnsmasq", "unbound"):
            return "dns"
        if app in ("httpd", "nginx", "apache"):
            return "web"
        if app in ("sudo", "su"):
            return "authorization"
        if app in ("clamd", "freshclam"):
            return "av_malware"
        if "auth" in msg or "login" in msg:
            return "authentication"
        return "system"
