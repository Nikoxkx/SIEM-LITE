"""
Apache and Nginx web server log parsers.

Supports:
- Apache combined log format
- Apache common log format
- Apache error log format
- Nginx access log format
- Nginx error log format
"""

import re
import logging
from datetime import datetime, timezone
from .base import BaseParser, ParseError, ParserResult

logger = logging.getLogger(__name__)


class ApacheAccessParser(BaseParser):
    """Parser for Apache/Nginx access logs (combined format).

    Format: %h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\"

    Example:
        127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://example.com/start.html" "Mozilla/4.08 [en] (Win98; I ;Nav)"
    """

    # Combined log format
    COMBINED_PATTERN = re.compile(
        r'^(?P<source_ip>\S+)\s+'
        r'(?P<identd>\S+)\s+'
        r'(?P<source_user>\S+)\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<request>[^"]*)"\s+'
        r'(?P<status_code>\S+)\s+'
        r'(?P<bytes_sent>\S+)'
        r'(?:\s+"(?P<referer>[^"]*)")?'
        r'(?:\s+"(?P<user_agent>[^"]*)")?'
        r'.*$'
    )

    def __init__(self):
        super().__init__(
            name="apache",
            description="Apache/Nginx combined access log parser",
            priority=40,
        )

    def parse(self, raw_data):
        data = self._decode(raw_data).strip()

        match = self.COMBINED_PATTERN.match(data)
        if not match:
            raise ParseError("Failed to parse Apache access log")

        fields = {
            "raw_data": data,
            "source_ip": self._clean_value(match.group("source_ip")),
            "source_user": self._clean_value(match.group("source_user")),
            "timestamp": self._parse_apache_timestamp(match.group("timestamp")),
            "status_code": self._parse_int(match.group("status_code")),
            "bytes_sent": self._parse_int(match.group("bytes_sent")),
            "vendor": "Apache/Nginx",
            "product": "Web Server",
            "event_type": "web",
            "collection_method": "file",
        }

        if match.group("referer"):
            fields["referer"] = match.group("referer")
        if match.group("user_agent"):
            fields["user_agent"] = match.group("user_agent")

        # Parse request line
        request = match.group("request")
        if request:
            fields = self._parse_request(request, fields)

        # Determine action/result from status code
        status = fields.get("status_code")
        if status:
            if status < 400:
                fields["result"] = "success"
                fields["action"] = "request"
            elif status < 500:
                fields["result"] = "failure"
                fields["action"] = "request_denied"
            else:
                fields["result"] = "error"
                fields["action"] = "request_error"

        fields["message"] = self._build_message(fields)
        fields = self._clean_fields(fields)
        return ParserResult(fields=fields, parser_name=self.name, confidence=0.9)

    def _parse_apache_timestamp(self, ts_str):
        """Parse Apache timestamp format: 10/Oct/2000:13:55:36 -0700"""
        try:
            return datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            try:
                dt = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S")
                return dt.replace(tzinfo=timezone.utc)
            except ValueError:
                return ts_str

    def _parse_request(self, request, fields):
        """Parse HTTP request line: METHOD URI PROTOCOL"""
        parts = request.split()
        if len(parts) >= 2:
            fields["http_method"] = parts[0]
            fields["uri_path"] = parts[1]
            fields["url"] = parts[1]
            if len(parts) >= 3:
                fields["http_version"] = parts[2].replace("HTTP/", "")
        elif request:
            fields["message"] = request
        return fields

    def _parse_int(self, value):
        """Parse integer value, return None for '-'."""
        if value and value != "-":
            try:
                return int(value)
            except ValueError:
                pass
        return None

    def _build_message(self, fields):
        """Build a human-readable message."""
        method = fields.get("http_method", "")
        uri = fields.get("uri_path", "")
        status = fields.get("status_code", "")
        return f"{method} {uri} - {status}"

    def can_parse(self, raw_data):
        data = self._decode(raw_data).strip()
        # Quick check: starts with IP and contains quoted request
        if re.match(r'^\d+\.\d+\.\d+\.\d+\s', data) and '"' in data and "[" in data:
            return bool(self.COMBINED_PATTERN.match(data))
        return False


class NginxAccessParser(ApacheAccessParser):
    """Parser for Nginx access logs.

    Same format as Apache combined, but may include additional fields.
    """

    def __init__(self):
        super().__init__()
        self.name = "nginx"
        self.description = "Nginx access log parser"
        self.priority = 38
        self.field_map = {}


class ApacheErrorParser(BaseParser):
    """Parser for Apache error logs.

    Format: [DAY MON DD HH:MM:SS YYYY] [LEVEL] [CLIENT IP] MESSAGE

    Example:
        [Wed Oct 11 14:32:52 2000] [error] [client 127.0.0.1] client denied by server configuration
    """

    ERROR_PATTERN = re.compile(
        r'^\[(?P<timestamp>[^\]]+)\]\s+'
        r'\[(?P<severity>[^\]]+)\]\s+'
        r'(?:\[client\s+(?P<source_ip>[^\]]+)\]\s+)?'
        r'(?P<message>.*)$',
        re.DOTALL
    )

    def __init__(self):
        super().__init__(
            name="apache_error",
            description="Apache error log parser",
            priority=35,
        )

    def parse(self, raw_data):
        data = self._decode(raw_data).strip()

        match = self.ERROR_PATTERN.match(data)
        if not match:
            raise ParseError("Failed to parse Apache error log")

        fields = {
            "raw_data": data,
            "timestamp": self._parse_timestamp(match.group("timestamp")),
            "severity": self._map_severity(match.group("severity")),
            "message": match.group("message").strip(),
            "vendor": "Apache",
            "product": "Web Server",
            "event_type": "web",
            "result": "error",
            "action": "error",
            "collection_method": "file",
        }

        if match.group("source_ip"):
            fields["source_ip"] = match.group("source_ip")

        fields = self._clean_fields(fields)
        return ParserResult(fields=fields, parser_name=self.name, confidence=0.85)

    def _parse_timestamp(self, ts_str):
        """Parse Apache error timestamp: Wed Oct 11 14:32:52 2000"""
        try:
            return datetime.strptime(ts_str, "%a %b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
        except ValueError:
            return ts_str

    def _map_severity(self, severity):
        """Map Apache severity to canonical."""
        mapping = {
            "emerg": "emergency", "alert": "alert", "crit": "critical",
            "error": "error", "warn": "warning", "notice": "notice",
            "info": "info", "debug": "debug",
        }
        return mapping.get(severity.lower(), severity.lower())

    def can_parse(self, raw_data):
        data = self._decode(raw_data).strip()
        return data.startswith("[") and "]" in data[:40]


class NginxErrorParser(BaseParser):
    """Parser for Nginx error logs.

    Format: YYYY/MM/DD HH:MM:SS [LEVEL] PID#TID: *CID MESSAGE

    Example:
        2024/01/15 10:30:00 [error] 12345#0: *6789 open() failed
    """

    ERROR_PATTERN = re.compile(
        r'^(?P<timestamp>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'\[(?P<severity>\w+)\]\s+'
        r'(?P<pid>\d+)#\d+:\s+'
        r'(?:\*(?P<conn_id>\d+)\s+)?'
        r'(?P<message>.*?)'
        r'(?:,\s+client:\s+(?P<source_ip>[\d\.]+))?'
        r'(?:,\s+server:\s+(?P<server>[^,]+))?'
        r'(?:,\s+request:\s+"(?P<request>[^"]+)")?'
        r'.*$',
        re.DOTALL
    )

    def __init__(self):
        super().__init__(
            name="nginx_error",
            description="Nginx error log parser",
            priority=33,
        )

    def parse(self, raw_data):
        data = self._decode(raw_data).strip()

        match = self.ERROR_PATTERN.match(data)
        if not match:
            raise ParseError("Failed to parse Nginx error log")

        fields = {
            "raw_data": data,
            "timestamp": self._parse_timestamp(match.group("timestamp")),
            "severity": self._map_severity(match.group("severity")),
            "source_pid": int(match.group("pid")),
            "message": match.group("message").strip(),
            "vendor": "Nginx",
            "product": "Web Server",
            "event_type": "web",
            "result": "error",
            "action": "error",
            "collection_method": "file",
        }

        if match.group("source_ip"):
            fields["source_ip"] = match.group("source_ip")
        if match.group("server"):
            fields["dest_host"] = match.group("server")
        if match.group("request"):
            # Parse request
            parts = match.group("request").split()
            if len(parts) >= 2:
                fields["http_method"] = parts[0]
                fields["uri_path"] = parts[1]

        fields = self._clean_fields(fields)
        return ParserResult(fields=fields, parser_name=self.name, confidence=0.85)

    def _parse_timestamp(self, ts_str):
        """Parse Nginx timestamp: 2024/01/15 10:30:00"""
        try:
            return datetime.strptime(ts_str, "%Y/%m/%d %H:%M:%S").replace(tzinfo=timezone.utc)
        except ValueError:
            return ts_str

    def _map_severity(self, severity):
        """Map Nginx severity."""
        mapping = {
            "debug": "debug", "info": "info", "notice": "notice",
            "warn": "warning", "error": "error",
            "crit": "critical", "alert": "alert", "emerg": "emergency",
        }
        return mapping.get(severity.lower(), "error")
