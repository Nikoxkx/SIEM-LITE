"""
CSV and TSV parsers for delimited log formats.

Handles logs with consistent column layouts such as firewall exports,
database audit logs, and system metrics.
"""

import csv
import io
import logging
from .base import BaseParser, ParseError, ParserResult

logger = logging.getLogger(__name__)


class CSVParser(BaseParser):
    """Parser for CSV (comma-separated values) log format.

    Supports configurable delimiters and column headers.
    """

    def __init__(self, name="csv", delimiter=",", columns=None,
                 has_header=True, field_map=None, description=""):
        super().__init__(name=name, description=description or "CSV parser", priority=25)
        self.delimiter = delimiter
        self.columns = columns or []
        self.has_header = has_header
        self.field_map = field_map or self._default_field_map()
        self._header_seen = False

    def _default_field_map(self):
        """Default field name mappings for CSV columns."""
        return {
            "timestamp": "timestamp", "time": "timestamp", "date": "timestamp",
            "datetime": "timestamp", "ts": "timestamp",
            "src": "source_ip", "src_ip": "source_ip", "source": "source_ip",
            "source_ip": "source_ip", "srcip": "source_ip",
            "dst": "dest_ip", "dst_ip": "dest_ip", "dest": "dest_ip",
            "dest_ip": "dest_ip", "dstip": "dest_ip", "target": "dest_ip",
            "src_port": "source_port", "spt": "source_port", "sport": "source_port",
            "dst_port": "dest_port", "dpt": "dest_port", "dport": "dest_port",
            "proto": "protocol", "protocol": "protocol",
            "action": "action", "act": "action",
            "user": "source_user", "username": "source_user",
            "status": "result", "result": "result", "outcome": "result",
            "severity": "severity", "level": "severity", "priority": "severity",
            "message": "message", "msg": "message", "desc": "message",
            "bytes": "bytes_sent", "packets": "packets_sent",
            "duration": "duration", "interface": "interface",
            "type": "event_type", "category": "category",
            "hostname": "source_host", "host": "source_host",
            "process": "process_name", "command": "command_line",
            "url": "url", "uri": "uri_path", "method": "http_method",
        }

    def set_columns(self, columns):
        """Set column names for headerless CSV files."""
        self.columns = list(columns)
        self.has_header = False

    def parse(self, raw_data):
        data = self._decode(raw_data).strip()
        if not data:
            raise ParseError("Empty CSV data")

        reader = csv.reader(io.StringIO(data), delimiter=self.delimiter)

        if self.has_header and not self.columns:
            # First row is header
            rows = list(reader)
            if not rows:
                raise ParseError("No data rows in CSV")
            self.columns = [c.strip().lower() for c in rows[0]]
            data_rows = rows[1:]
            if not data_rows:
                raise ParseError("CSV has header but no data")
            row = data_rows[0]
        elif self.columns:
            rows = list(reader)
            if not rows:
                raise ParseError("No data rows in CSV")
            row = rows[0]
        else:
            raise ParseError("No columns defined and has_header is False")

        if len(row) != len(self.columns):
            raise ParseError(
                f"Column count mismatch: expected {len(self.columns)}, got {len(row)}"
            )

        fields = {"raw_data": data, "collection_method": "csv", "vendor": "csv"}

        for col_name, value in zip(self.columns, row):
            value = self._clean_value(value)
            if value is not None:
                mapped = self.field_map.get(col_name, col_name.lower().replace(" ", "_"))
                if mapped not in fields:
                    fields[mapped] = value

        # Try to construct message
        if "message" not in fields:
            parts = []
            for key in ("action", "source_ip", "dest_ip", "result"):
                if key in fields:
                    parts.append(f"{key}={fields[key]}")
            fields["message"] = " ".join(parts) if parts else "CSV event"

        fields.setdefault("event_type", self._infer_type(fields))
        fields.setdefault("severity", "info")

        fields = self._clean_fields(fields)
        return ParserResult(fields=fields, parser_name=self.name, confidence=0.7)

    def _infer_type(self, fields):
        """Infer event type from fields."""
        action = str(fields.get("action", "")).lower()
        category = str(fields.get("category", "")).lower()
        combined = f"{action} {category}"

        if any(k in combined for k in ["login", "auth", "logon"]):
            return "authentication"
        if any(k in combined for k in ["firewall", "block", "deny", "allow"]):
            return "firewall"
        if any(k in combined for k in ["connection", "network"]):
            return "network"
        if any(k in combined for k in ["dns", "query"]):
            return "dns"
        return "system"

    def can_parse(self, raw_data):
        data = self._decode(raw_data).strip()
        if not data:
            return False
        # Check if it looks like CSV (has delimiter)
        if self.delimiter == ",":
            return "," in data and data.count(",") >= 2
        else:
            return self.delimiter in data and data.count(self.delimiter) >= 2


class TSVParser(CSVParser):
    """Parser for TSV (tab-separated values) log format."""

    def __init__(self, name="tsv", columns=None, has_header=True, field_map=None, description=""):
        super().__init__(
            name=name, delimiter="\t", columns=columns,
            has_header=has_header, field_map=field_map,
            description=description or "TSV parser"
        )
        self.priority = 22
