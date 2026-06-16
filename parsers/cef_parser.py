"""
CEF (Common Event Format) parser.

CEF Format: CEF:Version|Device Vendor|Device Product|Device Version|
             Signature ID|Name|Severity|Extension

Extension fields are key=value pairs separated by spaces.

Example:
    CEF:0|Cisco|ASA|1.0|MyEvent|Message from 10.0.0.1|6|src=10.0.0.1 dst=192.168.1.1 spt=1234
"""

import re
import logging
from .base import BaseParser, ParseError, ParserResult

logger = logging.getLogger(__name__)


class CEFParser(BaseParser):
    """Parser for Common Event Format (CEF)."""

    # CEF header pattern (first 7 pipe-separated fields)
    # Note: pipes within field values should be escaped as \\|
    HEADER_PATTERN = re.compile(
        r'^CEF:(?P<version>\d+)\|'
        r'(?P<vendor>(?:[^|\\]|\\.)*)\|'
        r'(?P<product>(?:[^|\\]|\\.)*)\|'
        r'(?P<dev_version>(?:[^|\\]|\\.)*)\|'
        r'(?P<sig_id>(?:[^|\\]|\\.)*)\|'
        r'(?P<name>(?:[^|\\]|\\.)*)\|'
        r'(?P<severity>(?:[^|\\]|\\.)*)\|?'
        r'(?P<extension>.*)$',
        re.DOTALL
    )

    # CEF extension field mappings
    EXTENSION_MAP = {
        # Source
        "src": "source_ip", "sourceAddress": "source_ip", "sourceHostName": "source_host",
        "spt": "source_port", "sourcePort": "source_port",
        "suser": "source_user", "sourceUser": "source_user", "suid": "source_user",
        "smac": "source_mac", "sourceMacAddress": "source_mac",
        "sproc": "source_process", "sourceProcessName": "source_process",
        "spid": "source_pid", "sourceProcessId": "source_pid",
        # Destination
        "dst": "dest_ip", "destinationAddress": "dest_ip", "dhost": "dest_host",
        "destinationHostName": "dest_host",
        "dpt": "dest_port", "destinationPort": "dest_port",
        "duser": "dest_user", "destinationUser": "dest_user", "duid": "dest_user",
        "dmac": "dest_mac", "destinationMacAddress": "dest_mac",
        "dproc": "dest_process",
        "dpid": "dest_pid",
        # Network
        "proto": "protocol", "transportProtocol": "protocol",
        "in": "bytes_received", "bytesIn": "bytes_received",
        "out": "bytes_sent", "bytesOut": "bytes_sent",
        "duration": "duration",
        # Action
        "act": "action", "deviceAction": "action",
        "outcome": "result", "eventOutcome": "result",
        "reason": "reason", "actionReason": "reason",
        # Application
        "app": "protocol", "applicationProtocol": "protocol",
        "request": "url", "requestURL": "url",
        "requestMethod": "http_method",
        "requestClientApplication": "user_agent",
        # File
        "fname": "file_name", "fileName": "file_name",
        "fpath": "file_path", "filePath": "file_path",
        "fhash": "file_hash", "fileHash": "file_hash",
        "fsize": "file_size", "fileSize": "file_size",
        # Process
        "proc": "process_name", "processName": "process_name",
        "cmd": "command_line", "commandLine": "command_line",
        # DNS
        "query": "dns_query", "dnsQuery": "dns_query",
        "queryType": "dns_record_type",
        # Email
        "from": "email_from", "sender": "email_from",
        "to": "email_to", "recipient": "email_to",
        "subject": "email_subject",
        # Time
        "rt": "timestamp", "deviceTime": "timestamp", "end": "timestamp",
        "start": "timestamp",
        # Metadata
        "msg": "message", "message": "message",
        "cn1": "category", "category": "category",
        "sev": "severity",
        # Session
        "session": "session_id",
        # Custom fields
        "cs1": "custom_string_1", "cs2": "custom_string_2",
        "cn1Label": "_cn1_label",
        "cs1Label": "_cs1_label",
    }

    def __init__(self):
        super().__init__(
            name="cef",
            description="Common Event Format (CEF) parser",
            priority=70,
        )

    def parse(self, raw_data):
        data = self._decode(raw_data).strip()
        if not data.startswith("CEF:"):
            raise ParseError("Not a CEF message: missing CEF: prefix")

        match = self.HEADER_PATTERN.match(data)
        if not match:
            raise ParseError("Failed to parse CEF header")

        version = int(match.group("version"))
        vendor = self._unescape(match.group("vendor"))
        product = self._unescape(match.group("product"))
        dev_version = self._unescape(match.group("dev_version"))
        sig_id = self._unescape(match.group("sig_id"))
        name = self._unescape(match.group("name"))
        severity = self._unescape(match.group("severity"))
        extension = match.group("extension") or ""

        # Parse severity (can be string or number)
        severity_parsed = self._parse_severity(severity)

        fields = {
            "cef_version": version,
            "vendor": vendor or "Unknown",
            "product": product or "Unknown",
            "device_version": dev_version,
            "rule_id": sig_id,
            "message": name,
            "severity": severity_parsed,
            "raw_data": data,
            "collection_method": "cef",
            "event_type": self._classify_event(name, vendor, product),
        }

        # Parse extension key=value pairs
        ext_fields = self._parse_extension(extension)
        fields.update(ext_fields)

        # Process labels (cn1Label, cs1Label, etc.)
        self._process_labels(fields)

        fields = self._clean_fields(fields)
        return ParserResult(fields=fields, parser_name=self.name, confidence=0.95)

    def _unescape(self, value):
        """Unescape CEF special characters."""
        if not value:
            return value
        value = value.replace("\\|", "|")
        value = value.replace("\\\\", "\\")
        value = value.replace("\\n", "\n")
        value = value.replace("\\=", "=")
        return value.strip()

    def _parse_severity(self, severity):
        """Parse CEF severity (0-10 or Unknown/Low/Medium/High/Very-High)."""
        severity = severity.strip()
        try:
            sev_num = int(severity)
            if sev_num <= 0:
                return "info"
            elif sev_num <= 3:
                return "low"
            elif sev_num <= 6:
                return "medium"
            elif sev_num <= 8:
                return "high"
            else:
                return "critical"
        except ValueError:
            sev_lower = severity.lower()
            mapping = {
                "unknown": "info", "info": "info",
                "low": "low", "minor": "low",
                "medium": "medium", "moderate": "medium",
                "high": "high", "major": "high",
                "very-high": "critical", "critical": "critical",
                "severe": "critical",
            }
            return mapping.get(sev_lower, "medium")

    def _parse_extension(self, extension):
        """Parse CEF extension key=value pairs."""
        if not extension:
            return {}

        fields = {}
        # Key=value pairs, values can be quoted or extend to next key=
        # Pattern: key=value where value goes until the next "key=" pattern
        pattern = re.compile(r'(\w[\w\.]*)=(?:"([^"]*)"|(\S+?))(?=\s+\w+=|$)')
        for match in pattern.finditer(extension):
            key = match.group(1)
            value = match.group(2) or match.group(3) or ""
            value = self._unescape(value)

            mapped_key = self.EXTENSION_MAP.get(key, key.lower())
            if mapped_key not in fields:
                fields[mapped_key] = value
            else:
                if isinstance(fields[mapped_key], list):
                    fields[mapped_key].append(value)
                else:
                    fields[mapped_key] = [fields[mapped_key], value]

        return fields

    def _process_labels(self, fields):
        """Process label fields (e.g., cs1Label='Threat Name' -> rename cs1)."""
        labels_to_remove = []
        for key in list(fields.keys()):
            if key.endswith("Label") and key.startswith("_"):
                base_key = key[1:-5]  # Remove leading _ and trailing Label
                actual_key = base_key
                label_value = fields[key]
                if actual_key in fields and label_value:
                    # Rename field to its label value (lowercase, underscored)
                    new_name = re.sub(r'[^\w]', '_', label_value.lower()).strip("_")
                    if new_name and new_name != actual_key:
                        fields[new_name] = fields[actual_key]
                        del fields[actual_key]
                    labels_to_remove.append(key)

        for key in labels_to_remove:
            del fields[key]

    def _classify_event(self, name, vendor, product):
        """Classify event type from name and vendor/product."""
        name_lower = (name or "").lower()
        vendor_lower = (vendor or "").lower()
        product_lower = (product or "").lower()

        type_keywords = {
            "authentication": ["login", "logout", "auth", "logon", "logoff", "credential"],
            "network": ["connection", "connect", "socket", "packet"],
            "firewall": ["firewall", "deny", "permit", "allow", "block"],
            "dns": ["dns", "query", "resolve", "domain"],
            "web": ["http", "request", "web"],
            "file": ["file", "create", "modify", "delete", "write"],
            "process": ["process", "exec", "spawn", "launch"],
            "av_malware": ["malware", "virus", "trojan", "worm", "infection"],
            "ids_ips": ["intrusion", "alert", "attack", "exploit"],
            "vpn": ["vpn", "tunnel", "ipsec"],
            "email": ["email", "smtp", "mail", "spam"],
            "cloud": ["cloud", "aws", "azure", "gcp"],
        }

        combined = f"{name_lower} {vendor_lower} {product_lower}"
        for event_type, keywords in type_keywords.items():
            if any(kw in combined for kw in keywords):
                return event_type

        return "system"

    def can_parse(self, raw_data):
        data = self._decode(raw_data).strip()
        return data.startswith("CEF:")
