"""
Event normalizer: converts parsed fields into the canonical event schema.

The normalizer applies field mappings, type coercion, severity normalization,
and standard field population to ensure all events have a consistent shape
regardless of their source format.
"""

import re
import logging
from datetime import datetime, timezone

from ..models.event import Event, EventStatus, CANONICAL_FIELDS

logger = logging.getLogger(__name__)


class Normalizer:
    """Normalizes parsed log data into canonical Event objects.

    The normalizer:
    1. Maps source-specific field names to canonical names
    2. Coerces field values to correct types
    3. Normalizes severity levels
    4. Populates derived fields (event_type, timestamp defaults)
    5. Adds source/product metadata
    """

    # Severity normalization mappings
    SEVERITY_MAP = {
        # Numeric severities (various sources)
        "0": "emergency", "1": "alert", "2": "critical",
        "3": "error", "4": "warning", "5": "notice",
        "6": "info", "7": "debug",
        # Named severities (various case variations)
        "emerg": "emergency", "emergency": "emergency",
        "alert": "alert",
        "crit": "critical", "critical": "critical",
        "err": "error", "error": "error", "fatal": "critical",
        "warn": "warning", "warning": "warning",
        "notice": "notice",
        "info": "info", "information": "info", "informational": "info",
        "debug": "debug",
        # Common alternatives
        "high": "high", "medium": "medium", "low": "low",
        "severe": "critical", "important": "high",
        "minor": "low", "major": "high",
        "trace": "debug", "verbose": "debug",
        "ok": "info", "success": "info",
        "fail": "error", "failure": "error", "failed": "error",
        "unknown": "info",
    }

    # Action normalization
    ACTION_MAP = {
        "accept": "accept", "accepted": "accept", "allow": "accept",
        "permit": "accept", "permitted": "accept", "pass": "accept",
        "deny": "deny", "denied": "deny", "block": "deny",
        "blocked": "deny", "reject": "deny", "rejected": "deny",
        "drop": "deny", "dropped": "deny",
        "logon": "logon", "login": "logon",
        "logoff": "logoff", "logout": "logoff",
        "connect": "connect", "connection": "connect",
        "disconnect": "disconnect",
        "create": "create", "add": "create", "new": "create",
        "modify": "modify", "update": "modify", "change": "modify", "set": "modify",
        "delete": "delete", "remove": "delete", "del": "delete", "rm": "delete",
        "read": "read", "get": "read", "access": "read",
        "write": "write", "put": "write", "save": "write",
        "execute": "execute", "exec": "execute", "run": "execute", "launch": "execute",
        "start": "start", "stop": "stop", "restart": "restart",
        "alert": "alert", "notify": "alert",
    }

    # Result normalization
    RESULT_MAP = {
        "success": "success", "successful": "success", "ok": "success",
        "succeeded": "success", "pass": "success", "allowed": "success",
        "accept": "success", "accepted": "success",
        "failure": "failure", "failed": "failure", "fail": "failure",
        "error": "error", "err": "error",
        "denied": "failure", "deny": "failure", "reject": "failure",
        "rejected": "failure", "blocked": "failure",
        "timeout": "error", "timed_out": "error",
        "pending": "pending", "in_progress": "pending",
        "unknown": "unknown", "none": "unknown",
    }

    def __init__(self, field_mappings=None, default_vendor="unknown",
                 default_product="unknown", config=None):
        """Initialize the normalizer.

        Args:
            field_mappings: Dict mapping source field names to canonical names.
            default_vendor: Default vendor if not specified.
            default_product: Default product if not specified.
            config: Optional configuration dict.
        """
        config = config or {}
        self.field_mappings = field_mappings or config.get("field_mappings", {})
        self.default_vendor = default_vendor if default_vendor != "unknown" else config.get("default_vendor", "unknown")
        self.default_product = default_product if default_product != "unknown" else config.get("default_product", "unknown")
        self._normalize_count = 0
        self._error_count = 0

    def normalize(self, parsed_fields, source_log=None):
        """Normalize parsed fields into an Event.

        Args:
            parsed_fields: Dict of fields from a parser.
            source_log: Source log identifier (collector name).

        Returns:
            Event object with normalized fields.
        """
        self._normalize_count += 1

        try:
            # Apply field mappings
            mapped = self._apply_mappings(parsed_fields)

            # Create event
            event = Event(source_log=source_log or "unknown")

            # Set all fields
            for field_name, value in mapped.items():
                if value is not None:
                    event.set(field_name, value)

            # Normalize specific fields
            self._normalize_severity(event)
            self._normalize_action(event)
            self._normalize_result(event)
            self._normalize_timestamp(event)
            self._normalize_event_type(event)
            self._normalize_ips(event)
            self._normalize_ports(event)
            self._populate_defaults(event)
            self._compute_derived_fields(event)

            # Set processing status
            event.set("event_status", EventStatus.NORMALIZED.value)

            return event

        except Exception as exc:
            self._error_count += 1
            logger.error("Normalization error: %s", exc, exc_info=True)
            # Return a basic event with error info
            event = Event(source_log=source_log or "unknown")
            event.set("raw_data", str(parsed_fields))
            event.set("event_status", EventStatus.ERROR.value)
            event.add_tag("normalization_error")
            return event

    def _apply_mappings(self, fields):
        """Apply field name mappings."""
        mapped = {}
        for key, value in fields.items():
            canonical = self.field_mappings.get(key, key)
            if canonical in mapped:
                if isinstance(mapped[canonical], list):
                    mapped[canonical].append(value)
                else:
                    mapped[canonical] = [mapped[canonical], value]
            else:
                mapped[canonical] = value
        return mapped

    def _normalize_severity(self, event):
        """Normalize severity to canonical values."""
        severity = event.get("severity")
        if not severity:
            event.set("severity", "info")
            return

        severity_str = str(severity).strip().lower()
        normalized = self.SEVERITY_MAP.get(severity_str)

        if not normalized:
            # Try numeric
            try:
                sev_num = int(severity_str)
                if 0 <= sev_num <= 7:
                    normalized = self.SEVERITY_MAP[str(sev_num)]
                elif sev_num > 7:
                    normalized = "debug"
                else:
                    normalized = "info"
            except ValueError:
                normalized = "info"

        event.set("severity", normalized)

    def _normalize_action(self, event):
        """Normalize action field."""
        action = event.get("action")
        if action:
            action_str = str(action).strip().lower()
            normalized = self.ACTION_MAP.get(action_str, action_str)
            event.set("action", normalized)

    def _normalize_result(self, event):
        """Normalize result field."""
        result = event.get("result")
        if result:
            result_str = str(result).strip().lower()
            normalized = self.RESULT_MAP.get(result_str, result_str)
            event.set("result", normalized)

        # Infer result from status code
        if not result and event.get("status_code"):
            status = event.get("status_code")
            try:
                status_int = int(status)
                if 200 <= status_int < 400:
                    event.set("result", "success")
                elif 400 <= status_int < 500:
                    event.set("result", "failure")
                else:
                    event.set("result", "error")
            except (ValueError, TypeError):
                pass

    def _normalize_timestamp(self, event):
        """Ensure timestamp is set and valid."""
        ts = event.get("timestamp")
        if ts is None:
            event.set("timestamp", datetime.now(timezone.utc))
            return

        if isinstance(ts, str):
            from ..utils.time_utils import parse_timestamp
            parsed = parse_timestamp(ts)
            if parsed:
                event.set("timestamp", parsed)
            else:
                event.set("timestamp", datetime.now(timezone.utc))
                event.add_tag("invalid_timestamp")

    def _normalize_event_type(self, event):
        """Ensure event_type is set."""
        event_type = event.get("event_type")
        if not event_type or event_type == "unknown":
            inferred = self._infer_event_type(event)
            event.set("event_type", inferred)

    def _infer_event_type(self, event):
        """Infer event type from fields."""
        # Check product/vendor
        product = str(event.get("product", "")).lower()
        vendor = str(event.get("vendor", "")).lower()
        action = str(event.get("action", "")).lower()
        message = str(event.get("message", "")).lower()

        # Product-based inference
        product_types = {
            "sshd": "authentication", "login": "authentication", "pam": "authentication",
            "iptables": "firewall", "ufw": "firewall", "pf": "firewall", "firewalld": "firewall",
            "named": "dns", "dnsmasq": "dns", "unbound": "dns", "bind": "dns",
            "httpd": "web", "nginx": "web", "apache": "web",
            "clamd": "av_malware", "freshclam": "av_malware", "windows defender": "av_malware",
            "sudo": "authorization", "openvpn": "vpn", "strongswan": "vpn",
            "auditd": "audit", "postgresql": "database", "mysql": "database",
        }

        for keyword, etype in product_types.items():
            if keyword in product or keyword in vendor:
                return etype

        # Action-based inference
        action_types = {
            "logon": "authentication", "logoff": "authentication",
            "logon_failed": "authentication", "logon_explicit": "authentication",
            "connect": "network", "disconnect": "network",
            "process_created": "process", "process_terminated": "process",
            "file_access": "file", "object_access": "file",
            "request": "web", "request_denied": "web",
        }

        if action in action_types:
            return action_types[action]

        # Message-based inference
        if any(w in message for w in ["login", "auth", "password"]):
            return "authentication"
        if any(w in message for w in ["firewall", "blocked", "permit"]):
            return "firewall"
        if any(w in message for w in ["process", "exec", "spawn"]):
            return "process"
        if any(w in message for w in ["file", "write", "delete"]):
            return "file"

        # Check for network indicators
        if event.get("source_port") or event.get("dest_port"):
            return "network"

        return "system"

    def _normalize_ips(self, event):
        """Normalize and validate IP addresses."""
        from ..utils.geoip import IPClassifier

        for ip_field in ("source_ip", "dest_ip"):
            ip_val = event.get(ip_field)
            if ip_val:
                ip_str = str(ip_val).strip()
                # Check if it's actually a hostname (not an IP)
                if not IPClassifier.is_valid_ip(ip_str):
                    # Try to handle hostname cases
                    if ip_field == "source_ip" and not event.get("source_host"):
                        event.set("source_host", ip_str)
                        event._data.pop(ip_field, None)
                    elif ip_field == "dest_ip" and not event.get("dest_host"):
                        event.set("dest_host", ip_str)
                        event._data.pop(ip_field, None)
                    continue

                # Set internal/external flag
                is_internal = IPClassifier.is_internal(ip_str)
                if ip_field == "source_ip":
                    event.set("source_is_internal", is_internal)
                else:
                    event.set("dest_is_internal", is_internal)

    def _normalize_ports(self, event):
        """Normalize port numbers."""
        for port_field in ("source_port", "dest_port"):
            port_val = event.get(port_field)
            if port_val and isinstance(port_val, str):
                try:
                    port = int(port_val)
                    if 0 <= port <= 65535:
                        event.set(port_field, port)
                    else:
                        event._data.pop(port_field, None)
                except ValueError:
                    event._data.pop(port_field, None)

    def _populate_defaults(self, event):
        """Populate default field values."""
        if not event.get("vendor"):
            event.set("vendor", self.default_vendor)
        if not event.get("product"):
            event.set("product", self.default_product)
        if not event.get("message"):
            event.set("message", event.get("action", "Event"))
        if not event.get("ingest_time"):
            event.set("ingest_time", datetime.now(timezone.utc))

    def _compute_derived_fields(self, event):
        """Compute derived field values."""
        # Determine if this is internal-to-internal traffic
        src_internal = event.get("source_is_internal", False)
        dst_internal = event.get("dest_is_internal", False)

        if src_internal and dst_internal:
            event.set("direction", "internal")
        elif src_internal and not dst_internal:
            event.set("direction", "outbound")
        elif not src_internal and dst_internal:
            event.set("direction", "inbound")
        elif event.get("source_ip") or event.get("dest_ip"):
            event.set("direction", "external")

        # Classify by protocol/port
        if not event.get("category"):
            dest_port = event.get("dest_port")
            if dest_port:
                category = self._port_to_category(dest_port)
                if category:
                    event.set("category", category)

    @staticmethod
    def _port_to_category(port):
        """Map a port number to a service category."""
        port_categories = {
            20: "ftp", 21: "ftp", 22: "ssh", 23: "telnet",
            25: "smtp", 53: "dns", 69: "tftp",
            80: "http", 88: "kerberos", 110: "pop3",
            111: "rpc", 123: "ntp", 135: "rpc",
            137: "netbios", 138: "netbios", 139: "netbios",
            143: "imap", 161: "snmp", 162: "snmp",
            389: "ldap", 443: "https", 445: "smb",
            465: "smtps", 514: "syslog", 587: "smtp",
            636: "ldaps", 873: "rsync", 993: "imaps",
            995: "pop3s", 1080: "socks", 1194: "openvpn",
            1433: "mssql", 1521: "oracle", 1723: "pptp",
            2049: "nfs", 3306: "mysql", 3389: "rdp",
            5432: "postgresql", 5900: "vnc", 5985: "winrm",
            5986: "winrm", 6379: "redis", 8080: "http_proxy",
            8443: "https", 9092: "kafka", 9200: "elasticsearch",
            27017: "mongodb",
        }
        return port_categories.get(int(port) if isinstance(port, (int, str)) else 0)

    def add_field_mapping(self, source_field, canonical_field):
        """Add a custom field mapping."""
        self.field_mappings[source_field] = canonical_field

    def get_stats(self):
        """Get normalization statistics."""
        return {
            "normalize_count": self._normalize_count,
            "error_count": self._error_count,
            "field_mappings": len(self.field_mappings),
        }

    def reset_stats(self):
        """Reset statistics."""
        self._normalize_count = 0
        self._error_count = 0
