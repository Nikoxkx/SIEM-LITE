"""
Event model: the central normalized data structure for all ingested logs.

Every log entry from every source is normalized into an Event object with
a consistent set of fields, enabling cross-source correlation and analysis.

The schema is loosely based on the Open Cybersecurity Schema Framework (OCSF)
but simplified for the SIEM-Lite use case.
"""

import time
import uuid
import json
import hashlib
import ipaddress
from datetime import datetime, timezone
from enum import Enum
from copy import deepcopy


class EventStatus(Enum):
    """Processing status of an event in the pipeline."""
    NEW = "new"
    PARSED = "parsed"
    NORMALIZED = "normalized"
    ENRICHED = "enriched"
    CORRELATED = "correlated"
    ARCHIVED = "archived"
    DROPPED = "dropped"
    ERROR = "error"


class EventType(Enum):
    """High-level classification of event types."""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    NETWORK = "network"
    SYSTEM = "system"
    FILE = "file"
    PROCESS = "process"
    REGISTRY = "registry"
    DATABASE = "database"
    WEB = "web"
    EMAIL = "email"
    DNS = "dns"
    VPN = "vpn"
    FIREWALL = "firewall"
    IDS_IPS = "ids_ips"
    AV_MALWARE = "av_malware"
    DLP = "dlp"
    AUDIT = "audit"
    CLOUD = "cloud"
    CONTAINER = "container"
    APPLICATION = "application"
    OTHER = "other"
    UNKNOWN = "unknown"


# Canonical field definitions: (field_name, data_type, description, indexed)
CANONICAL_FIELDS = {
    # Identity
    "event_id": ("str", "Unique event identifier", True),
    "event_type": ("str", "Event type classification", True),
    "event_status": ("str", "Processing pipeline status", False),
    "raw_data": ("str", "Original raw log line", False),

    # Time
    "timestamp": ("datetime", "Event occurrence time (UTC)", True),
    "ingest_time": ("datetime", "When event entered the pipeline", False),
    "process_time": ("datetime", "When event completed processing", False),

    # Source
    "source_ip": ("str", "Source IP address", True),
    "source_port": ("int", "Source port number", True),
    "source_host": ("str", "Source hostname", True),
    "source_user": ("str", "Source user/service account", True),
    "source_mac": ("str", "Source MAC address", False),
    "source_asset": ("str", "Source asset identifier", True),
    "source_process": ("str", "Source process name", False),
    "source_pid": ("int", "Source process ID", False),

    # Destination
    "dest_ip": ("str", "Destination IP address", True),
    "dest_port": ("int", "Destination port number", True),
    "dest_host": ("str", "Destination hostname", True),
    "dest_user": ("str", "Destination user", True),
    "dest_mac": ("str", "Destination MAC address", False),
    "dest_asset": ("str", "Destination asset identifier", True),
    "dest_process": ("str", "Destination process name", False),
    "dest_pid": ("int", "Destination process ID", False),

    # Network
    "protocol": ("str", "Protocol (TCP/UDP/ICMP)", True),
    "transport": ("str", "Transport layer", True),
    "direction": ("str", "Connection direction (inbound/outbound)", True),
    "bytes_sent": ("int", "Bytes sent", False),
    "bytes_received": ("int", "Bytes received", False),
    "packets_sent": ("int", "Packets sent", False),
    "packets_received": ("int", "Packets received", False),
    "duration": ("float", "Connection/operation duration (seconds)", False),
    "interface": ("str", "Network interface", False),

    # Action / Result
    "action": ("str", "Action performed", True),
    "result": ("str", "Action result (success/failure/error)", True),
    "severity": ("str", "Event severity", True),
    "outcome": ("str", "Detailed outcome", False),
    "status_code": ("int", "HTTP or protocol status code", True),
    "reason": ("str", "Reason for action/failure", False),

    # Authentication specifics
    "auth_method": ("str", "Authentication method", True),
    "auth_protocol": ("str", "Auth protocol (Kerberos/NTLM/SSH)", True),
    "logon_type": ("str", "Windows logon type", False),
    "session_id": ("str", "Session identifier", True),

    # File / Process
    "file_name": ("str", "File name", True),
    "file_path": ("str", "Full file path", True),
    "file_hash": ("str", "File hash (MD5/SHA)", True),
    "file_size": ("int", "File size in bytes", False),
    "process_name": ("str", "Process name", True),
    "process_path": ("str", "Full process path", True),
    "command_line": ("str", "Command line arguments", True),
    "parent_process": ("str", "Parent process name", False),
    "parent_pid": ("int", "Parent process ID", False),

    # Application / Web
    "url": ("str", "URL", True),
    "http_method": ("str", "HTTP method", True),
    "user_agent": ("str", "User agent string", False),
    "referer": ("str", "HTTP referer", False),
    "uri_path": ("str", "URI path", True),
    "query_string": ("str", "Query string", False),
    "http_version": ("str", "HTTP version", False),

    # DNS / Email
    "dns_query": ("str", "DNS query name", True),
    "dns_record_type": ("str", "DNS record type", True),
    "dns_response": ("str", "DNS response", False),
    "email_from": ("str", "Email sender", True),
    "email_to": ("str", "Email recipient", True),
    "email_subject": ("str", "Email subject", True),
    "email_attachment": ("str", "Email attachment name", False),

    # Metadata
    "product": ("str", "Source product/tool", True),
    "vendor": ("str", "Vendor name", True),
    "category": ("str", "Event category", True),
    "subcategory": ("str", "Event subcategory", True),
    "facility": ("str", "Syslog facility", True),
    "priority": ("int", "Syslog priority", False),
    "message": ("str", "Human-readable message", False),

    # Enrichment (added during processing)
    "source_country": ("str", "Source geo: country", True),
    "source_city": ("str", "Source geo: city", False),
    "source_asn": ("str", "Source ASN", True),
    "source_isp": ("str", "Source ISP", False),
    "source_is_internal": ("bool", "Whether source is internal", True),
    "dest_country": ("str", "Destination geo: country", True),
    "dest_city": ("str", "Destination geo: city", False),
    "dest_asn": ("str", "Destination ASN", True),
    "dest_is_internal": ("bool", "Whether destination is internal", True),
    "reputation_score": ("int", "IP reputation score", True),
    "threat_tags": ("list", "Threat intelligence tags", True),
    "ioc_matched": ("str", "Matched IOC value", True),

    # Correlation
    "rule_id": ("str", "Triggered rule ID", True),
    "rule_name": ("str", "Triggered rule name", True),
    "risk_score": ("float", "Computed risk score", True),
    "correlation_id": ("str", "Correlation group ID", True),
    "tags": ("list", "Event tags", True),
    "mitre_attack": ("list", "MITRE ATT&CK technique IDs", True),

    # Additional context
    "extra": ("dict", "Additional fields", False),
    "source_log": ("str", "Source log identifier", True),
    "parser": ("str", "Parser used", False),
    "collection_method": ("str", "How the log was collected", False),
    "retention_days": ("int", "Retention period", False),
}


class EventField:
    """Represents a single field with metadata."""

    __slots__ = ("name", "value", "type", "indexed")

    def __init__(self, name, value=None, type_hint="str", indexed=True):
        self.name = name
        self.value = value
        self.type = type_hint
        self.indexed = indexed

    def __repr__(self):
        return f"EventField(name={self.name!r}, value={self.value!r}, type={self.type})"

    def to_dict(self):
        return {"name": self.name, "value": self.value, "type": self.type, "indexed": self.indexed}


class Event:
    """
    Normalized event object. This is the universal data structure that all
    logs are converted to after parsing and normalization.

    Supports dict-like access, serialization, hashing, and deduplication.
    """

    # Fields that participate in deduplication hashing
    DEDUP_FIELDS = (
        "timestamp", "source_ip", "dest_ip", "source_port",
        "dest_port", "action", "result", "product", "message"
    )

    def __init__(self, data=None, **kwargs):
        """Initialize an event with optional data dict and/or kwargs.

        Args:
            data: Dictionary of field values to initialize with.
            **kwargs: Additional field values.
        """
        self._data = {}
        self._fields = {}
        self._dirty = False
        self._hash = None

        # Initialize with canonical field defaults
        for fname, (ftype, _, _) in CANONICAL_FIELDS.items():
            self._fields[fname] = EventField(fname, None, ftype, True)

        # Generate unique event ID
        self._data["event_id"] = str(uuid.uuid4())
        self._data["ingest_time"] = datetime.now(timezone.utc)

        # Merge data sources
        if data:
            if isinstance(data, Event):
                data = data.to_dict()
            for key, val in data.items():
                self.set(key, val)

        for key, val in kwargs.items():
            self.set(key, val)

        if "event_status" not in self._data:
            self._data["event_status"] = EventStatus.NEW.value
        if "tags" not in self._data:
            self._data["tags"] = []
        if "threat_tags" not in self._data:
            self._data["threat_tags"] = []
        if "mitre_attack" not in self._data:
            self._data["mitre_attack"] = []
        if "extra" not in self._data:
            self._data["extra"] = {}

    # --- Dict-like interface ---

    def __getitem__(self, key):
        return self._data.get(key)

    def __setitem__(self, key, value):
        self.set(key, value)

    def __delitem__(self, key):
        if key in self._data:
            del self._data[key]
            self._dirty = True

    def __contains__(self, key):
        return key in self._data and self._data[key] is not None

    def __iter__(self):
        return iter(self._data)

    def __len__(self):
        return len(self._data)

    def __eq__(self, other):
        if not isinstance(other, Event):
            return False
        return self.event_id == other.event_id

    def __hash__(self):
        if self._hash is None:
            self._hash = int(self.event_id.replace("-", ""), 16)
        return self._hash

    def __repr__(self):
        src = self._data.get("source_ip", "?")
        dst = self._data.get("dest_ip", "?")
        act = self._data.get("action", "?")
        ts = self._data.get("timestamp", "?")
        return f"Event(id={self._data['event_id'][:8]}, ts={ts}, {src}->{dst}, action={act})"

    # --- Property access ---

    @property
    def event_id(self):
        return self._data.get("event_id")

    @property
    def timestamp(self):
        return self._data.get("timestamp")

    @property
    def ingest_time(self):
        return self._data.get("ingest_time")

    @property
    def event_type(self):
        return self._data.get("event_type")

    @property
    def source_ip(self):
        return self._data.get("source_ip")

    @property
    def dest_ip(self):
        return self._data.get("dest_ip")

    @property
    def severity(self):
        return self._data.get("severity", "info")

    @property
    def risk_score(self):
        return self._data.get("risk_score", 0.0)

    @property
    def is_internal(self):
        """Check if both source and dest are internal."""
        return (self._data.get("source_is_internal", False) and
                self._data.get("dest_is_internal", False))

    @property
    def raw_data(self):
        return self._data.get("raw_data", "")

    # --- Field management ---

    def get(self, key, default=None):
        """Get a field value, returning default if not present."""
        return self._data.get(key, default)

    def set(self, key, value):
        """Set a field value with type coercion."""
        if value is None:
            return

        # Type coercion based on canonical field definition
        if key in CANONICAL_FIELDS:
            ftype = CANONICAL_FIELDS[key][0]
            value = self._coerce_type(value, ftype)
        else:
            # Non-canonical fields go into 'extra'
            if key not in self._data.setdefault("extra", {}):
                self._data["extra"][key] = value
            else:
                self._data["extra"][key] = value
            self._dirty = True
            return

        self._data[key] = value
        self._dirty = True

    def update(self, other):
        """Update fields from another dict or Event."""
        if isinstance(other, Event):
            other = other.to_dict()
        elif not isinstance(other, dict):
            raise TypeError("update() requires a dict or Event")
        for key, val in other.items():
            self.set(key, val)

    def add_tag(self, tag):
        """Add a tag to the event."""
        tags = self._data.setdefault("tags", [])
        if tag not in tags:
            tags.append(tag)
            self._dirty = True

    def remove_tag(self, tag):
        """Remove a tag from the event."""
        tags = self._data.get("tags", [])
        if tag in tags:
            tags.remove(tag)
            self._dirty = True

    def add_threat_tag(self, tag):
        """Add a threat intelligence tag."""
        tags = self._data.setdefault("threat_tags", [])
        if tag not in tags:
            tags.append(tag)
            self._dirty = True

    def add_mitre(self, technique_id):
        """Add a MITRE ATT&CK technique ID."""
        techniques = self._data.setdefault("mitre_attack", [])
        if technique_id not in techniques:
            techniques.append(technique_id)
            self._dirty = True

    def has_tag(self, tag):
        """Check if event has a specific tag."""
        return tag in self._data.get("tags", [])

    # --- Type coercion ---

    @staticmethod
    def _coerce_type(value, target_type):
        """Coerce a value to the target type."""
        if value is None:
            return None
        try:
            if target_type == "int":
                if isinstance(value, str):
                    return int(float(value)) if "." in value else int(value)
                return int(value)
            elif target_type == "float":
                return float(value)
            elif target_type == "bool":
                if isinstance(value, str):
                    return value.lower() in ("true", "1", "yes", "on")
                return bool(value)
            elif target_type == "datetime":
                if isinstance(value, datetime):
                    if value.tzinfo is None:
                        return value.replace(tzinfo=timezone.utc)
                    return value
                if isinstance(value, (int, float)):
                    return datetime.fromtimestamp(value, tz=timezone.utc)
                if isinstance(value, str):
                    return _parse_datetime(value)
                return value
            elif target_type == "list":
                if isinstance(value, list):
                    return value
                return [value]
            elif target_type == "dict":
                if isinstance(value, dict):
                    return value
                if isinstance(value, str):
                    try:
                        return json.loads(value)
                    except (json.JSONDecodeError, ValueError):
                        return {"raw": value}
                return {"raw": str(value)}
            else:  # str
                if isinstance(value, (dict, list)):
                    return json.dumps(value)
                return str(value)
        except (ValueError, TypeError) as exc:
            return value

    # --- Validation ---

    def validate(self):
        """Validate the event. Returns (is_valid, list_of_errors)."""
        errors = []
        eid = self._data.get("event_id")
        if not eid:
            errors.append("Missing event_id")
        if not self._data.get("timestamp"):
            errors.append("Missing timestamp")
        if not self._data.get("source_log"):
            errors.append("Missing source_log identifier")

        # Validate IP addresses if present
        for ip_field in ("source_ip", "dest_ip"):
            ip_val = self._data.get(ip_field)
            if ip_val and ip_val != "-":
                try:
                    ipaddress.ip_address(ip_val)
                except ValueError:
                    errors.append(f"Invalid {ip_field}: {ip_val}")

        return (len(errors) == 0, errors)

    # --- Deduplication ---

    def dedup_hash(self):
        """Compute a hash for deduplication based on key fields."""
        parts = []
        for field_name in self.DEDUP_FIELDS:
            val = self._data.get(field_name)
            if val is not None:
                parts.append(str(val))
        digest = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
        return digest

    def is_duplicate_of(self, other):
        """Check if this event is a near-duplicate of another."""
        if not isinstance(other, Event):
            return False
        return self.dedup_hash() == other.dedup_hash()

    # --- Serialization ---

    def to_dict(self, include_raw=True):
        """Convert to a plain dictionary."""
        result = {}
        for key, val in self._data.items():
            if isinstance(val, datetime):
                result[key] = val.isoformat()
            elif isinstance(val, dict):
                result[key] = dict(val)
            elif isinstance(val, list):
                result[key] = list(val)
            else:
                result[key] = val
        if not include_raw:
            result.pop("raw_data", None)
        return result

    def to_json(self, indent=None, include_raw=True):
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(include_raw), indent=indent, default=str)

    def to_flat_dict(self):
        """Return a flattened dictionary (extra fields promoted to top level)."""
        result = self.to_dict()
        extra = result.pop("extra", {})
        for k, v in extra.items():
            if k not in result:
                result[k] = v
        return result

    def to_syslog(self):
        """Convert back to a syslog-like string representation."""
        ts = self._data.get("timestamp")
        host = self._data.get("source_host") or self._data.get("source_ip") or "unknown"
        msg = self._data.get("message") or self._data.get("action", "event")
        facility = self._data.get("facility", "local0")
        severity = self._data.get("severity", "info")
        ts_str = ts.isoformat() if ts else datetime.now(timezone.utc).isoformat()
        return f"{ts_str} {host} {facility}[{severity}]: {msg}"

    def to_cef(self):
        """Convert to Common Event Format (CEF) string."""
        vendor = self._data.get("vendor", "SIEM-Lite")
        product = self._data.get("product", "Generic")
        version = "1.0"
        sig_id = self._data.get("rule_id", "0")
        name = self._data.get("message") or self._data.get("action", "Event")
        sev_map = {"emergency": 10, "alert": 9, "critical": 8, "error": 7,
                   "warning": 5, "notice": 3, "info": 1, "debug": 0}
        severity = sev_map.get(self._data.get("severity", "info"), 1)

        cef = f"CEF:0|{vendor}|{product}|{version}|{sig_id}|{name}|{severity}"
        extensions = []
        field_map = {
            "src": "source_ip", "spt": "source_port", "dst": "dest_ip",
            "dpt": "dest_port", "act": "action", "proto": "protocol",
            "suser": "source_user", "duser": "dest_user",
            "msg": "message", "rt": "timestamp",
        }
        for ext_key, field in field_map.items():
            val = self._data.get(field)
            if val is not None:
                if isinstance(val, datetime):
                    val = int(val.timestamp() * 1000)
                extensions.append(f"{ext_key}={val}")

        if extensions:
            cef += " " + " ".join(extensions)
        return cef

    @classmethod
    def from_dict(cls, data):
        """Create an Event from a dictionary."""
        event = cls()
        for key, val in data.items():
            event.set(key, val)
        return event

    @classmethod
    def from_json(cls, json_str):
        """Create an Event from a JSON string."""
        return cls.from_dict(json.loads(json_str))

    def copy(self):
        """Return a deep copy of this event."""
        new = Event()
        new._data = deepcopy(self._data)
        new._fields = deepcopy(self._fields)
        new._data["event_id"] = str(uuid.uuid4())
        return new

    def age(self, now=None):
        """Return the age of the event in seconds."""
        if now is None:
            now = datetime.now(timezone.utc)
        ts = self._data.get("timestamp")
        if ts is None:
            return float("inf")
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return (now - ts).total_seconds()

    def summary(self):
        """Return a one-line summary string."""
        parts = []
        ts = self._data.get("timestamp")
        if ts:
            parts.append(str(ts))
        sip = self._data.get("source_ip")
        if sip:
            parts.append(sip)
        dip = self._data.get("dest_ip")
        if dip:
            parts.append(f"->{dip}")
        action = self._data.get("action")
        if action:
            parts.append(action)
        result = self._data.get("result")
        if result:
            parts.append(f"[{result}]")
        msg = self._data.get("message")
        if msg:
            parts.append(f'"{msg[:50]}"')
        return " ".join(parts)


def _parse_datetime(value):
    """Parse a datetime string in various formats."""
    if not value:
        return None

    # Try ISO format first
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        pass

    # Try common formats
    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y/%m/%d %H:%M:%S",
        "%d/%b/%Y:%H:%M:%S %z",
        "%b %d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%SZ",
        "%d/%b/%Y:%H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",
        "%Y%m%d%H%M%S",
    ]

    for fmt in formats:
        try:
            dt = datetime.strptime(value, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except (ValueError, TypeError):
            continue

    # Try epoch timestamps
    try:
        ts = float(value)
        if ts > 1e12:  # milliseconds
            ts /= 1000
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    except (ValueError, TypeError):
        pass

    # Return as-is if nothing works
    return value
