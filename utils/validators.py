"""
Input validation utilities.

Provides validation functions for common data types used in the SIEM system.
"""

import re
import ipaddress
import html
import logging

logger = logging.getLogger(__name__)

# Regex patterns
EMAIL_PATTERN = re.compile(
    r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
)
URL_PATTERN = re.compile(
    r'^https?://[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?'
    r'(:\d+)?(/[^\s]*)?$'
)
UUID_PATTERN = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.IGNORECASE
)
MAC_PATTERN = re.compile(
    r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
)
HASH_PATTERN_MD5 = re.compile(r'^[a-fA-F0-9]{32}$')
HASH_PATTERN_SHA1 = re.compile(r'^[a-fA-F0-9]{40}$')
HASH_PATTERN_SHA256 = re.compile(r'^[a-fA-F0-9]{64}$')
HASH_PATTERN_SHA512 = re.compile(r'^[a-fA-F0-9]{128}$')

HOSTNAME_PATTERN = re.compile(
    r'^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])'
    r'(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]))*$'
)

VALID_SEVERITIES = {"emergency", "alert", "critical", "error",
                    "warning", "notice", "info", "debug",
                    "low", "medium", "high"}


def validate_ip(ip_str):
    """Validate an IP address (IPv4 or IPv6).

    Returns (is_valid, parsed_ip or error_message).
    """
    if not ip_str or not isinstance(ip_str, str):
        return False, "IP address is required"
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return True, str(ip)
    except ValueError:
        return False, f"Invalid IP address: {ip_str}"


def validate_cidr(cidr_str):
    """Validate a CIDR notation.

    Returns (is_valid, network or error_message).
    """
    if not cidr_str:
        return False, "CIDR is required"
    try:
        network = ipaddress.ip_network(cidr_str.strip(), strict=False)
        return True, str(network)
    except ValueError:
        return False, f"Invalid CIDR: {cidr_str}"


def validate_email(email):
    """Validate an email address."""
    if not email:
        return False, "Email is required"
    if not EMAIL_PATTERN.match(email.strip()):
        return False, f"Invalid email: {email}"
    return True, email.strip().lower()


def validate_url(url):
    """Validate a URL."""
    if not url:
        return False, "URL is required"
    if not URL_PATTERN.match(url.strip()):
        return False, f"Invalid URL: {url}"
    return True, url.strip()


def validate_port(port):
    """Validate a network port number."""
    try:
        port_num = int(port)
        if 0 <= port_num <= 65535:
            return True, port_num
        return False, f"Port out of range: {port}"
    except (ValueError, TypeError):
        return False, f"Invalid port: {port}"


def validate_hostname(hostname):
    """Validate a hostname."""
    if not hostname:
        return False, "Hostname is required"
    hostname = hostname.strip()
    if len(hostname) > 253:
        return False, "Hostname too long"
    if not HOSTNAME_PATTERN.match(hostname):
        return False, f"Invalid hostname: {hostname}"
    return True, hostname


def validate_mac_address(mac):
    """Validate a MAC address."""
    if not mac:
        return False, "MAC address is required"
    if not MAC_PATTERN.match(mac.strip()):
        return False, f"Invalid MAC address: {mac}"
    return True, mac.strip().lower()


def validate_hash(hash_str):
    """Validate a hash and detect its type.

    Returns (is_valid, hash_type).
    """
    if not hash_str:
        return False, "Hash is required"
    hash_str = hash_str.strip().lower()
    if HASH_PATTERN_MD5.match(hash_str):
        return True, "md5"
    if HASH_PATTERN_SHA1.match(hash_str):
        return True, "sha1"
    if HASH_PATTERN_SHA256.match(hash_str):
        return True, "sha256"
    if HASH_PATTERN_SHA512.match(hash_str):
        return True, "sha512"
    return False, f"Invalid hash: {hash_str}"


def validate_uuid(uuid_str):
    """Validate a UUID string."""
    if not uuid_str:
        return False, "UUID is required"
    if not UUID_PATTERN.match(uuid_str.strip()):
        return False, f"Invalid UUID: {uuid_str}"
    return True, uuid_str.strip().lower()


def validate_severity(severity):
    """Validate a severity level."""
    if not severity:
        return False, "Severity is required"
    severity = severity.strip().lower()
    if severity not in VALID_SEVERITIES:
        return False, f"Invalid severity: {severity}"
    return True, severity


def validate_rule_name(name):
    """Validate a rule name."""
    if not name:
        return False, "Rule name is required"
    name = name.strip()
    if len(name) < 3:
        return False, "Rule name must be at least 3 characters"
    if len(name) > 200:
        return False, "Rule name must be at most 200 characters"
    return True, name


def validate_event_type(event_type):
    """Validate an event type against known types."""
    if not event_type:
        return False, "Event type is required"
    valid_types = {
        "authentication", "authorization", "network", "system", "file",
        "process", "registry", "database", "web", "email", "dns", "vpn",
        "firewall", "ids_ips", "av_malware", "dlp", "audit", "cloud",
        "container", "application", "other", "unknown",
    }
    if event_type.lower() not in valid_types:
        return False, f"Invalid event type: {event_type}"
    return True, event_type.lower()


# SQL injection prevention
SQL_DANGEROUS_PATTERNS = [
    r"(\b(union|select|insert|update|delete|drop|create|alter|exec)\b.*\b(from|into|table|database)\b)",
    r"(--|/\*|\*/|;)",
    r"(\bor\b\s+1\s*=\s*1)",
    r"(\band\b\s+1\s*=\s*1)",
    r"(\bxp_cmdshell\b)",
    r"(\bsp_executesql\b)",
]


def sanitize_string(value, max_length=65535, allow_html=False):
    """Sanitize a string for safe storage/display.

    Args:
        value: String to sanitize.
        max_length: Maximum allowed length.
        allow_html: If False, HTML-escapes the string.

    Returns:
        Sanitized string.
    """
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    # Remove null bytes
    value = value.replace("\x00", "")
    # Truncate
    if len(value) > max_length:
        value = value[:max_length]
    if not allow_html:
        value = html.escape(value, quote=True)
    return value


def escape_sql(value):
    """Escape a string for use in SQL queries (basic).

    Note: Use parameterized queries whenever possible. This is a fallback.
    """
    if value is None:
        return "NULL"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return "'" + value.replace("'", "''").replace("\\", "\\\\") + "'"
    return "'" + str(value).replace("'", "''") + "'"


def escape_html(value):
    """HTML-escape a string."""
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def detect_sql_injection(value):
    """Check if a string contains potential SQL injection patterns.

    Returns True if suspicious patterns are found.
    """
    if not value or not isinstance(value, str):
        return False
    value_lower = value.lower()
    for pattern in SQL_DANGEROUS_PATTERNS:
        if re.search(pattern, value_lower, re.IGNORECASE):
            return True
    return False


def detect_xss(value):
    """Check if a string contains potential XSS patterns.

    Returns True if suspicious patterns are found.
    """
    if not value or not isinstance(value, str):
        return False
    xss_patterns = [
        r"<script", r"javascript:", r"onerror\s*=", r"onload\s*=",
        r"onclick\s*=", r"onmouseover\s*=", r"<iframe", r"<embed",
        r"<object", r"eval\s*\(", r"document\.cookie",
    ]
    value_lower = value.lower()
    for pattern in xss_patterns:
        if re.search(pattern, value_lower):
            return True
    return False


def sanitize_log_input(value, max_length=100000):
    """Sanitize log data input to prevent injection and oversized entries."""
    if value is None:
        return None
    if isinstance(value, str):
        # Remove control characters except newline and tab
        value = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', value)
        if len(value) > max_length:
            value = value[:max_length] + "...[truncated]"
        return value
    if isinstance(value, dict):
        return {k: sanitize_log_input(v, max_length) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize_log_input(v, max_length) for v in value]
    return value


def validate_username(username):
    """Validate a username."""
    if not username:
        return False, "Username is required"
    username = username.strip()
    if len(username) < 3:
        return False, "Username must be at least 3 characters"
    if len(username) > 64:
        return False, "Username must be at most 64 characters"
    if not re.match(r'^[a-zA-Z0-9._-]+$', username):
        return False, "Username can only contain letters, numbers, dots, hyphens, and underscores"
    return True, username.lower()


def validate_password(password):
    """Validate password strength.

    Returns (is_valid, list of issues).
    """
    issues = []
    if not password:
        return False, ["Password is required"]
    if len(password) < 8:
        issues.append("Password must be at least 8 characters")
    if len(password) > 128:
        issues.append("Password must be at most 128 characters")
    if not any(c.isupper() for c in password):
        issues.append("Password must contain at least one uppercase letter")
    if not any(c.islower() for c in password):
        issues.append("Password must contain at least one lowercase letter")
    if not any(c.isdigit() for c in password):
        issues.append("Password must contain at least one number")
    if not any(not c.isalnum() for c in password):
        issues.append("Password must contain at least one special character")
    # Common passwords
    common = {"password", "12345678", "qwerty", "abc123", "letmein",
              "welcome", "monkey", "dragon", "master"}
    if password.lower() in common:
        issues.append("Password is too common")
    return (len(issues) == 0, issues)
