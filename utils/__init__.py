"""
Utility modules for the SIEM-Lite engine.

Contains helper functions for:
- Time/date parsing and formatting
- IP address utilities and GeoIP
- Cryptographic operations
- Input validation
- General helpers
"""

from .time_utils import (
    parse_timestamp, format_timestamp, utc_now, to_epoch, from_epoch,
    time_ago, time_until, parse_duration, format_duration,
    get_time_range, floor_to_interval, TimeRange,
)
from .geoip import GeoIPLookup, GeoIPResult, IPClassifier
from .crypto import (
    hash_string, hash_file, encrypt_data, decrypt_data,
    generate_token, generate_uuid, encode_base64, decode_base64,
    secure_compare, HMACSigner,
)
from .validators import (
    validate_ip, validate_cidr, validate_email, validate_url,
    validate_port, validate_hostname, validate_mac_address,
    validate_hash, validate_uuid, validate_severity,
    sanitize_string, escape_sql, escape_html,
)
from .helpers import (
    deep_get, deep_set, flatten_dict, unflatten_dict,
    chunk_list, deduplicate_list, safe_int, safe_float,
    merge_dicts, truncate_string, slugify, mask_sensitive,
    compute_statistics, percentile, mean, median, stddev,
    rate_limit, retry, memoize, timed,
)

__all__ = [
    # Time utils
    "parse_timestamp", "format_timestamp", "utc_now", "to_epoch", "from_epoch",
    "time_ago", "time_until", "parse_duration", "format_duration",
    "get_time_range", "floor_to_interval", "TimeRange",
    # GeoIP
    "GeoIPLookup", "GeoIPResult", "IPClassifier",
    # Crypto
    "hash_string", "hash_file", "encrypt_data", "decrypt_data",
    "generate_token", "generate_uuid", "encode_base64", "decode_base64",
    "secure_compare", "HMACSigner",
    # Validators
    "validate_ip", "validate_cidr", "validate_email", "validate_url",
    "validate_port", "validate_hostname", "validate_mac_address",
    "validate_hash", "validate_uuid", "validate_severity",
    "sanitize_string", "escape_sql", "escape_html",
    # Helpers
    "deep_get", "deep_set", "flatten_dict", "unflatten_dict",
    "chunk_list", "deduplicate_list", "safe_int", "safe_float",
    "merge_dicts", "truncate_string", "slugify", "mask_sensitive",
    "compute_statistics", "percentile", "mean", "median", "stddev",
    "rate_limit", "retry", "memoize", "timed",
]
