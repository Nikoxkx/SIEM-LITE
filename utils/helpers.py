"""
General helper utility functions.

Provides commonly used helper functions for data manipulation,
statistics, decorators, and more.
"""

import re
import time
import math
import hashlib
import logging
import functools
from collections import OrderedDict
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


# --- Dictionary utilities ---

def deep_get(data, path, default=None, separator="."):
    """Get a nested value from a dictionary using dot notation.

    Args:
        data: Dictionary to search.
        path: Dot-separated path (e.g., "user.address.city").
        default: Default value if not found.
        separator: Path separator.

    Returns:
        Value at path or default.
    """
    if not data or not path:
        return default
    keys = path.split(separator) if isinstance(path, str) else path
    current = data
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key)
        elif isinstance(current, (list, tuple)):
            try:
                current = current[int(key)]
            except (ValueError, IndexError):
                return default
        else:
            return default
        if current is None:
            return default
    return current


def deep_set(data, path, value, separator="."):
    """Set a nested value in a dictionary using dot notation.

    Args:
        data: Dictionary to modify.
        path: Dot-separated path.
        value: Value to set.
        separator: Path separator.

    Returns:
        Modified dictionary.
    """
    keys = path.split(separator) if isinstance(path, str) else list(path)
    current = data
    for key in keys[:-1]:
        if key not in current or not isinstance(current[key], dict):
            current[key] = {}
        current = current[key]
    current[keys[-1]] = value
    return data


def flatten_dict(data, parent_key="", separator="."):
    """Flatten a nested dictionary.

    Example: {"a": {"b": 1}} -> {"a.b": 1}
    """
    items = []
    if not isinstance(data, dict):
        return {parent_key: data} if parent_key else data
    for key, value in data.items():
        new_key = f"{parent_key}{separator}{key}" if parent_key else key
        if isinstance(value, dict):
            items.extend(flatten_dict(value, new_key, separator).items())
        elif isinstance(value, list):
            for i, item in enumerate(value):
                list_key = f"{new_key}{separator}{i}"
                if isinstance(item, dict):
                    items.extend(flatten_dict(item, list_key, separator).items())
                else:
                    items.append((list_key, item))
        else:
            items.append((new_key, value))
    return dict(items)


def unflatten_dict(data, separator="."):
    """Unflatten a dictionary with dot-separated keys.

    Example: {"a.b": 1} -> {"a": {"b": 1}}
    """
    result = {}
    for key, value in data.items():
        parts = key.split(separator)
        current = result
        for part in parts[:-1]:
            if part not in current:
                current[part] = {}
            current = current[part]
        current[parts[-1]] = value
    return result


def merge_dicts(*dicts, deep=False):
    """Merge multiple dictionaries.

    Args:
        *dicts: Dictionaries to merge (later ones override earlier).
        deep: If True, merge nested dicts recursively.

    Returns:
        Merged dictionary.
    """
    result = {}
    for d in dicts:
        if not d:
            continue
        if deep:
            for key, value in d.items():
                if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                    result[key] = merge_dicts(result[key], value, deep=True)
                else:
                    result[key] = value
        else:
            result.update(d)
    return result


# --- List utilities ---

def chunk_list(items, chunk_size):
    """Split a list into chunks of the specified size."""
    if chunk_size <= 0:
        return [items]
    return [items[i:i + chunk_size] for i in range(0, len(items), chunk_size)]


def deduplicate_list(items, key=None):
    """Remove duplicates from a list, preserving order.

    Args:
        items: List to deduplicate.
        key: Optional function to extract comparison key.
    """
    seen = set()
    result = []
    for item in items:
        k = key(item) if key else item
        if k not in seen:
            seen.add(k)
            result.append(item)
    return result


def safe_int(value, default=0):
    """Safely convert to int."""
    try:
        if isinstance(value, str):
            return int(float(value)) if "." in value else int(value)
        return int(value)
    except (ValueError, TypeError):
        return default


def safe_float(value, default=0.0):
    """Safely convert to float."""
    try:
        return float(value)
    except (ValueError, TypeError):
        return default


def safe_str(value, default=""):
    """Safely convert to string."""
    if value is None:
        return default
    return str(value)


def truncate_string(s, max_length=100, suffix="..."):
    """Truncate a string to max_length with optional suffix."""
    if not s:
        return ""
    if len(s) <= max_length:
        return s
    return s[:max_length - len(suffix)] + suffix


def slugify(s, separator="-", max_length=100):
    """Convert a string to a URL-friendly slug."""
    s = re.sub(r'[^\w\s-]', '', s.lower())
    s = re.sub(r'[\s_-]+', separator, s)
    s = s.strip(separator)
    return s[:max_length]


def mask_sensitive(value, visible_start=4, visible_end=4, mask_char="*"):
    """Mask a sensitive string, showing only the first and last few characters.

    Example: mask_sensitive("password123") -> "pass******1234" -> "pass*****d123"
    """
    if not value:
        return ""
    if len(value) <= visible_start + visible_end:
        return mask_char * len(value)
    masked_len = len(value) - visible_start - visible_end
    return value[:visible_start] + (mask_char * masked_len) + value[-visible_end:]


# --- Statistics ---

def compute_statistics(values):
    """Compute basic statistics for a list of numbers.

    Returns dict with count, mean, median, stddev, min, max, percentiles.
    """
    if not values:
        return {
            "count": 0, "mean": 0, "median": 0, "stddev": 0,
            "min": 0, "max": 0, "sum": 0,
            "p25": 0, "p50": 0, "p75": 0, "p90": 0, "p95": 0, "p99": 0,
        }
    n = len(values)
    sorted_vals = sorted(values)
    return {
        "count": n,
        "mean": sum(values) / n,
        "median": median(sorted_vals),
        "stddev": stddev(values),
        "min": sorted_vals[0],
        "max": sorted_vals[-1],
        "sum": sum(values),
        "p25": percentile(sorted_vals, 25),
        "p50": percentile(sorted_vals, 50),
        "p75": percentile(sorted_vals, 75),
        "p90": percentile(sorted_vals, 90),
        "p95": percentile(sorted_vals, 95),
        "p99": percentile(sorted_vals, 99),
    }


def percentile(sorted_values, pct):
    """Compute the p-th percentile from a sorted list."""
    if not sorted_values:
        return 0.0
    if len(sorted_values) == 1:
        return float(sorted_values[0])
    k = (len(sorted_values) - 1) * (pct / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return float(sorted_values[int(k)])
    return sorted_values[f] * (c - k) + sorted_values[c] * (k - f)


def mean(values):
    """Compute the arithmetic mean."""
    if not values:
        return 0.0
    return sum(values) / len(values)


def median(values):
    """Compute the median."""
    if not values:
        return 0.0
    sorted_vals = sorted(values)
    n = len(sorted_vals)
    if n % 2 == 0:
        return (sorted_vals[n // 2 - 1] + sorted_vals[n // 2]) / 2
    return sorted_vals[n // 2]


def stddev(values, population=False):
    """Compute standard deviation.

    Args:
        values: List of numbers.
        population: If True, use population stddev; otherwise sample stddev.
    """
    if not values or len(values) < 2:
        return 0.0
    m = mean(values)
    variance = sum((x - m) ** 2 for x in values) / (len(values) if population else len(values) - 1)
    return math.sqrt(variance)


def iqr(values):
    """Compute interquartile range (Q3 - Q1)."""
    if not values:
        return 0.0
    sorted_vals = sorted(values)
    return percentile(sorted_vals, 75) - percentile(sorted_vals, 25)


def moving_average(values, window=5):
    """Compute simple moving average."""
    if not values or window <= 0:
        return []
    result = []
    for i in range(len(values)):
        start = max(0, i - window + 1)
        window_vals = values[start:i + 1]
        result.append(sum(window_vals) / len(window_vals))
    return result


def exponential_moving_average(values, alpha=0.3):
    """Compute exponential moving average."""
    if not values:
        return []
    result = [values[0]]
    for i in range(1, len(values)):
        ema = alpha * values[i] + (1 - alpha) * result[-1]
        result.append(ema)
    return result


# --- Decorators ---

def timed(func):
    """Decorator to measure function execution time."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start = time.perf_counter()
        result = func(*args, **kwargs)
        elapsed = time.perf_counter() - start
        logger.debug("%s executed in %.4f seconds", func.__name__, elapsed)
        return result
    return wrapper


def retry(max_attempts=3, delay=1.0, backoff=2.0, exceptions=(Exception,)):
    """Decorator to retry a function on failure.

    Args:
        max_attempts: Maximum number of attempts.
        delay: Initial delay between retries.
        backoff: Multiplier for delay after each failure.
        exceptions: Tuple of exception types to catch.
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            attempt = 0
            current_delay = delay
            while attempt < max_attempts:
                try:
                    return func(*args, **kwargs)
                except exceptions as exc:
                    attempt += 1
                    if attempt >= max_attempts:
                        logger.error("Function %s failed after %d attempts: %s",
                                     func.__name__, max_attempts, exc)
                        raise
                    logger.warning("Function %s attempt %d failed: %s. Retrying in %.1fs",
                                   func.__name__, attempt, exc, current_delay)
                    time.sleep(current_delay)
                    current_delay *= backoff
        return wrapper
    return decorator


def memoize(max_size=128):
    """Decorator to memoize function results with LRU eviction."""
    def decorator(func):
        cache = OrderedDict()

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Create cache key from args and kwargs
            try:
                key = hashlib.sha256(repr((args, sorted(kwargs.items()))).encode()).hexdigest()
            except TypeError:
                return func(*args, **kwargs)

            if key in cache:
                cache.move_to_end(key)
                return cache[key]

            result = func(*args, **kwargs)
            cache[key] = result
            if len(cache) > max_size:
                cache.popitem(last=False)
            return result

        wrapper.cache_clear = cache.clear
        wrapper.cache_info = lambda: {"size": len(cache), "max_size": max_size}
        return wrapper
    return decorator


class RateLimiter:
    """Token bucket rate limiter."""

    def __init__(self, rate, burst=None):
        """Initialize rate limiter.

        Args:
            rate: Tokens per second.
            burst: Maximum burst size (defaults to rate).
        """
        self.rate = rate
        self.burst = burst or rate
        self.tokens = self.burst
        self.last_refill = time.monotonic()

    def acquire(self, tokens=1):
        """Try to acquire tokens. Returns True if successful."""
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
        self.last_refill = now
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False

    def wait(self, tokens=1):
        """Wait until tokens are available, then acquire."""
        while not self.acquire(tokens):
            time.sleep(0.01)


def rate_limit(rate, burst=None):
    """Decorator for rate limiting function calls."""
    limiter = RateLimiter(rate, burst)

    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if not limiter.acquire():
                raise RuntimeError(f"Rate limit exceeded for {func.__name__}")
            return func(*args, **kwargs)
        return wrapper
    return decorator


# --- Text processing ---

def extract_ips(text):
    """Extract all IP addresses from a text string."""
    ip_pattern = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    )
    return ip_pattern.findall(text)


def extract_urls(text):
    """Extract all URLs from a text string."""
    url_pattern = re.compile(r'https?://[^\s<>"\']+')
    return url_pattern.findall(text)


def extract_domains(text):
    """Extract domain names from text."""
    domain_pattern = re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*'
        r'(?:[a-zA-Z]{2,})\b'
    )
    return domain_pattern.findall(text)


def extract_emails(text):
    """Extract email addresses from text."""
    email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
    return email_pattern.findall(text)


def extract_hashes(text):
    """Extract file hashes from text."""
    hashes = {
        "md5": re.findall(r'\b[a-fA-F0-9]{32}\b', text),
        "sha1": re.findall(r'\b[a-fA-F0-9]{40}\b', text),
        "sha256": re.findall(r'\b[a-fA-F0-9]{64}\b', text),
        "sha512": re.findall(r'\b[a-fA-F0-9]{128}\b', text),
    }
    return hashes


def levenshtein_distance(s1, s2):
    """Compute Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def string_similarity(s1, s2):
    """Compute string similarity ratio (0-1) based on Levenshtein distance."""
    if not s1 and not s2:
        return 1.0
    if not s1 or not s2:
        return 0.0
    max_len = max(len(s1), len(s2))
    distance = levenshtein_distance(s1, s2)
    return 1.0 - (distance / max_len)


def fingerprint_string(s, ngram_size=3):
    """Create a fingerprint of a string using n-grams.

    Useful for fuzzy matching of log messages.
    """
    if not s:
        return ""
    s = re.sub(r'\d+', '#', s.lower())  # Replace numbers with placeholder
    s = re.sub(r'[^\w\s]', ' ', s)  # Replace special chars with space
    words = s.split()
    if len(words) < ngram_size:
        return " ".join(words)
    ngrams = [" ".join(words[i:i + ngram_size]) for i in range(len(words) - ngram_size + 1)]
    return "|".join(sorted(set(ngrams)))


def colorize_severity(severity):
    """Return ANSI color code for a severity level."""
    colors = {
        "emergency": "\033[91m",  # bright red
        "alert": "\033[91m",
        "critical": "\033[31m",   # red
        "error": "\033[31m",
        "warning": "\033[33m",    # yellow
        "notice": "\033[36m",     # cyan
        "info": "\033[32m",       # green
        "debug": "\033[37m",      # white
    }
    reset = "\033[0m"
    color = colors.get(severity.lower(), "")
    return f"{color}{severity}{reset}"
