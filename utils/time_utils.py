"""
Time and date utility functions.

Handles parsing of various timestamp formats, formatting, duration parsing,
and time range calculations.
"""

import re
from datetime import datetime, timezone, timedelta
from collections import namedtuple


# Common timestamp formats
TIMESTAMP_FORMATS = [
    "%Y-%m-%dT%H:%M:%S.%fZ",      # ISO 8601 with ms and Z
    "%Y-%m-%dT%H:%M:%SZ",          # ISO 8601 with Z
    "%Y-%m-%dT%H:%M:%S.%f",        # ISO 8601 with ms
    "%Y-%m-%dT%H:%M:%S",           # ISO 8601
    "%Y-%m-%d %H:%M:%S.%f",        # Standard with ms
    "%Y-%m-%d %H:%M:%S",           # Standard
    "%Y-%m-%d %H:%M",              # Standard without seconds
    "%Y/%m/%d %H:%M:%S",           # Slash format
    "%Y/%m/%d %H:%M:%S.%f",        # Slash format with ms
    "%d/%b/%Y:%H:%M:%S %z",        # Apache/Nginx log format
    "%d/%b/%Y:%H:%M:%S",           # Apache/Nginx without tz
    "%d/%m/%Y %H:%M:%S",           # European format
    "%m/%d/%Y %H:%M:%S",           # US format
    "%m/%d/%Y %I:%M:%S %p",        # US format with AM/PM
    "%b %d %H:%M:%S",              # Syslog format
    "%b %d %Y %H:%M:%S",           # Extended syslog
    "%Y%m%d%H%M%S",                # Compact format
    "%Y%m%d",                      # Date only
    "%d-%b-%Y %H:%M:%S",           # Alternative
    "%a %b %d %H:%M:%S %Y",        # Ctime format
]

# Duration pattern: 1h30m, 2d, 500ms, etc.
DURATION_PATTERN = re.compile(
    r'(?:(\d+)w)?(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m(?!s))?(?:(\d+)s)?(?:(\d+)ms)?',
    re.IGNORECASE
)

TimeRange = namedtuple("TimeRange", ["start", "end"])


def utc_now():
    """Get current UTC datetime."""
    return datetime.now(timezone.utc)


def parse_timestamp(value, default_tz=timezone.utc):
    """Parse a timestamp string in various formats.

    Args:
        value: Timestamp string, datetime, or epoch number.
        default_tz: Timezone to use if none is specified in the value.

    Returns:
        Timezone-aware datetime object, or None if parsing fails.
    """
    if value is None:
        return None

    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=default_tz)
        return value

    if isinstance(value, (int, float)):
        return _epoch_to_datetime(value)

    if not isinstance(value, str):
        return None

    value = value.strip()
    if not value:
        return None

    # Try ISO format first (most common)
    try:
        # Handle Z suffix and offset
        clean = value.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=default_tz)
        return dt
    except (ValueError, TypeError):
        pass

    # Try all predefined formats
    for fmt in TIMESTAMP_FORMATS:
        try:
            dt = datetime.strptime(value, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=default_tz)
            return dt
        except (ValueError, TypeError):
            continue

    # Try epoch timestamps
    try:
        ts = float(value)
        return _epoch_to_datetime(ts)
    except (ValueError, TypeError):
        pass

    # Try relative time formats (e.g., "now", "-5m", "2 hours ago")
    relative = parse_relative_time(value)
    if relative:
        return relative

    return None


def parse_relative_time(value):
    """Parse relative time strings like '5 minutes ago', '-1h', 'now'."""
    value = value.strip().lower()
    now = utc_now()

    if value == "now":
        return now

    # "-5m", "-1h", "-2d"
    match = re.match(r'^-(\d+)([smhdw])$', value)
    if match:
        amount = int(match.group(1))
        unit = match.group(2)
        delta = _create_timedelta(amount, unit)
        return now - delta

    # "5 minutes ago", "2 hours ago", "1 day ago"
    match = re.match(r'^(\d+)\s+(second|minute|hour|day|week)s?\s+ago$', value)
    if match:
        amount = int(match.group(1))
        unit = match.group(2)[0]
        delta = _create_timedelta(amount, unit)
        return now - delta

    return None


def _create_timedelta(amount, unit):
    """Create a timedelta from an amount and unit character."""
    if unit == "s":
        return timedelta(seconds=amount)
    elif unit == "m":
        return timedelta(minutes=amount)
    elif unit == "h":
        return timedelta(hours=amount)
    elif unit == "d":
        return timedelta(days=amount)
    elif unit == "w":
        return timedelta(weeks=amount)
    return timedelta(0)


def _epoch_to_datetime(epoch):
    """Convert epoch timestamp to datetime."""
    if epoch > 1e12:  # milliseconds
        epoch = epoch / 1000.0
    elif epoch > 1e9 * 100:  # microseconds
        epoch = epoch / 1000000.0
    try:
        return datetime.fromtimestamp(epoch, tz=timezone.utc)
    except (ValueError, OSError):
        return None


def format_timestamp(dt, fmt="%Y-%m-%dT%H:%M:%S.%fZ"):
    """Format a datetime to a string."""
    if dt is None:
        return ""
    if isinstance(dt, str):
        dt = parse_timestamp(dt)
        if dt is None:
            return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    # Convert to UTC for consistent formatting
    dt_utc = dt.astimezone(timezone.utc)
    if fmt.endswith("Z"):
        return dt_utc.strftime(fmt[:-1]) + "Z"
    return dt_utc.strftime(fmt)


def to_epoch(dt, unit="seconds"):
    """Convert datetime to epoch timestamp."""
    if dt is None:
        return None
    if isinstance(dt, str):
        dt = parse_timestamp(dt)
        if dt is None:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    ts = dt.timestamp()
    if unit == "milliseconds":
        return int(ts * 1000)
    elif unit == "microseconds":
        return int(ts * 1000000)
    return int(ts)


def from_epoch(epoch, unit="seconds"):
    """Convert epoch timestamp to datetime."""
    return _epoch_to_datetime(epoch if unit == "seconds" else
                               epoch / 1000 if unit == "milliseconds" else
                               epoch / 1000000)


def time_ago(dt, granularity="auto"):
    """Return a human-readable 'time ago' string."""
    if dt is None:
        return "never"
    if isinstance(dt, str):
        dt = parse_timestamp(dt)
        if dt is None:
            return "unknown"
    now = utc_now()
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    diff = now - dt
    return format_duration(diff.total_seconds(), granularity)


def time_until(dt, granularity="auto"):
    """Return a human-readable 'time until' string."""
    if dt is None:
        return "never"
    if isinstance(dt, str):
        dt = parse_timestamp(dt)
        if dt is None:
            return "unknown"
    now = utc_now()
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    diff = dt - now
    if diff.total_seconds() < 0:
        return "past due"
    return format_duration(diff.total_seconds(), granularity)


def parse_duration(value):
    """Parse a duration string to seconds.

    Supports formats like:
        "300" -> 300 seconds
        "5m" -> 300 seconds
        "1h30m" -> 5400 seconds
        "2d" -> 172800 seconds
        "500ms" -> 0.5 seconds
        "1w2d3h4m5s" -> comprehensive
    """
    if isinstance(value, (int, float)):
        return float(value)

    if not isinstance(value, str):
        raise ValueError(f"Cannot parse duration: {value}")

    value = value.strip().lower()

    # Plain number
    try:
        return float(value)
    except ValueError:
        pass

    # Match pattern
    match = DURATION_PATTERN.match(value)
    if not match or not any(match.groups()):
        raise ValueError(f"Invalid duration format: {value}")

    weeks, days, hours, minutes, seconds, milliseconds = match.groups()

    total = 0.0
    if weeks:
        total += int(weeks) * 604800
    if days:
        total += int(days) * 86400
    if hours:
        total += int(hours) * 3600
    if minutes:
        total += int(minutes) * 60
    if seconds:
        total += int(seconds)
    if milliseconds:
        total += int(milliseconds) / 1000.0

    return total


def format_duration(seconds, granularity="auto"):
    """Format seconds into a human-readable duration string.

    Args:
        seconds: Duration in seconds.
        granularity: "auto", "coarse", or "fine".
    """
    if seconds is None or seconds < 0:
        return "unknown"

    seconds = int(seconds)
    intervals = [
        ("week", 604800),
        ("day", 86400),
        ("hour", 3600),
        ("minute", 60),
        ("second", 1),
    ]

    parts = []
    for name, count in intervals:
        value = seconds // count
        if value:
            seconds -= value * count
            if value == 1:
                parts.append(f"{value} {name}")
            else:
                parts.append(f"{value} {name}s")

    if not parts:
        return "0 seconds"

    if granularity == "coarse":
        return parts[0]
    elif granularity == "fine":
        return ", ".join(parts[:3])
    else:  # auto
        if len(parts) <= 2:
            return ", ".join(parts)
        return ", ".join(parts[:2])


def get_time_range(time_spec, end_time=None):
    """Get a TimeRange from a time specification.

    Args:
        time_spec: Can be:
            - A duration string ("1h", "24h", "7d")
            - A tuple of (start, end) strings/datetimes
            - A relative time string ("now", "-1h")
            - A dict with 'start' and 'end' keys
        end_time: Optional end time override.
    """
    now = utc_now()

    if isinstance(time_spec, (tuple, list)) and len(time_spec) == 2:
        start = parse_timestamp(time_spec[0]) or now
        end = parse_timestamp(time_spec[1]) or end_time or now
        return TimeRange(start, end)

    if isinstance(time_spec, dict):
        start = parse_timestamp(time_spec.get("start", "-1h")) or now
        end = parse_timestamp(time_spec.get("end", "now")) or end_time or now
        return TimeRange(start, end)

    if isinstance(time_spec, str):
        # Try as duration
        try:
            duration = parse_duration(time_spec)
            end = end_time or now
            start = end - timedelta(seconds=duration)
            return TimeRange(start, end)
        except ValueError:
            pass

        # Try as relative time
        ts = parse_timestamp(time_spec)
        if ts:
            end = end_time or now
            if ts > end:
                return TimeRange(end, ts)
            return TimeRange(ts, end)

    # Default: last hour
    return TimeRange(now - timedelta(hours=1), end_time or now)


def floor_to_interval(dt, interval_seconds):
    """Floor a datetime to the nearest interval boundary."""
    if dt is None:
        return None
    if isinstance(dt, str):
        dt = parse_timestamp(dt)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    epoch = dt.timestamp()
    floored = (epoch // interval_seconds) * interval_seconds
    return datetime.fromtimestamp(floored, tz=timezone.utc)
