"""
Aggregation engine: groups and summarizes events over time intervals.

Provides time-series aggregation, statistical grouping, and rate computation
for dashboards, baselining, and alerting.
"""

import time
import logging
import threading
from datetime import datetime, timezone, timedelta
from collections import defaultdict, Counter

from ..utils.time_utils import floor_to_interval
from ..utils.helpers import compute_statistics, mean, stddev

logger = logging.getLogger(__name__)


class AggregationBucket:
    """A single aggregation bucket (time interval x group)."""

    __slots__ = ("timestamp", "group_key", "count", "fields_sum",
                 "fields_min", "fields_max", "events", "first_seen", "last_seen")

    def __init__(self, timestamp, group_key):
        self.timestamp = timestamp
        self.group_key = group_key
        self.count = 0
        self.fields_sum = defaultdict(float)
        self.fields_min = {}
        self.fields_max = {}
        self.events = []
        self.first_seen = None
        self.last_seen = None

    def add(self, event):
        """Add an event to the bucket."""
        self.count += 1
        ts = event.get("timestamp")
        if ts:
            if self.first_seen is None or ts < self.first_seen:
                self.first_seen = ts
            if self.last_seen is None or ts > self.last_seen:
                self.last_seen = ts

        # Track numeric fields
        for field in ("bytes_sent", "bytes_received", "packets_sent",
                       "packets_received", "duration", "risk_score", "status_code"):
            val = event.get(field)
            if val is not None:
                try:
                    val = float(val)
                    self.fields_sum[field] += val
                    if field not in self.fields_min or val < self.fields_min[field]:
                        self.fields_min[field] = val
                    if field not in self.fields_max or val > self.fields_max[field]:
                        self.fields_max[field] = val
                except (ValueError, TypeError):
                    pass

    def to_dict(self):
        return {
            "timestamp": self.timestamp.isoformat() if isinstance(self.timestamp, datetime) else self.timestamp,
            "group_key": self.group_key,
            "count": self.count,
            "fields_sum": dict(self.fields_sum),
            "fields_min": self.fields_min,
            "fields_max": self.fields_max,
            "first_seen": self.first_seen.isoformat() if isinstance(self.first_seen, datetime) else self.first_seen,
            "last_seen": self.last_seen.isoformat() if isinstance(self.last_seen, datetime) else self.last_seen,
        }


class AggregationEngine:
    """Aggregates events into time-series buckets.

    Maintains rolling aggregations for:
    - Event counts over time
    - Field statistics (sum, min, max, avg)
    - Grouped aggregations (by source IP, user, etc.)
    - Rate calculations (events per second/minute)
    """

    def __init__(self, config=None):
        self.config = config or {}
        self._intervals = self.config.get("intervals", [60, 300, 3600])  # 1m, 5m, 1h
        self._group_fields = self.config.get("group_fields",
                                              ["source_ip", "event_type", "severity", "action"])
        self._max_bucket_age = self.config.get("max_bucket_age", 86400)  # 24h
        self._buckets = defaultdict(dict)  # interval -> {bucket_key: AggregationBucket}
        self._lock = threading.RLock()
        self._event_count = 0

        self._stats = {
            "events_aggregated": 0,
            "buckets_created": 0,
        }

    def process(self, event):
        """Add an event to aggregation buckets."""
        self._event_count += 1
        self._stats["events_aggregated"] += 1

        with self._lock:
            ts = event.get("timestamp") or datetime.now(timezone.utc)
            if isinstance(ts, str):
                from ..utils.time_utils import parse_timestamp
                ts = parse_timestamp(ts) or datetime.now(timezone.utc)

            for interval in self._intervals:
                bucket_ts = floor_to_interval(ts, interval)
                group_key = self._get_group_key(event)
                bucket_key = (bucket_ts, group_key)

                if bucket_key not in self._buckets[interval]:
                    self._buckets[interval][bucket_key] = AggregationBucket(bucket_ts, group_key)
                    self._stats["buckets_created"] += 1

                self._buckets[interval][bucket_key].add(event)

    def _get_group_key(self, event):
        """Get the group key for an event."""
        parts = []
        for field in self._group_fields:
            val = event.get(field)
            parts.append(str(val) if val is not None else "*")
        return "|".join(parts)

    def get_timeseries(self, interval=300, duration=3600, group_filter=None):
        """Get a time series for a given interval.

        Args:
            interval: Bucket size in seconds.
            duration: Duration to look back in seconds.
            group_filter: Optional function to filter groups.

        Returns:
            List of bucket dicts sorted by timestamp.
        """
        with self._lock:
            now = datetime.now(timezone.utc)
            cutoff = now - timedelta(seconds=duration)
            buckets = self._buckets.get(interval, {})

            series = []
            for (bucket_ts, group_key), bucket in buckets.items():
                if bucket_ts < cutoff:
                    continue
                if group_filter and not group_filter(group_key):
                    continue
                series.append(bucket.to_dict())

            series.sort(key=lambda b: (b["timestamp"], b["group_key"]))
            return series

    def get_counts(self, interval=300, duration=3600, group_by=None):
        """Get aggregated event counts.

        Args:
            interval: Bucket size in seconds.
            duration: Duration to look back in seconds.
            group_by: Field to group counts by.

        Returns:
            Dict of group -> total count.
        """
        series = self.get_timeseries(interval, duration)
        counts = defaultdict(int)
        for bucket in series:
            if group_by:
                group_parts = bucket["group_key"].split("|")
                try:
                    field_idx = self._group_fields.index(group_by)
                    key = group_parts[field_idx] if field_idx < len(group_parts) else "*"
                except ValueError:
                    key = bucket["group_key"]
            else:
                key = "total"
            counts[key] += bucket["count"]
        return dict(counts)

    def get_rate(self, interval=60, duration=300):
        """Calculate event rate (events per second)."""
        series = self.get_timeseries(interval, duration)
        total = sum(b["count"] for b in series)
        num_intervals = max(1, len(series))
        return total / (num_intervals * interval)

    def get_top_values(self, field, interval=3600, duration=86400, limit=10):
        """Get top values for a field.

        Args:
            field: Field name to aggregate.
            interval: Bucket size in seconds.
            duration: Duration to look back.
            limit: Maximum number of results.

        Returns:
            List of (value, count) tuples.
        """
        # This requires iterating through stored events; in production,
        # would maintain a separate counter
        with self._lock:
            counts = Counter()
            buckets = self._buckets.get(interval, {})
            now = datetime.now(timezone.utc)
            cutoff = now - timedelta(seconds=duration)

            for (bucket_ts, group_key), bucket in buckets.items():
                if bucket_ts < cutoff:
                    continue
                # Extract the field value from the group key
                group_parts = group_key.split("|")
                try:
                    field_idx = self._group_fields.index(field)
                    val = group_parts[field_idx]
                    counts[val] += bucket.count
                except (ValueError, IndexError):
                    pass

            return counts.most_common(limit)

    def get_statistics(self, field=None, interval=3600, duration=86400):
        """Get statistical summary of aggregations."""
        series = self.get_timeseries(interval, duration)
        counts = [b["count"] for b in series]
        stats = {
            "total_events": sum(counts),
            "total_buckets": len(series),
            "avg_events_per_bucket": mean(counts) if counts else 0,
            "max_events_in_bucket": max(counts) if counts else 0,
            "min_events_in_bucket": min(counts) if counts else 0,
            "events_stddev": stddev(counts) if counts else 0,
        }
        if field:
            field_values = [b["fields_sum"].get(field, 0) for b in series]
            stats[f"{field}_total"] = sum(field_values)
            stats[f"{field}_avg"] = mean(field_values) if field_values else 0
        return stats

    def cleanup(self):
        """Remove old buckets."""
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=self._max_bucket_age)
        removed = 0
        with self._lock:
            for interval, buckets in self._buckets.items():
                to_remove = []
                for (bucket_ts, group_key) in buckets:
                    if bucket_ts < cutoff:
                        to_remove.append((bucket_ts, group_key))
                for key in to_remove:
                    del buckets[key]
                    removed += 1
        return removed

    def get_stats(self):
        """Get engine statistics."""
        with self._lock:
            total_buckets = sum(len(buckets) for buckets in self._buckets.values())
        return {
            **self._stats,
            "current_buckets": total_buckets,
            "events_seen": self._event_count,
            "intervals": self._intervals,
        }

    def reset_stats(self):
        """Reset statistics."""
        self._stats = {"events_aggregated": 0, "buckets_created": 0}

    def clear(self):
        """Clear all buckets."""
        with self._lock:
            self._buckets.clear()
            self._event_count = 0
