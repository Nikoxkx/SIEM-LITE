"""
Anomaly detection engine: detects statistical anomalies in event patterns.

Implements multiple anomaly detection algorithms:
- Z-Score detection (deviation from mean)
- EWMA (Exponentially Weighted Moving Average)
- IQR (Interquartile Range) based detection
- Rate-based anomaly detection
- Rare event detection
- Behavioral baselining
"""

import math
import time
import logging
import threading
from datetime import datetime, timezone, timedelta
from collections import defaultdict, deque, Counter

from ..utils.helpers import mean, median, stddev, percentile, iqr, \
    exponential_moving_average, moving_average
from ..utils.time_utils import floor_to_interval

logger = logging.getLogger(__name__)


class Baseline:
    """A statistical baseline for a metric.

    Tracks historical values and computes statistics for anomaly detection.
    """

    def __init__(self, name, window_size=1000, warmup_period=50):
        self.name = name
        self.window_size = window_size
        self.warmup_period = warmup_period
        self._values = deque(maxlen=window_size)
        self._ewma_value = None
        self._ewma_alpha = 0.3
        self._lock = threading.Lock()
        self._count = 0
        self._last_update = None

    def update(self, value):
        """Add a new value to the baseline."""
        with self._lock:
            self._values.append(value)
            self._count += 1
            self._last_update = datetime.now(timezone.utc)

            # Update EWMA
            if self._ewma_value is None:
                self._ewma_value = value
            else:
                self._ewma_value = self._ewma_alpha * value + (1 - self._ewma_alpha) * self._ewma_value

    def is_anomalous(self, value, method="zscore", threshold=3.0):
        """Check if a value is anomalous.

        Args:
            value: The value to check.
            method: Detection method (zscore, ewma, iqr).
            threshold: Anomaly threshold.

        Returns:
            (is_anomaly, score, details) tuple.
        """
        if self._count < self.warmup_period:
            return False, 0.0, {"reason": "warming_up", "count": self._count}

        with self._lock:
            values = list(self._values)

        if method == "zscore":
            return self._check_zscore(value, values, threshold)
        elif method == "ewma":
            return self._check_ewma(value, threshold)
        elif method == "iqr":
            return self._check_iqr(value, values, threshold)
        else:
            return False, 0.0, {"reason": "unknown_method"}

    def _check_zscore(self, value, values, threshold):
        """Z-score based anomaly detection."""
        m = mean(values)
        s = stddev(values)
        if s == 0:
            return False, 0.0, {"reason": "zero_stddev", "mean": m}
        z_score = abs(value - m) / s
        is_anomaly = z_score > threshold
        return is_anomaly, z_score, {
            "method": "zscore",
            "mean": m,
            "stddev": s,
            "z_score": z_score,
            "threshold": threshold,
        }

    def _check_ewma(self, value, threshold):
        """EWMA based anomaly detection."""
        if self._ewma_value is None:
            return False, 0.0, {"reason": "no_baseline"}
        values = list(self._values)
        m = mean(values)
        s = stddev(values)
        if s == 0:
            return False, 0.0, {"reason": "zero_stddev"}
        deviation = abs(value - self._ewma_value) / s
        is_anomaly = deviation > threshold
        return is_anomaly, deviation, {
            "method": "ewma",
            "ewma": self._ewma_value,
            "mean": m,
            "stddev": s,
            "deviation": deviation,
            "threshold": threshold,
        }

    def _check_iqr(self, value, values, threshold):
        """IQR based anomaly detection."""
        sorted_vals = sorted(values)
        q1 = percentile(sorted_vals, 25)
        q3 = percentile(sorted_vals, 75)
        iqr_val = q3 - q1
        if iqr_val == 0:
            return False, 0.0, {"reason": "zero_iqr"}
        lower_bound = q1 - threshold * iqr_val
        upper_bound = q3 + threshold * iqr_val
        is_anomaly = value < lower_bound or value > upper_bound
        score = abs(value - median(values)) / iqr_val if iqr_val > 0 else 0
        return is_anomaly, score, {
            "method": "iqr",
            "q1": q1,
            "q3": q3,
            "iqr": iqr_val,
            "lower_bound": lower_bound,
            "upper_bound": upper_bound,
            "median": median(values),
            "threshold": threshold,
        }

    def get_stats(self):
        """Get baseline statistics."""
        with self._lock:
            values = list(self._values)
        if not values:
            return {"name": self.name, "count": 0}
        return {
            "name": self.name,
            "count": self._count,
            "mean": mean(values),
            "median": median(values),
            "stddev": stddev(values),
            "min": min(values),
            "max": max(values),
            "ewma": self._ewma_value,
            "p25": percentile(sorted(values), 25),
            "p75": percentile(sorted(values), 75),
            "p95": percentile(sorted(values), 95),
            "p99": percentile(sorted(values), 99),
            "last_update": self._last_update.isoformat() if self._last_update else None,
        }


class AnomalyEngine:
    """Anomaly detection engine.

    Maintains baselines for various metrics and detects anomalies in
    real-time event streams. Generates alerts when anomalies are detected.
    """

    def __init__(self, alert_handler=None, config=None):
        self.config = config or {}
        self._alert_handler = alert_handler
        self._baselines = {}  # baseline_name -> Baseline
        self._rate_trackers = {}  # key -> RateTracker
        self._rare_event_tracker = defaultdict(Counter)
        self._lock = threading.RLock()

        self._detection_method = self.config.get("method", "zscore")
        self._threshold = self.config.get("threshold", 3.0)
        self._warmup_period = self.config.get("warmup_period", 50)

        self._stats = {
            "events_processed": 0,
            "anomalies_detected": 0,
            "baselines_tracked": 0,
            "rare_events_detected": 0,
        }

        # Track event rates per entity
        self._entity_rates = defaultdict(lambda: deque(maxlen=1000))
        self._entity_last_event = {}

    def process(self, event):
        """Process an event for anomaly detection.

        Checks multiple anomaly dimensions:
        - Rate anomalies (events per entity)
        - Rare event detection
        - Field value anomalies
        """
        self._stats["events_processed"] += 1
        anomalies = []

        # Rate-based anomaly detection
        rate_anomaly = self._check_rate_anomaly(event)
        if rate_anomaly:
            anomalies.append(rate_anomaly)

        # Rare event detection
        rare_anomaly = self._check_rare_event(event)
        if rare_anomaly:
            anomalies.append(rare_anomaly)

        # Time-based anomaly
        time_anomaly = self._check_time_anomaly(event)
        if time_anomaly:
            anomalies.append(time_anomaly)

        # Behavioral anomaly (new IP, new user, etc.)
        behavior_anomaly = self._check_behavioral_anomaly(event)
        if behavior_anomaly:
            anomalies.append(behavior_anomaly)

        # Generate alerts for anomalies
        for anomaly in anomalies:
            self._stats["anomalies_detected"] += 1
            if self._alert_handler:
                try:
                    alert = self._create_anomaly_alert(event, anomaly)
                    self._alert_handler(alert, event, None)
                except Exception as exc:
                    logger.error("Anomaly alert handler error: %s", exc)

        return anomalies

    def _check_rate_anomaly(self, event):
        """Check for rate-based anomalies."""
        # Track per-source-IP event rate
        src_ip = event.get("source_ip")
        if not src_ip:
            return None

        now = datetime.now(timezone.utc)
        key = f"rate:{src_ip}"

        with self._lock:
            # Record this event
            self._entity_rates[key].append(now)
            last = self._entity_last_event.get(key)
            self._entity_last_event[key] = now

            # Compute rate (events per minute)
            rates = list(self._entity_rates[key])
            if len(rates) < self._warmup_period:
                return None

            # Count events in last minute
            one_min_ago = now - timedelta(minutes=1)
            recent_count = sum(1 for t in rates if t > one_min_ago)

            # Build/update baseline
            baseline_key = key
            if baseline_key not in self._baselines:
                self._baselines[baseline_key] = Baseline(
                    baseline_key, warmup_period=self._warmup_period // 2
                )

            baseline = self._baselines[baseline_key]
            is_anomaly, score, details = baseline.is_anomalous(
                recent_count, method="zscore", threshold=self._threshold
            )
            baseline.update(recent_count)

            if is_anomaly and recent_count > details.get("mean", 0):
                return {
                    "type": "rate_anomaly",
                    "entity": src_ip,
                    "metric": "events_per_minute",
                    "value": recent_count,
                    "score": score,
                    "details": details,
                    "description": f"High event rate from {src_ip}: {recent_count} events/min "
                                  f"(baseline mean: {details.get('mean', 0):.1f})",
                }

        return None

    def _check_rare_event(self, event):
        """Check for rare/unusual events."""
        event_type = event.get("event_type", "unknown")
        action = event.get("action", "unknown")
        source_ip = event.get("source_ip", "*")

        # Track combinations
        combo = f"{event_type}:{action}"
        key = f"rare:{source_ip}"

        with self._lock:
            self._rare_event_tracker[key][combo] += 1
            total = sum(self._rare_event_tracker[key].values())
            count = self._rare_event_tracker[key][combo]

            # If this combination is very rare (< 2% of all events) and we have enough data
            if total > 100 and count <= 2:
                frequency = count / total
                if frequency < 0.02:
                    self._stats["rare_events_detected"] += 1
                    return {
                        "type": "rare_event",
                        "entity": source_ip,
                        "event_type": event_type,
                        "action": action,
                        "count": count,
                        "total": total,
                        "frequency": frequency,
                        "description": f"Rare event from {source_ip}: {event_type}/{action} "
                                      f"(seen {count}/{total} times, {frequency*100:.2f}%)",
                    }

        return None

    def _check_time_anomaly(self, event):
        """Check for time-based anomalies."""
        ts = event.get("timestamp")
        if not ts:
            return None

        src_ip = event.get("source_ip", "*")
        hour = None

        if isinstance(ts, datetime):
            hour = ts.hour
        elif isinstance(ts, str):
            from ..utils.time_utils import parse_timestamp
            parsed = parse_timestamp(ts)
            if parsed:
                hour = parsed.hour

        if hour is None:
            return None

        # Track activity hours per entity
        key = f"hours:{src_ip}"
        with self._lock:
            if key not in self._baselines:
                self._baselines[key] = Baseline(key, warmup_period=20)

            baseline = self._baselines[key]
            is_anomaly, score, details = baseline.is_anomalous(
                hour, method="iqr", threshold=2.0
            )
            baseline.update(hour)

            if is_anomaly and (hour < 6 or hour >= 23):
                return {
                    "type": "time_anomaly",
                    "entity": src_ip,
                    "hour": hour,
                    "score": score,
                    "details": details,
                    "description": f"Off-hours activity from {src_ip} at {hour}:02 "
                                  f"(unusual time based on baseline)",
                }

        return None

    def _check_behavioral_anomaly(self, event):
        """Check for behavioral anomalies (first-seen entities)."""
        anomalies = []

        # First-time source IP for this user
        src_ip = event.get("source_ip")
        user = event.get("source_user")

        if src_ip and user:
            key = f"user_ip:{user}"
            with self._lock:
                if key not in self._baselines:
                    self._baselines[key] = Baseline(key, warmup_period=1)

                baseline = self._baselines[key]
                # Use IP hash as value to detect new IPs
                import hashlib
                ip_hash = int(hashlib.md5(src_ip.encode()).hexdigest()[:8], 16) % 1000
                is_anomaly, score, details = baseline.is_anomalous(
                    ip_hash, method="iqr", threshold=1.5
                )
                baseline.update(ip_hash)

                if is_anomaly and baseline._count < 5:
                    return {
                        "type": "behavioral_anomaly",
                        "entity": user,
                        "metric": "new_source_ip",
                        "source_ip": src_ip,
                        "description": f"User {user} logging in from new IP {src_ip}",
                    }

        return None

    def _create_anomaly_alert(self, event, anomaly):
        """Create an alert for a detected anomaly."""
        from ..models.alert import Alert

        severity = "medium"
        score = anomaly.get("score", 0)
        if score > 5:
            severity = "critical"
        elif score > 3:
            severity = "high"

        return Alert(
            title=f"Anomaly Detected: {anomaly['type'].replace('_', ' ').title()}",
            description=anomaly.get("description", "Statistical anomaly detected"),
            severity=severity,
            status="open",
            rule_id=f"anomaly_{anomaly['type']}",
            rule_name=f"Anomaly Detection - {anomaly['type']}",
            rule_type="anomaly",
            category="anomaly_detection",
            source_events=[event.event_id],
            source_event_count=1,
            risk_score=min(100, score * 15),
            confidence=min(1.0, score / 5),
            entities={"source_ip": anomaly.get("entity")},
            evidence=[{
                "type": "anomaly_details",
                **anomaly,
            }],
            recommended_actions=[
                "Investigate the anomalous activity",
                "Determine if this is legitimate or malicious",
                "Check related events from the same entity",
            ],
            false_positive_probability=0.3,
            tags=["anomaly", anomaly["type"]],
        )

    def get_baseline(self, name):
        """Get a baseline by name."""
        return self._baselines.get(name)

    def get_all_baselines(self):
        """Get all baseline statistics."""
        return {name: b.get_stats() for name, b in self._baselines.items()}

    def get_stats(self):
        """Get engine statistics."""
        return {
            **self._stats,
            "baselines_tracked": len(self._baselines),
            "method": self._detection_method,
            "threshold": self._threshold,
        }

    def reset_stats(self):
        """Reset statistics."""
        self._stats = {
            "events_processed": 0,
            "anomalies_detected": 0,
            "baselines_tracked": len(self._baselines),
            "rare_events_detected": 0,
        }
