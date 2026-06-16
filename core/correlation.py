"""
Correlation engine: detects patterns across multiple events over time windows.

The correlation engine maintains sliding time windows for each correlation rule
and groups events by specified fields. When a threshold of matching events is
reached within the window, an alert is generated.

Supports:
- Threshold correlation (N events in T seconds)
- Sequence correlation (event A then event B)
- Temporal correlation (events within proximity)
- Group-based correlation (same source, user, etc.)
"""

import time
import logging
import threading
from datetime import datetime, timezone, timedelta
from collections import defaultdict, deque

from ..models.rule import Rule, RuleType
from ..models.alert import Alert

logger = logging.getLogger(__name__)


class CorrelationWindow:
    """A sliding time window for tracking correlated events.

    Stores events keyed by a group identifier and automatically
    expires old events.
    """

    def __init__(self, window_seconds, group_by_fields=None):
        self.window_seconds = window_seconds
        self.group_by = group_by_fields or []
        self._buckets = defaultdict(lambda: deque(maxlen=10000))
        self._lock = threading.Lock()

    def add(self, event):
        """Add an event to the window. Returns the group key."""
        group_key = self._get_group_key(event)
        now = datetime.now(timezone.utc)
        entry = {
            "event": event,
            "timestamp": event.get("timestamp") or now,
            "added_at": now,
        }
        with self._lock:
            self._buckets[group_key].append(entry)
        return group_key

    def get_events(self, group_key, since=None):
        """Get events in a group, optionally since a timestamp."""
        with self._lock:
            bucket = self._buckets.get(group_key, deque())
            if since:
                return [e["event"] for e in bucket if e["timestamp"] >= since]
            return [e["event"] for e in bucket]

    def count(self, group_key, since=None):
        """Count events in a group."""
        with self._lock:
            bucket = self._buckets.get(group_key, deque())
            if since:
                return sum(1 for e in bucket if e["timestamp"] >= since)
            return len(bucket)

    def _get_group_key(self, event):
        """Get the group key for an event."""
        if not self.group_by:
            return "_global"
        parts = []
        for field in self.group_by:
            val = event.get(field)
            parts.append(str(val) if val is not None else "*")
        return "|".join(parts)

    def cleanup(self, now=None):
        """Remove expired events from all buckets."""
        if now is None:
            now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=self.window_seconds)
        removed = 0
        with self._lock:
            empty_keys = []
            for key, bucket in self._buckets.items():
                while bucket and bucket[0]["timestamp"] < cutoff:
                    bucket.popleft()
                    removed += 1
                if not bucket:
                    empty_keys.append(key)
            for key in empty_keys:
                del self._buckets[key]
        return removed

    def get_all_keys(self):
        """Get all group keys."""
        with self._lock:
            return list(self._buckets.keys())

    def get_stats(self):
        """Get window statistics."""
        with self._lock:
            total_events = sum(len(b) for b in self._buckets.values())
            return {
                "groups": len(self._buckets),
                "total_events": total_events,
                "window_seconds": self.window_seconds,
            }

    def clear(self):
        """Clear all events."""
        with self._lock:
            self._buckets.clear()


class CorrelationEngine:
    """Multi-event correlation engine.

    Evaluates correlation rules that look for patterns across multiple
    events within time windows. Generates alerts when patterns are detected.
    """

    def __init__(self, alert_handler=None, config=None):
        self.config = config or {}
        self._alert_handler = alert_handler
        self._rules = {}  # rule_id -> Rule
        self._windows = {}  # rule_id -> CorrelationWindow
        self._fired_state = {}  # rule_id -> {group_key -> last_fired_time}
        self._lock = threading.RLock()

        self._stats = {
            "events_processed": 0,
            "correlations_detected": 0,
            "alerts_generated": 0,
            "events_in_windows": 0,
        }

        self._max_windows_memory = self.config.get("max_windows_memory", 500000)
        self._cleanup_interval = self.config.get("cleanup_interval", 60)
        self._last_cleanup = time.time()

    def add_rule(self, rule):
        """Add a correlation rule."""
        with self._lock:
            if isinstance(rule, dict):
                rule = Rule.from_dict(rule)
            if rule.rule_type not in (RuleType.CORRELATION, RuleType.AGGREGATION):
                logger.warning("Rule %s is not a correlation/aggregation rule", rule.rule_id)
            self._rules[rule.rule_id] = rule
            self._windows[rule.rule_id] = CorrelationWindow(
                rule.window, rule.group_by
            )
            self._fired_state[rule.rule_id] = {}
            logger.debug("Added correlation rule: %s (window=%ds, threshold=%d)",
                        rule.name, rule.window, rule.threshold)

    def remove_rule(self, rule_id):
        """Remove a rule."""
        with self._lock:
            self._rules.pop(rule_id, None)
            self._windows.pop(rule_id, None)
            self._fired_state.pop(rule_id, None)

    def process(self, event):
        """Process an event through all correlation rules.

        Returns list of generated alerts.
        """
        self._stats["events_processed"] += 1
        alerts = []

        # Periodic cleanup
        now = time.time()
        if now - self._last_cleanup > self._cleanup_interval:
            self._cleanup_windows()
            self._last_cleanup = now

        with self._lock:
            for rule_id, rule in list(self._rules.items()):
                if not rule.enabled:
                    continue

                # Check if event matches this rule's conditions
                if not rule.matches_filters(event):
                    continue

                # For correlation rules, check if the event matches conditions
                if rule.conditions and not rule.evaluate(event):
                    # Event doesn't match rule conditions, skip
                    # But we still might want to add it if it's part of a sequence
                    continue

                window = self._windows.get(rule_id)
                if not window:
                    continue

                # Add event to window
                group_key = window.add(event)

                # Check threshold
                count = window.count(group_key)
                if count >= rule.threshold:
                    # Check if we already fired for this group recently
                    fired_state = self._fired_state.get(rule_id, {})
                    last_fired = fired_state.get(group_key)

                    # Only fire again after window/2 has passed (rate limiting)
                    rate_limit = rule.window / 2
                    if last_fired and (datetime.now(timezone.utc) - last_fired).total_seconds() < rate_limit:
                        continue

                    # Generate alert
                    alert = self._create_correlation_alert(
                        rule, event, group_key, count, window
                    )
                    alerts.append(alert)
                    self._stats["correlations_detected"] += 1
                    self._stats["alerts_generated"] += 1

                    fired_state[group_key] = datetime.now(timezone.utc)

                    if self._alert_handler:
                        try:
                            self._alert_handler(alert, event, rule)
                        except Exception as exc:
                            logger.error("Alert handler error in correlation: %s", exc)

        return alerts

    def _create_correlation_alert(self, rule, event, group_key, count, window):
        """Create an alert for a correlation match."""
        # Get all events in the group
        group_events = window.get_events(group_key)

        # Collect unique entities
        entities = defaultdict(set)
        for evt in group_events:
            for field in ("source_ip", "dest_ip", "source_user", "dest_user",
                          "source_host", "dest_host"):
                val = evt.get(field)
                if val:
                    entities[field].add(str(val))

        # Convert sets to lists
        entities = {k: list(v) for k, v in entities.items()}

        # Collect event IDs
        event_ids = [evt.event_id for evt in group_events]

        # Determine time range
        timestamps = [evt.get("timestamp") for evt in group_events if evt.get("timestamp")]
        first_seen = min(timestamps) if timestamps else datetime.now(timezone.utc)
        last_seen = max(timestamps) if timestamps else datetime.now(timezone.utc)

        # Build evidence
        evidence = [{
            "type": "correlation_summary",
            "group_key": group_key,
            "event_count": count,
            "time_window": rule.window,
            "threshold": rule.threshold,
        }]

        # Add sample events as evidence
        for evt in group_events[-5:]:  # Last 5 events
            evidence.append({
                "type": "correlated_event",
                "event_id": evt.event_id,
                "timestamp": evt.get("timestamp"),
                "source_ip": evt.get("source_ip"),
                "action": evt.get("action"),
                "message": evt.get("message"),
            })

        severity = rule.severity
        # Escalate severity based on count
        if count >= rule.threshold * 3:
            severity = "critical"
        elif count >= rule.threshold * 2:
            severity = "high"

        alert = Alert(
            title=f"{rule.name} ({count} events)",
            description=f"Correlation rule '{rule.name}' triggered: {count} matching events "
                       f"in {rule.window}s window. Group: {group_key}",
            severity=severity,
            status="open",
            rule_id=rule.rule_id,
            rule_name=rule.name,
            rule_type="correlation",
            category=rule.category,
            source_events=event_ids,
            source_event_count=count,
            first_seen=first_seen,
            last_seen=last_seen,
            risk_score=min(100, count * rule.confidence * 10),
            confidence=rule.confidence,
            entities=entities,
            evidence=evidence,
            recommended_actions=self._get_correlation_actions(rule, event, count),
            false_positive_probability=rule.false_positive_rate,
            mitre_attack=rule.mitre_attack,
            tags=rule.tags + ["correlation"],
            metadata={
                "group_key": group_key,
                "threshold": rule.threshold,
                "window": rule.window,
            },
        )

        return alert

    def _get_correlation_actions(self, rule, event, count):
        """Generate recommended actions for correlation alerts."""
        actions = []
        category = rule.category.lower()
        name_lower = rule.name.lower()

        if "brute" in name_lower:
            actions.append(f"High volume of authentication events ({count}) detected")
            actions.append("Check if this is legitimate user activity or brute force attack")
            actions.append("Consider temporarily blocking the source IP")
            actions.append("Review affected user accounts for compromise")

        elif "scan" in name_lower or "port" in name_lower:
            actions.append(f"Port/network scanning detected ({count} connections)")
            actions.append("Verify if source is an authorized scanner")
            actions.append("Block source IP if unauthorized")

        elif "malware" in category:
            actions.append(f"Multiple malware-related events ({count}) detected")
            actions.append("Isolate affected systems immediately")
            actions.append("Investigate scope of potential infection")

        elif "data" in category and "exfil" in name_lower:
            actions.append(f"Potential data exfiltration pattern ({count} events)")
            actions.append("Review data transfer details")
            actions.append("Check for unauthorized data movement")

        if not actions:
            actions.append(f"Investigate correlated activity ({count} events matching '{rule.name}')")
            actions.append("Review the grouped events for patterns")

        return actions

    def _cleanup_windows(self):
        """Clean up expired events from all windows."""
        total_removed = 0
        with self._lock:
            for window in self._windows.values():
                total_removed += window.cleanup()
        if total_removed > 0:
            logger.debug("Correlation cleanup: removed %d expired events", total_removed)

    def get_window_stats(self, rule_id=None):
        """Get statistics for correlation windows."""
        if rule_id:
            window = self._windows.get(rule_id)
            return window.get_stats() if window else None
        return {rid: w.get_stats() for rid, w in self._windows.items()}

    def get_stats(self):
        """Get engine statistics."""
        total_in_windows = 0
        for window in self._windows.values():
            stats = window.get_stats()
            total_in_windows += stats["total_events"]
        self._stats["events_in_windows"] = total_in_windows
        return {
            **self._stats,
            "active_rules": sum(1 for r in self._rules.values() if r.enabled),
            "total_rules": len(self._rules),
        }

    def reset_stats(self):
        """Reset statistics."""
        self._stats = {
            "events_processed": 0,
            "correlations_detected": 0,
            "alerts_generated": 0,
            "events_in_windows": 0,
        }

    def get_active_correlations(self):
        """Get currently active correlation groups."""
        result = {}
        with self._lock:
            for rule_id, window in self._windows.items():
                rule = self._rules.get(rule_id)
                if not rule:
                    continue
                active_groups = []
                for key in window.get_all_keys():
                    count = window.count(key)
                    if count > 0:
                        active_groups.append({
                            "group_key": key,
                            "event_count": count,
                            "threshold": rule.threshold,
                            "percentage": (count / rule.threshold * 100) if rule.threshold else 0,
                        })
                result[rule_id] = {
                    "rule_name": rule.name,
                    "active_groups": active_groups,
                }
        return result
