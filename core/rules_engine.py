"""
Rules engine: evaluates detection rules against incoming events.

For each incoming event, the rules engine checks all active detection rules
and fires those whose conditions match. Supports rule scheduling,
suppression windows, and output actions.
"""

import time
import logging
import threading
from datetime import datetime, timezone, timedelta
from collections import defaultdict, deque

from ..models.rule import Rule, RuleType, RuleStatus, RuleAction, OPERATORS
from ..models.alert import Alert, AlertSeverity

logger = logging.getLogger(__name__)


class SuppressionWindow:
    """Manages rule suppression to prevent alert flooding.

    When a rule fires, it can be suppressed for a configurable duration
    to avoid duplicate alerts.
    """

    def __init__(self):
        self._suppressed = {}  # rule_key -> expiry_time
        self._lock = threading.Lock()

    def is_suppressed(self, rule_id, key=None):
        """Check if a rule is suppressed.

        Args:
            rule_id: The rule ID.
            key: Optional deduplication key (e.g., source_ip).
        """
        suppress_key = f"{rule_id}:{key}" if key else rule_id
        with self._lock:
            if suppress_key in self._suppressed:
                if datetime.now(timezone.utc) < self._suppressed[suppress_key]:
                    return True
                else:
                    del self._suppressed[suppress_key]
            return False

    def suppress(self, rule_id, duration=300, key=None):
        """Suppress a rule for a duration.

        Args:
            rule_id: The rule ID.
            duration: Suppression duration in seconds.
            key: Optional deduplication key.
        """
        suppress_key = f"{rule_id}:{key}" if key else rule_id
        with self._lock:
            self._suppressed[suppress_key] = datetime.now(timezone.utc) + timedelta(seconds=duration)

    def clear(self):
        """Clear all suppressions."""
        with self._lock:
            self._suppressed.clear()

    def cleanup(self):
        """Remove expired suppressions."""
        now = datetime.now(timezone.utc)
        with self._lock:
            expired = [k for k, v in self._suppressed.items() if v < now]
            for k in expired:
                del self._suppressed[k]
            return len(expired)


class RulesEngine:
    """Evaluates detection rules against events.

    The rules engine:
    1. Maintains a set of active detection rules
    2. Evaluates each event against all rules
    3. Fires matching rules, creating alerts
    4. Manages suppression windows
    5. Tracks rule performance statistics
    """

    def __init__(self, alert_handler=None, config=None):
        self.config = config or {}
        self._rules = {}  # rule_id -> Rule
        self._rules_by_type = defaultdict(list)  # RuleType -> [Rule]
        self._alert_handler = alert_handler
        self._suppression = SuppressionWindow()
        self._lock = threading.RLock()

        # Statistics
        self._stats = {
            "events_evaluated": 0,
            "rules_fired": 0,
            "alerts_generated": 0,
            "evaluations_performed": 0,
        }

        # Rule performance tracking
        self._rule_stats = defaultdict(lambda: {
            "fires": 0, "evaluations": 0, "last_fired": None,
            "avg_eval_time": 0.0,
        })

        self._max_eval_time = self.config.get("max_rule_eval_time", 0.001)
        self._last_cleanup = time.time()

    def add_rule(self, rule):
        """Add a rule to the engine."""
        with self._lock:
            if isinstance(rule, dict):
                rule = Rule.from_dict(rule)
            elif isinstance(rule, str):
                import json
                rule = Rule.from_dict(json.loads(rule))

            self._rules[rule.rule_id] = rule
            self._rules_by_type[rule.rule_type].append(rule)
            logger.debug("Added rule: %s (%s)", rule.name, rule.rule_id)

    def remove_rule(self, rule_id):
        """Remove a rule."""
        with self._lock:
            rule = self._rules.pop(rule_id, None)
            if rule:
                type_list = self._rules_by_type.get(rule.rule_type, [])
                if rule in type_list:
                    type_list.remove(rule)
                logger.debug("Removed rule: %s", rule_id)
            return rule is not None

    def enable_rule(self, rule_id):
        """Enable a rule."""
        rule = self._rules.get(rule_id)
        if rule:
            rule.enable()
            return True
        return False

    def disable_rule(self, rule_id):
        """Disable a rule."""
        rule = self._rules.get(rule_id)
        if rule:
            rule.disable()
            return True
        return False

    def get_rule(self, rule_id):
        """Get a rule by ID."""
        return self._rules.get(rule_id)

    def get_all_rules(self):
        """Get all rules."""
        return list(self._rules.values())

    def get_rules_by_type(self, rule_type):
        """Get rules by type."""
        if isinstance(rule_type, str):
            rule_type = RuleType(rule_type)
        return list(self._rules_by_type.get(rule_type, []))

    def evaluate(self, event):
        """Evaluate an event against all detection rules.

        Returns list of fired rules (Rule objects).
        """
        self._stats["events_evaluated"] += 1
        fired_rules = []

        # Periodic cleanup
        now = time.time()
        if now - self._last_cleanup > 60:
            self._suppression.cleanup()
            self._last_cleanup = now

        detection_rules = self._rules_by_type.get(RuleType.DETECTION, [])
        threat_intel_rules = self._rules_by_type.get(RuleType.THREAT_INTEL, [])

        for rule in detection_rules + threat_intel_rules:
            if not rule.enabled:
                continue

            # Check pre-filters
            if not rule.matches_filters(event):
                continue

            rule_stat = self._rule_stats[rule.rule_id]
            rule_stat["evaluations"] += 1
            self._stats["evaluations_performed"] += 1

            start_time = time.perf_counter()

            try:
                matched = rule.evaluate(event)
            except Exception as exc:
                logger.error("Error evaluating rule %s: %s", rule.rule_id, exc)
                matched = False

            eval_time = time.perf_counter() - start_time
            rule_stat["avg_eval_time"] = (
                rule_stat["avg_eval_time"] * 0.9 + eval_time * 0.1
            )

            if matched:
                # Check suppression
                suppress_key = self._get_suppress_key(rule, event)
                if self._suppression.is_suppressed(rule.rule_id, suppress_key):
                    continue

                fired_rules.append(rule)
                self._stats["rules_fired"] += 1
                rule_stat["fires"] += 1
                rule_stat["last_fired"] = datetime.now(timezone.utc)
                rule.record_fire(event)

                # Apply suppression
                suppress_duration = rule.metadata.get("suppress_duration", 0)
                if suppress_duration > 0:
                    self._suppression.suppress(rule.rule_id, suppress_duration, suppress_key)

                # Create and dispatch alert
                alert = self._create_alert(rule, event)
                self._stats["alerts_generated"] += 1

                if self._alert_handler:
                    try:
                        self._alert_handler(alert, event, rule)
                    except Exception as exc:
                        logger.error("Alert handler error: %s", exc)

        return fired_rules

    def _get_suppress_key(self, rule, event):
        """Get a suppression key based on rule's group_by fields."""
        if not rule.group_by:
            return None
        key_parts = []
        for field in rule.group_by:
            val = event.get(field)
            if val:
                key_parts.append(str(val))
        return ":".join(key_parts) if key_parts else None

    def _create_alert(self, rule, event):
        """Create an alert from a fired rule and event."""
        # Build entities for the alert
        entities = {}
        for field in ("source_ip", "dest_ip", "source_user", "dest_user",
                       "source_host", "dest_host"):
            val = event.get(field)
            if val:
                entities[field] = val

        # Build evidence
        evidence = [{
            "type": "triggering_event",
            "event_id": event.event_id,
            "timestamp": event.get("timestamp"),
            "message": event.get("message"),
            "raw_data": (event.get("raw_data") or "")[:500],
        }]

        alert = Alert(
            title=rule.name,
            description=rule.description or f"Rule {rule.name} triggered",
            severity=rule.severity,
            status="open",
            rule_id=rule.rule_id,
            rule_name=rule.name,
            rule_type=rule.rule_type.value,
            category=rule.category,
            source_events=[event.event_id],
            source_event_count=1,
            first_seen=event.get("timestamp") or datetime.now(timezone.utc),
            last_seen=event.get("timestamp") or datetime.now(timezone.utc),
            risk_score=event.get("risk_score", rule.confidence * 50),
            confidence=rule.confidence,
            entities=entities,
            evidence=evidence,
            recommended_actions=self._get_recommended_actions(rule, event),
            false_positive_probability=rule.false_positive_rate,
            mitre_attack=rule.mitre_attack,
            tags=rule.tags,
            metadata={
                "rule_type": rule.rule_type.value,
                "rule_version": rule.version,
                "rule_author": rule.author,
            },
        )

        return alert

    def _get_recommended_actions(self, rule, event):
        """Generate recommended actions for an alert."""
        actions = []
        category = rule.category.lower()
        event_type = (event.get("event_type") or "").lower()

        if "brute" in rule.name.lower() or event_type == "authentication":
            actions.append("Verify if the authentication attempts are legitimate")
            actions.append("Check user account for compromise indicators")
            actions.append("Consider blocking the source IP if malicious")

        if event.get("ioc_matched"):
            actions.append(f"Investigate IOC match: {event.get('ioc_matched')}")
            actions.append("Check for lateral movement from affected systems")

        if event.get("source_country") and not event.get("source_is_internal"):
            actions.append(f"Verify if connection from {event.get('source_country')} is expected")

        if "malware" in category or "virus" in category:
            actions.append("Isolate affected system immediately")
            actions.append("Run full malware scan")
            actions.append("Check for data exfiltration")

        if not actions:
            actions.append("Review the triggering event details")
            actions.append("Determine if this is a false positive")

        return actions

    def test_rule(self, rule, events):
        """Test a rule against a set of events.

        Returns list of events that would trigger the rule.
        """
        if isinstance(rule, dict):
            rule = Rule.from_dict(rule)
        matches = []
        for event in events:
            if rule.matches_filters(event) and rule.evaluate(event):
                matches.append(event)
        return matches

    def get_rule_stats(self, rule_id=None):
        """Get rule evaluation statistics."""
        if rule_id:
            return dict(self._rule_stats.get(rule_id, {}))
        return {rid: dict(stats) for rid, stats in self._rule_stats.items()}

    def get_stats(self):
        """Get engine statistics."""
        return {
            **self._stats,
            "active_rules": sum(1 for r in self._rules.values() if r.enabled),
            "total_rules": len(self._rules),
            "rules_by_type": {
                t.value: len(self._rules_by_type.get(t, []))
                for t in RuleType
            },
        }

    def reset_stats(self):
        """Reset statistics."""
        self._stats = {
            "events_evaluated": 0,
            "rules_fired": 0,
            "alerts_generated": 0,
            "evaluations_performed": 0,
        }
        self._rule_stats.clear()

    def load_rules_from_list(self, rules_data):
        """Load rules from a list of dicts."""
        loaded = 0
        for rule_data in rules_data:
            try:
                self.add_rule(rule_data)
                loaded += 1
            except Exception as exc:
                logger.error("Failed to load rule: %s", exc)
        logger.info("Loaded %d rules", loaded)
        return loaded

    def load_rules_from_yaml(self, yaml_path):
        """Load rules from a YAML file."""
        try:
            import yaml
            with open(yaml_path, "r") as f:
                data = yaml.safe_load(f)
            if isinstance(data, dict) and "rules" in data:
                return self.load_rules_from_list(data["rules"])
            elif isinstance(data, list):
                return self.load_rules_from_list(data)
        except (FileNotFoundError, yaml.YAMLError) as exc:
            logger.error("Failed to load rules from %s: %s", yaml_path, exc)
        return 0
