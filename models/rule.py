"""
Rule model: defines detection and correlation rules.

Rules can be simple field-matching detection rules or complex temporal
correlation rules with windows, thresholds, and sequences.
"""

import re
import uuid
import json
import operator
import logging
from datetime import datetime, timezone, timedelta
from enum import Enum

logger = logging.getLogger(__name__)


class RuleType(Enum):
    """Type of rule."""
    DETECTION = "detection"        # Single-event match
    CORRELATION = "correlation"    # Multi-event correlation
    AGGREGATION = "aggregation"    # Threshold/count based
    ANOMALY = "anomaly"            # Statistical anomaly
    THREAT_INTEL = "threat_intel"  # Threat intelligence match
    COMPOSITE = "composite"        # Combination of above


class RuleStatus(Enum):
    """Rule lifecycle status."""
    DRAFT = "draft"
    ACTIVE = "active"
    DISABLED = "disabled"
    TESTING = "testing"
    DEPRECATED = "deprecated"
    ERROR = "error"


class RuleAction(Enum):
    """Action to take when a rule triggers."""
    ALERT = "alert"
    LOG = "log"
    DROP = "drop"
    TAG = "tag"
    ENRICH = "enrich"
    WEBHOOK = "webhook"
    EMAIL = "email"
    SCRIPT = "script"
    BLOCK = "block"
    ISOLATE = "isolate"


# Supported comparison operators for rule conditions
OPERATORS = {
    "eq": operator.eq,
    "ne": operator.ne,
    "gt": operator.gt,
    "gte": operator.ge,
    "lt": operator.lt,
    "lte": operator.le,
    "contains": lambda a, b: b in (a or ""),
    "not_contains": lambda a, b: b not in (a or ""),
    "startswith": lambda a, b: (a or "").startswith(b),
    "endswith": lambda a, b: (a or "").endswith(b),
    "in": lambda a, b: a in b,
    "not_in": lambda a, b: a not in b,
    "regex": lambda a, b: bool(re.search(b, str(a or ""))),
    "exists": lambda a, b: a is not None,
    "not_exists": lambda a, b: a is None,
    "is_empty": lambda a, b: not a,
    "is_not_empty": lambda a, b: bool(a),
    "between": lambda a, b: b[0] <= a <= b[1] if a is not None else False,
    "cidr": lambda a, b: _cidr_match(a, b),
    "any_in": lambda a, b: any(x in b for x in (a if isinstance(a, list) else [a])),
    "all_in": lambda a, b: all(x in b for x in (a if isinstance(a, list) else [a])),
}


def _cidr_match(ip, cidr):
    """Check if an IP is within a CIDR range."""
    try:
        import ipaddress
        net = ipaddress.ip_network(cidr, strict=False)
        addr = ipaddress.ip_address(ip)
        return addr in net
    except (ValueError, TypeError):
        return False


class RuleCondition:
    """
    A single condition in a rule. Conditions are combined with AND/OR logic.

    Example:
        condition = RuleCondition(
            field="source_ip",
            operator="not_in",
            value=internal_cidrs,
        )
    """

    __slots__ = ("field", "operator", "value", "case_sensitive")

    def __init__(self, field, operator_name, value, case_sensitive=True):
        self.field = field
        if operator_name not in OPERATORS:
            raise ValueError(f"Unknown operator: {operator_name}")
        self.operator = operator_name
        self.value = value
        self.case_sensitive = case_sensitive

    def evaluate(self, event):
        """Evaluate this condition against an event."""
        field_value = event.get(self.field)

        # Handle case-insensitive string comparison
        if not self.case_sensitive and isinstance(field_value, str) and isinstance(self.value, str):
            field_value = field_value.lower()
            value = self.value.lower()
        else:
            value = self.value

        op_func = OPERATORS[self.operator]
        try:
            return bool(op_func(field_value, value))
        except (TypeError, ValueError) as exc:
            logger.debug("Condition eval error: field=%s op=%s err=%s", self.field, self.operator, exc)
            return False

    def to_dict(self):
        return {
            "field": self.field,
            "operator": self.operator,
            "value": self.value,
            "case_sensitive": self.case_sensitive,
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            field=data["field"],
            operator_name=data["operator"],
            value=data.get("value"),
            case_sensitive=data.get("case_sensitive", True),
        )

    def __repr__(self):
        return f"Condition({self.field} {self.operator} {self.value!r})"


class RuleSchedule:
    """Schedule for when a rule should be evaluated."""

    __slots__ = ("start_time", "end_time", "days_of_week", "timezone")

    def __init__(self, start_time=None, end_time=None, days_of_week=None, timezone_str="UTC"):
        self.start_time = start_time  # "HH:MM"
        self.end_time = end_time      # "HH:MM"
        self.days_of_week = days_of_week or list(range(7))  # 0=Mon
        self.timezone = timezone_str

    def is_active_now(self, now=None):
        """Check if the rule should be active at the current time."""
        if now is None:
            now = datetime.now(timezone.utc)
        if now.weekday() not in self.days_of_week:
            return False
        if self.start_time and self.end_time:
            current_time = now.strftime("%H:%M")
            return self.start_time <= current_time <= self.end_time
        return True

    def to_dict(self):
        return {
            "start_time": self.start_time,
            "end_time": self.end_time,
            "days_of_week": self.days_of_week,
            "timezone": self.timezone,
        }


class Rule:
    """
    A detection or correlation rule.

    For detection rules: a set of conditions (AND/OR groups) evaluated against
    each incoming event.

    For correlation rules: a sequence of condition groups evaluated over a
    time window with optional thresholds.

    Attributes:
        rule_id: Unique identifier.
        name: Human-readable name.
        description: Detailed description.
        rule_type: RuleType enum.
        severity: Alert severity when triggered.
        status: Rule lifecycle status.
        conditions: List of condition groups (AND within group, OR between groups).
                   Each group is a list of RuleCondition.
        logic: How condition groups are combined: "or" (any) or "and" (all).
        actions: List of RuleAction to take when triggered.
        window: Time window for correlation (seconds).
        threshold: Minimum number of matching events to trigger.
        group_by: Fields to group events by for correlation.
        filters: Pre-filters to reduce events evaluated.
        schedule: When the rule is active.
        tags: Categorization tags.
        mitre_attack: MITRE ATT&CK technique IDs.
        enabled: Whether the rule is active.
        false_positive_rate: Estimated FP rate.
        author: Rule author.
        version: Rule version string.
        created_at: Creation timestamp.
        updated_at: Last update timestamp.
        last_fired: When the rule last triggered.
        fire_count: Total number of times triggered.
        metadata: Additional metadata.
    """

    def __init__(self, **kwargs):
        self.rule_id = kwargs.get("rule_id") or f"RL-{uuid.uuid4().hex[:8].upper()}"
        self.name = kwargs.get("name", "Unnamed Rule")
        self.description = kwargs.get("description", "")
        self.rule_type = RuleType(kwargs.get("rule_type", RuleType.DETECTION.value))
        self.severity = kwargs.get("severity", "medium")
        self.status = RuleStatus(kwargs.get("status", RuleStatus.ACTIVE.value))

        # Conditions: list of groups. Each group is a list of conditions (AND).
        # Groups are combined with OR (any group matches) or AND (all groups match).
        self.conditions = self._parse_conditions(kwargs.get("conditions", []))
        self.logic = kwargs.get("logic", "or")  # how groups combine

        # Actions
        self.actions = self._parse_actions(kwargs.get("actions", ["alert"]))

        # Correlation parameters
        self.window = kwargs.get("window", 300)  # seconds
        self.threshold = kwargs.get("threshold", 1)
        self.group_by = kwargs.get("group_by", [])  # fields to group by
        self.sequence = kwargs.get("sequence", None)  # for ordered sequences

        # Filters
        self.filters = kwargs.get("filters", {})

        # Schedule
        self.schedule = kwargs.get("schedule")
        if isinstance(self.schedule, dict):
            self.schedule = RuleSchedule(**self.schedule)

        # Metadata
        self.tags = kwargs.get("tags", [])
        self.mitre_attack = kwargs.get("mitre_attack", [])
        self.category = kwargs.get("category", "security")
        self.false_positive_rate = kwargs.get("false_positive_rate", 0.1)
        self.confidence = kwargs.get("confidence", 0.8)
        self.author = kwargs.get("author", "system")
        self.version = kwargs.get("version", "1.0")

        now = datetime.now(timezone.utc)
        self.created_at = kwargs.get("created_at", now)
        self.updated_at = kwargs.get("updated_at", now)
        self.last_fired = kwargs.get("last_fired")
        self.fire_count = kwargs.get("fire_count", 0)
        self.last_error = kwargs.get("last_error")

        self.metadata = kwargs.get("metadata", {})
        self.enabled = self.status == RuleStatus.ACTIVE

        # Compiled state for correlation rules
        self._state = {}
        self._lock_count = 0

    def _parse_conditions(self, conditions):
        """Parse conditions from dict or RuleCondition objects."""
        parsed = []
        for group in conditions:
            if isinstance(group, RuleCondition):
                parsed.append([group])
            elif isinstance(group, list):
                group_list = []
                for cond in group:
                    if isinstance(cond, RuleCondition):
                        group_list.append(cond)
                    elif isinstance(cond, dict):
                        group_list.append(RuleCondition.from_dict(cond))
                if group_list:
                    parsed.append(group_list)
            elif isinstance(group, dict):
                parsed.append([RuleCondition.from_dict(group)])
        return parsed

    def _parse_actions(self, actions):
        """Parse action list."""
        result = []
        if isinstance(actions, str):
            actions = [actions]
        for action in actions:
            if isinstance(action, RuleAction):
                result.append(action)
            elif isinstance(action, str):
                try:
                    result.append(RuleAction(action))
                except ValueError:
                    result.append(RuleAction.ALERT)
            elif isinstance(action, dict):
                result.append(action)  # action with parameters
        return result

    def add_condition_group(self, conditions):
        """Add a condition group (AND'd conditions)."""
        if isinstance(conditions, dict):
            conditions = [conditions]
        group = []
        for cond in conditions:
            if isinstance(cond, dict):
                group.append(RuleCondition.from_dict(cond))
            elif isinstance(cond, RuleCondition):
                group.append(cond)
        if group:
            self.conditions.append(group)
            self.updated_at = datetime.now(timezone.utc)

    def evaluate(self, event):
        """Evaluate the rule against a single event (for detection rules).

        Returns True if the event matches the rule conditions.
        """
        if not self.enabled or not self.conditions:
            return False

        # Check schedule
        if self.schedule and not self.schedule.is_active_now():
            return False

        return self._evaluate_conditions(event)

    def _evaluate_conditions(self, event):
        """Evaluate all condition groups against an event."""
        if self.logic == "and":
            return all(self._evaluate_group(group, event) for group in self.conditions)
        else:
            return any(self._evaluate_group(group, event) for group in self.conditions)

    def _evaluate_group(self, group, event):
        """Evaluate a condition group (all conditions must match)."""
        return all(cond.evaluate(event) for cond in group)

    def matches_filters(self, event):
        """Check if an event passes the pre-filters."""
        if not self.filters:
            return True
        for field, expected in self.filters.items():
            if event.get(field) != expected:
                return False
        return True

    def enable(self):
        """Enable the rule."""
        self.status = RuleStatus.ACTIVE
        self.enabled = True
        self.updated_at = datetime.now(timezone.utc)

    def disable(self):
        """Disable the rule."""
        self.status = RuleStatus.DISABLED
        self.enabled = False
        self.updated_at = datetime.now(timezone.utc)

    def record_fire(self, event=None):
        """Record that the rule fired."""
        self.last_fired = datetime.now(timezone.utc)
        self.fire_count += 1

    def validate(self):
        """Validate the rule configuration. Returns (is_valid, errors)."""
        errors = []
        if not self.name:
            errors.append("Rule name is required")
        if not self.conditions:
            errors.append("Rule must have at least one condition")
        if self.rule_type == RuleType.CORRELATION:
            if self.window <= 0:
                errors.append("Correlation rule window must be > 0")
            if self.threshold < 1:
                errors.append("Correlation rule threshold must be >= 1")
        if self.severity not in ("info", "low", "medium", "high", "critical"):
            errors.append(f"Invalid severity: {self.severity}")
        for i, group in enumerate(self.conditions):
            for j, cond in enumerate(group):
                if cond.operator not in OPERATORS:
                    errors.append(f"Invalid operator in group {i}, condition {j}: {cond.operator}")
        return (len(errors) == 0, errors)

    def to_dict(self):
        """Serialize rule to dictionary."""
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "rule_type": self.rule_type.value,
            "severity": self.severity,
            "status": self.status.value,
            "conditions": [[c.to_dict() for c in g] for g in self.conditions],
            "logic": self.logic,
            "actions": [a if isinstance(a, dict) else a.value for a in self.actions],
            "window": self.window,
            "threshold": self.threshold,
            "group_by": self.group_by,
            "sequence": self.sequence,
            "filters": self.filters,
            "schedule": self.schedule.to_dict() if self.schedule else None,
            "tags": self.tags,
            "mitre_attack": self.mitre_attack,
            "category": self.category,
            "false_positive_rate": self.false_positive_rate,
            "confidence": self.confidence,
            "author": self.author,
            "version": self.version,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "last_fired": self.last_fired.isoformat() if self.last_fired else None,
            "fire_count": self.fire_count,
            "last_error": self.last_error,
            "metadata": self.metadata,
            "enabled": self.enabled,
        }

    def to_json(self, indent=None):
        return json.dumps(self.to_dict(), indent=indent, default=str)

    @classmethod
    def from_dict(cls, data):
        """Create a Rule from a dictionary."""
        return cls(**data)

    def __repr__(self):
        return (f"Rule(id={self.rule_id}, name={self.name!r}, "
                f"type={self.rule_type.value}, status={self.status.value})")

    def __eq__(self, other):
        if not isinstance(other, Rule):
            return False
        return self.rule_id == other.rule_id

    def __hash__(self):
        return hash(self.rule_id)
