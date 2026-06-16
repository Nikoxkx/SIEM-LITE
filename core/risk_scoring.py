"""
Risk scoring engine: computes risk scores for events, entities, and alerts.

The risk scoring system uses a weighted multi-factor model to compute
risk scores on a 0-100 scale. Factors include:
- Event severity
- Threat intelligence matches
- Asset criticality
- User privilege level
- Network direction (external vs internal)
- Historical behavior
- Time of day
- Action type
"""

import logging
import threading
from datetime import datetime, timezone
from collections import defaultdict

logger = logging.getLogger(__name__)


class RiskFactor:
    """A single risk scoring factor."""

    __slots__ = ("name", "weight", "description")

    def __init__(self, name, weight, description=""):
        self.name = name
        self.weight = weight
        self.description = description

    def evaluate(self, event, context=None):
        """Evaluate this factor for an event. Returns a score 0-1."""
        raise NotImplementedError


class RiskScoringEngine:
    """Computes risk scores using a weighted multi-factor model.

    Each factor contributes a score from 0-1, multiplied by its weight.
    The total score is normalized to 0-100.

    Custom factors can be added, and weights can be tuned per deployment.
    """

    # Severity to base score mapping
    SEVERITY_SCORES = {
        "emergency": 1.0, "alert": 0.95, "critical": 0.9,
        "error": 0.7, "warning": 0.5, "notice": 0.3,
        "info": 0.1, "debug": 0.05,
        "high": 0.8, "medium": 0.5, "low": 0.25,
    }

    # Action risk weights
    ACTION_RISK = {
        "logon_failed": 0.8, "delete": 0.7, "execute": 0.6,
        "deny": 0.6, "write": 0.5, "modify": 0.5,
        "create": 0.4, "logon": 0.3, "logoff": 0.1,
        "read": 0.2, "accept": 0.1, "connect": 0.3,
        "disconnect": 0.1, "start": 0.2, "stop": 0.2,
        "alert": 0.7, "process_created": 0.5,
        "user_created": 0.6, "user_deleted": 0.7,
        "policy_changed": 0.6, "log_cleared": 0.9,
        "service_installed": 0.5, "task_created": 0.5,
    }

    # Sensitive actions
    SENSITIVE_ACTIONS = {
        "log_cleared", "user_created", "user_deleted", "policy_changed",
        "password_reset", "service_installed", "logon_failed",
    }

    def __init__(self, config=None):
        self.config = config or {}
        self._lock = threading.RLock()
        self._entity_scores = defaultdict(list)  # entity -> [(timestamp, score)]
        self._max_entity_history = 1000

        # Factor weights (can be overridden via config)
        self.weights = self.config.get("weights", {
            "severity": 25,
            "threat_intel": 20,
            "asset_criticality": 15,
            "network_direction": 10,
            "action_risk": 10,
            "time_of_day": 5,
            "user_privilege": 10,
            "historical": 5,
        })

        self._custom_factors = []
        self._stats = {
            "events_scored": 0,
            "high_risk_events": 0,
            "critical_risk_events": 0,
        }

        # Track asset criticality
        self._asset_criticality = {}

    def score(self, event):
        """Compute a risk score for an event.

        Args:
            event: Event object to score.

        Returns:
            Risk score (0-100).
        """
        self._stats["events_scored"] += 1
        total_score = 0.0

        # Factor 1: Severity
        severity_score = self._score_severity(event)
        total_score += severity_score * self.weights["severity"]

        # Factor 2: Threat intelligence
        threat_score = self._score_threat_intel(event)
        total_score += threat_score * self.weights["threat_intel"]

        # Factor 3: Asset criticality
        asset_score = self._score_asset_criticality(event)
        total_score += asset_score * self.weights["asset_criticality"]

        # Factor 4: Network direction
        direction_score = self._score_network_direction(event)
        total_score += direction_score * self.weights["network_direction"]

        # Factor 5: Action risk
        action_score = self._score_action(event)
        total_score += action_score * self.weights["action_risk"]

        # Factor 6: Time of day
        time_score = self._score_time(event)
        total_score += time_score * self.weights["time_of_day"]

        # Factor 7: User privilege
        privilege_score = self._score_user_privilege(event)
        total_score += privilege_score * self.weights["user_privilege"]

        # Factor 8: Historical context
        history_score = self._score_historical(event)
        total_score += history_score * self.weights["historical"]

        # Apply custom factors
        for factor in self._custom_factors:
            try:
                factor_score = factor["func"](event)
                total_score += factor_score * factor["weight"]
            except Exception as exc:
                logger.debug("Custom risk factor error: %s", exc)

        # Normalize to 0-100
        normalized = min(100.0, max(0.0, total_score))

        # Track statistics
        if normalized >= 75:
            self._stats["critical_risk_events"] += 1
        elif normalized >= 50:
            self._stats["high_risk_events"] += 1

        # Track entity scores
        self._track_entity_score(event, normalized)

        return normalized

    def _score_severity(self, event):
        """Score based on event severity."""
        severity = event.get("severity", "info")
        return self.SEVERITY_SCORES.get(severity, 0.1)

    def _score_threat_intel(self, event):
        """Score based on threat intelligence matches."""
        if event.has_tag("threat_intel_match"):
            reputation = event.get("reputation_score", 50)
            # Lower reputation = higher risk
            return max(0, 1 - reputation / 100)

        ioc = event.get("ioc_matched")
        if ioc:
            return 0.7

        return 0.0

    def _score_asset_criticality(self, event):
        """Score based on asset criticality."""
        src_asset = event.get("source_asset")
        dst_asset = event.get("dest_asset")

        max_criticality = 0
        for asset_id in [src_asset, dst_asset]:
            if asset_id and asset_id in self._asset_criticality:
                crit = self._asset_criticality[asset_id]
                max_criticality = max(max_criticality, crit / 4.0)  # Normalize 0-4 to 0-1

        # Infer from tags
        if event.has_tag("critical_asset"):
            max_criticality = max(max_criticality, 1.0)

        return max_criticality

    def _score_network_direction(self, event):
        """Score based on network direction."""
        direction = event.get("direction", "")
        src_internal = event.get("source_is_internal", False)
        dst_internal = event.get("dest_is_internal", False)

        if not src_internal and dst_internal:
            return 0.8  # Inbound from external - higher risk
        elif src_internal and not dst_internal:
            return 0.5  # Outbound to external - moderate risk
        elif not src_internal and not dst_internal:
            return 0.6  # External to external
        else:
            return 0.2  # Internal to internal - lower risk

    def _score_action(self, event):
        """Score based on action type."""
        action = event.get("action", "")
        base_score = self.ACTION_RISK.get(action, 0.3)

        # Boost for sensitive actions
        if action in self.SENSITIVE_ACTIONS:
            base_score = min(1.0, base_score + 0.2)

        # Boost for failed critical actions
        result = event.get("result", "")
        if result == "failure" and action in ("logon", "logon_failed", "password_change_attempt"):
            base_score = min(1.0, base_score + 0.2)

        return base_score

    def _score_time(self, event):
        """Score based on time of day."""
        ts = event.get("timestamp")
        if not ts or not hasattr(ts, "hour"):
            return 0.1

        hour = ts.hour
        # Off-hours (midnight to 5 AM) is higher risk
        if 0 <= hour < 5:
            return 0.8
        elif 5 <= hour < 7 or 22 <= hour < 24:
            return 0.5
        elif ts.weekday() >= 5:  # Weekend
            return 0.4
        else:
            return 0.1

    def _score_user_privilege(self, event):
        """Score based on user privilege level."""
        user = event.get("source_user", "")
        if not user:
            return 0.2

        # Check for privileged accounts
        privileged_users = {"root", "admin", "administrator", "system", "sa",
                            "oracle", "postgres", "sys", "operator"}
        if user.lower() in privileged_users:
            return 0.9

        # Check for service accounts
        if user.endswith("$") or user.startswith("svc_") or "service" in user.lower():
            return 0.6

        # Check for admin-like names
        if any(kw in user.lower() for kw in ["admin", "root", "super", "sys"]):
            return 0.7

        return 0.3

    def _score_historical(self, event):
        """Score based on historical context."""
        # Check if event is part of an ongoing pattern
        src_ip = event.get("source_ip")
        if not src_ip:
            return 0.1

        with self._lock:
            history = self._entity_scores.get(src_ip, [])
            if len(history) < 5:
                return 0.1

            # Recent average
            recent = [s for _, s in history[-10:]]
            avg = sum(recent) / len(recent) if recent else 0

            # If recent scores are high, boost current
            if avg > 50:
                return min(1.0, avg / 100)
            elif avg > 30:
                return 0.4
            else:
                return 0.1

    def _track_entity_score(self, event, score):
        """Track entity scores for historical analysis."""
        entities = [event.get("source_ip"), event.get("dest_ip"),
                    event.get("source_user"), event.get("source_host")]
        now = datetime.now(timezone.utc)
        with self._lock:
            for entity in entities:
                if entity:
                    self._entity_scores[entity].append((now, score))
                    if len(self._entity_scores[entity]) > self._max_entity_history:
                        self._entity_scores[entity] = self._entity_scores[entity][-self._max_entity_history:]

    def add_custom_factor(self, name, func, weight=5):
        """Add a custom risk scoring factor.

        Args:
            name: Factor name.
            func: Function(event) -> score (0-1).
            weight: Factor weight.
        """
        self._custom_factors.append({"name": name, "func": func, "weight": weight})
        logger.debug("Added custom risk factor: %s (weight=%d)", name, weight)

    def set_asset_criticality(self, asset_id, criticality):
        """Set the criticality of an asset (0-4)."""
        self._asset_criticality[asset_id] = min(4, max(0, int(criticality)))

    def get_entity_risk(self, entity_id):
        """Get the risk profile for an entity."""
        with self._lock:
            history = self._entity_scores.get(entity_id, [])
        if not history:
            return {"entity": entity_id, "avg_risk": 0, "max_risk": 0, "event_count": 0}

        scores = [s for _, s in history]
        return {
            "entity": entity_id,
            "avg_risk": sum(scores) / len(scores),
            "max_risk": max(scores),
            "min_risk": min(scores),
            "event_count": len(scores),
            "recent_avg": sum(scores[-10:]) / min(10, len(scores)),
        }

    def get_stats(self):
        """Get scoring statistics."""
        return {
            **self._stats,
            "entities_tracked": len(self._entity_scores),
            "custom_factors": len(self._custom_factors),
            "weights": self.weights,
        }

    def reset_stats(self):
        """Reset statistics."""
        self._stats = {
            "events_scored": 0,
            "high_risk_events": 0,
            "critical_risk_events": 0,
        }

    def get_risk_level(self, score):
        """Get risk level label from score."""
        if score >= 80:
            return "critical"
        elif score >= 60:
            return "high"
        elif score >= 40:
            return "medium"
        elif score >= 20:
            return "low"
        else:
            return "minimal"
