"""
Data models for the SIEM-Lite engine.

This module defines the core data structures used throughout the system:
- Event: Normalized log event
- Alert: Generated alert from correlation/detection
- Rule: Detection or correlation rule
- User: System user with RBAC
- Incident: Grouped alerts forming an incident
- Asset: Network asset inventory entry
"""

from .event import Event, EventField, EventStatus, EventType
from .alert import (
    Alert,
    AlertStatus,
    AlertSeverity,
    AlertNote,
    AlertAcknowledgement,
)
from .rule import (
    Rule,
    RuleType,
    RuleStatus,
    RuleAction,
    RuleCondition,
    RuleSchedule,
)
from .user import User, Role, Permission, SessionToken
from .incident import Incident, IncidentStatus, IncidentTimelineEntry
from .asset import Asset, AssetType, AssetCriticality

__all__ = [
    "Event", "EventField", "EventStatus", "EventType",
    "Alert", "AlertStatus", "AlertSeverity", "AlertNote", "AlertAcknowledgement",
    "Rule", "RuleType", "RuleStatus", "RuleAction", "RuleCondition", "RuleSchedule",
    "User", "Role", "Permission", "SessionToken",
    "Incident", "IncidentStatus", "IncidentTimelineEntry",
    "Asset", "AssetType", "AssetCriticality",
]
