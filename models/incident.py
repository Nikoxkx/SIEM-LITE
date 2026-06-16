"""
Incident model: groups related alerts into security incidents for
investigation and response tracking.
"""

import uuid
import json
from datetime import datetime, timezone
from enum import Enum


class IncidentStatus(Enum):
    """Incident lifecycle status."""
    NEW = "new"
    TRIAGE = "triage"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    ERADICATED = "eradicated"
    RECOVERED = "recovered"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"
    DUPLICATE = "duplicate"


class IncidentTimelineEntry:
    """An entry in the incident timeline."""

    __slots__ = ("id", "timestamp", "author", "entry_type", "description", "metadata")

    def __init__(self, description, author="system", entry_type="note", metadata=None):
        self.id = str(uuid.uuid4())[:8]
        self.timestamp = datetime.now(timezone.utc)
        self.author = author
        self.entry_type = entry_type  # note, status_change, alert_added, evidence, etc.
        self.description = description
        self.metadata = metadata or {}

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "author": self.author,
            "type": self.entry_type,
            "description": self.description,
            "metadata": self.metadata,
        }


class Incident:
    """
    A security incident: a collection of related alerts representing a
    potential security event requiring investigation.
    """

    SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}

    def __init__(self, **kwargs):
        self.incident_id = kwargs.get("incident_id") or f"INC-{uuid.uuid4().hex[:10].upper()}"
        self.title = kwargs.get("title", "Untitled Incident")
        self.description = kwargs.get("description", "")
        self.status = IncidentStatus(kwargs.get("status", IncidentStatus.NEW.value))
        self.severity = kwargs.get("severity", "medium")

        # References
        self.alert_ids = kwargs.get("alert_ids", [])
        self.event_ids = kwargs.get("event_ids", [])
        self.related_incidents = kwargs.get("related_incidents", [])

        # People
        self.owner = kwargs.get("owner")
        self.assigned_to = kwargs.get("assigned_to")
        self.reporter = kwargs.get("reporter", "system")

        # Timing
        now = datetime.now(timezone.utc)
        self.created_at = kwargs.get("created_at", now)
        self.updated_at = kwargs.get("updated_at", now)
        self.first_event_time = kwargs.get("first_event_time")
        self.last_event_time = kwargs.get("last_event_time")
        self.due_date = kwargs.get("due_date")
        self.closed_at = kwargs.get("closed_at")
        self.sla_deadline = kwargs.get("sla_deadline")

        # Classification
        self.category = kwargs.get("category", "security")
        self.subcategory = kwargs.get("subcategory")
        self.impact = kwargs.get("impact", "unknown")  # low, medium, high, severe
        self.urgency = kwargs.get("urgency", "medium")
        self.priority = kwargs.get("priority")  # computed from impact x urgency

        # Attributes
        self.affected_assets = kwargs.get("affected_assets", [])
        self.affected_users = kwargs.get("affected_users", [])
        self.indicators = kwargs.get("indicators", [])
        self.attack_vectors = kwargs.get("attack_vectors", [])
        self.mitre_attack = kwargs.get("mitre_attack", [])
        self.tags = kwargs.get("tags", [])

        # Workflow
        self.timeline = kwargs.get("timeline", [])
        if self.timeline and isinstance(self.timeline[0], dict):
            self.timeline = [
                IncidentTimelineEntry(
                    e["description"], e.get("author", "system"),
                    e.get("type", "note"), e.get("metadata")
                )
                for e in self.timeline
            ]
        self.notes = kwargs.get("notes", [])
        self.evidence = kwargs.get("evidence", [])
        self.playbook_id = kwargs.get("playbook_id")

        # Metrics
        self.risk_score = kwargs.get("risk_score", 0.0)
        self.confidence = kwargs.get("confidence", 0.5)
        self.estimated_cost = kwargs.get("estimated_cost", 0.0)

        # Resolution
        self.resolution = kwargs.get("resolution")
        self.resolution_notes = kwargs.get("resolution_notes")
        self.lessons_learned = kwargs.get("lessons_learned", "")

        self.metadata = kwargs.get("metadata", {})

        # Add initial timeline entry if new
        if not self.timeline and self.status == IncidentStatus.NEW:
            self.add_timeline_entry(f"Incident created: {self.title}", "system", "created")

    def compute_priority(self):
        """Compute priority from impact and urgency."""
        impact_scores = {"low": 1, "medium": 2, "high": 3, "severe": 4, "unknown": 2}
        urgency_scores = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        impact_val = impact_scores.get(self.impact, 2)
        urgency_val = urgency_scores.get(self.urgency, 2)
        priority_score = impact_val * urgency_val
        if priority_score >= 12:
            self.priority = "P1"
        elif priority_score >= 8:
            self.priority = "P2"
        elif priority_score >= 4:
            self.priority = "P3"
        else:
            self.priority = "P4"
        return self.priority

    def add_timeline_entry(self, description, author="system", entry_type="note", metadata=None):
        """Add a timeline entry."""
        entry = IncidentTimelineEntry(description, author, entry_type, metadata)
        self.timeline.append(entry)
        self.updated_at = datetime.now(timezone.utc)
        return entry

    def add_alert(self, alert_id, author="system"):
        """Add an alert to the incident."""
        if alert_id not in self.alert_ids:
            self.alert_ids.append(alert_id)
            self.add_timeline_entry(f"Alert {alert_id} added to incident", author, "alert_added")
            self.updated_at = datetime.now(timezone.utc)

    def remove_alert(self, alert_id):
        """Remove an alert from the incident."""
        if alert_id in self.alert_ids:
            self.alert_ids.remove(alert_id)
            self.updated_at = datetime.now(timezone.utc)

    def add_evidence(self, evidence, author="system"):
        """Add evidence to the incident."""
        if isinstance(evidence, str):
            evidence = {"description": evidence}
        evidence.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
        evidence.setdefault("added_by", author)
        self.evidence.append(evidence)
        self.add_timeline_entry(f"Evidence added: {evidence.get('description', '')[:80]}", author, "evidence")
        self.updated_at = datetime.now(timezone.utc)

    def add_indicator(self, indicator_type, value, author="system"):
        """Add an indicator of compromise."""
        indicator = {
            "type": indicator_type,  # ip, domain, hash, url, email
            "value": value,
            "added_at": datetime.now(timezone.utc).isoformat(),
            "added_by": author,
        }
        self.indicators.append(indicator)
        self.add_timeline_entry(f"IOC added: {indicator_type}={value}", author, "indicator")
        self.updated_at = datetime.now(timezone.utc)

    def change_status(self, new_status, author="system", reason=""):
        """Change the incident status."""
        if isinstance(new_status, str):
            new_status = IncidentStatus(new_status)
        old_status = self.status
        self.status = new_status
        self.add_timeline_entry(
            f"Status changed from {old_status.value} to {new_status.value}: {reason}",
            author, "status_change"
        )
        if new_status in (IncidentStatus.CLOSED, IncidentStatus.FALSE_POSITIVE, IncidentStatus.DUPLICATE):
            self.closed_at = datetime.now(timezone.utc)
        self.updated_at = datetime.now(timezone.utc)

    def assign(self, user_id, author="system"):
        """Assign the incident to a user."""
        self.assigned_to = user_id
        self.add_timeline_entry(f"Incident assigned to {user_id}", author, "assignment")
        self.updated_at = datetime.now(timezone.utc)

    def escalate_severity(self, author="system", reason=""):
        """Escalate the incident severity."""
        severity_order = ["low", "medium", "high", "critical"]
        idx = severity_order.index(self.severity) if self.severity in severity_order else 0
        if idx < len(severity_order) - 1:
            self.severity = severity_order[idx + 1]
            self.add_timeline_entry(
                f"Severity escalated to {self.severity}: {reason}", author, "escalation"
            )
        self.updated_at = datetime.now(timezone.utc)

    def add_note(self, text, author="system"):
        """Add a note to the incident."""
        note = {
            "id": str(uuid.uuid4())[:8],
            "text": text,
            "author": author,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.notes.append(note)
        self.add_timeline_entry(f"Note added: {text[:80]}", author, "note")
        self.updated_at = datetime.now(timezone.utc)
        return note

    def resolve(self, resolution, notes="", author="system"):
        """Resolve the incident."""
        self.resolution = resolution
        self.resolution_notes = notes
        self.change_status(IncidentStatus.CLOSED, author, f"Resolution: {resolution}")
        if notes:
            self.add_note(notes, author)

    def merge(self, other, author="system"):
        """Merge another incident into this one."""
        for aid in other.alert_ids:
            if aid not in self.alert_ids:
                self.alert_ids.append(aid)
        for eid in other.event_ids:
            if eid not in self.event_ids:
                self.event_ids.append(eid)
        for entry in other.timeline:
            self.timeline.append(entry)
        for note in other.notes:
            self.notes.append(note)
        for evidence in other.evidence:
            self.evidence.append(evidence)
        for indicator in other.indicators:
            self.indicators.append(indicator)
        for asset in other.affected_assets:
            if asset not in self.affected_assets:
                self.affected_assets.append(asset)
        for technique in other.mitre_attack:
            if technique not in self.mitre_attack:
                self.mitre_attack.append(technique)
        for tag in other.tags:
            if tag not in self.tags:
                self.tags.append(tag)
        # Update severity to max
        if self.SEVERITY_ORDER.get(other.severity, 0) > self.SEVERITY_ORDER.get(self.severity, 0):
            self.severity = other.severity
        # Update risk score to max
        self.risk_score = max(self.risk_score, other.risk_score)
        # Update time bounds
        if other.first_event_time and (self.first_event_time is None or other.first_event_time < self.first_event_time):
            self.first_event_time = other.first_event_time
        if other.last_event_time and (self.last_event_time is None or other.last_event_time > self.last_event_time):
            self.last_event_time = other.last_event_time
        self.add_timeline_entry(f"Merged incident {other.incident_id}", author, "merge")
        self.updated_at = datetime.now(timezone.utc)

    @property
    def is_open(self):
        return self.status not in (IncidentStatus.CLOSED, IncidentStatus.FALSE_POSITIVE,
                                    IncidentStatus.DUPLICATE)

    @property
    def age(self):
        """Age of incident in seconds."""
        return (datetime.now(timezone.utc) - self.created_at).total_seconds()

    @property
    def alert_count(self):
        return len(self.alert_ids)

    @property
    def is_overdue(self):
        if self.due_date and self.is_open:
            return datetime.now(timezone.utc) > self.due_date
        return False

    def to_dict(self):
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "description": self.description,
            "status": self.status.value,
            "severity": self.severity,
            "priority": self.compute_priority(),
            "alert_ids": self.alert_ids,
            "event_ids": self.event_ids,
            "related_incidents": self.related_incidents,
            "owner": self.owner,
            "assigned_to": self.assigned_to,
            "reporter": self.reporter,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "first_event_time": self.first_event_time.isoformat() if self.first_event_time else None,
            "last_event_time": self.last_event_time.isoformat() if self.last_event_time else None,
            "due_date": self.due_date.isoformat() if self.due_date else None,
            "closed_at": self.closed_at.isoformat() if self.closed_at else None,
            "category": self.category,
            "subcategory": self.subcategory,
            "impact": self.impact,
            "urgency": self.urgency,
            "affected_assets": self.affected_assets,
            "affected_users": self.affected_users,
            "indicators": self.indicators,
            "attack_vectors": self.attack_vectors,
            "mitre_attack": self.mitre_attack,
            "tags": self.tags,
            "timeline": [e.to_dict() for e in self.timeline],
            "notes": self.notes,
            "evidence": self.evidence,
            "playbook_id": self.playbook_id,
            "risk_score": self.risk_score,
            "confidence": self.confidence,
            "resolution": self.resolution,
            "resolution_notes": self.resolution_notes,
            "lessons_learned": self.lessons_learned,
            "metadata": self.metadata,
            "is_open": self.is_open,
            "alert_count": self.alert_count,
            "age": self.age,
        }

    def to_json(self, indent=None):
        return json.dumps(self.to_dict(), indent=indent, default=str)

    @classmethod
    def from_dict(cls, data):
        return cls(**data)

    def __repr__(self):
        return (f"Incident(id={self.incident_id}, sev={self.severity}, "
                f"status={self.status.value}, alerts={len(self.alert_ids)})")

    def __eq__(self, other):
        if not isinstance(other, Incident):
            return False
        return self.incident_id == other.incident_id

    def __hash__(self):
        return hash(self.incident_id)
