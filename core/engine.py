"""
Main SIEM engine: integrates all components into a unified system.

The SIEMEngine is the central orchestrator that:
- Manages collectors, parsers, and the processing pipeline
- Coordinates detection, correlation, and alerting
- Provides unified API for queries and administration
- Manages system lifecycle (start, stop, health)
"""

import os
import time
import json
import logging
import threading
from datetime import datetime, timezone, timedelta
from collections import defaultdict

from .. import BASE_DIR, RULES_DIR
from ..models.event import Event, EventStatus
from ..models.rule import Rule, RuleType
from ..models.alert import Alert
from ..models.user import User, Role
from ..models.asset import Asset

from .normalizer import Normalizer
from .enrichment import EnrichmentEngine
from .threat_intel import ThreatIntelEngine
from .storage import InMemoryBackend, SQLiteBackend
from .rules_engine import RulesEngine
from .correlation import CorrelationEngine
from .aggregation import AggregationEngine
from .anomaly import AnomalyEngine
from .risk_scoring import RiskScoringEngine
from .alerting import AlertingEngine
from .query import QueryEngine, Query
from .pipeline import ProcessingPipeline

from ..parsers.base import ParserRegistry
from ..collectors.base import CollectorRegistry

logger = logging.getLogger(__name__)


class SIEMEngine:
    """Central SIEM engine orchestrating all components.

    This is the main entry point for the SIEM system. It initializes
    all sub-engines, connects them via the processing pipeline, and
    provides a unified interface for event ingestion, querying, and
    administration.

    Example:
        engine = SIEMEngine()
        engine.start()
        engine.ingest("<34>Oct 11 22:14:15 host sshd: Failed password for user")
        results = engine.search("source_ip:192.168.1.1")
    """

    def __init__(self, config=None):
        """Initialize the SIEM engine.

        Args:
            config: Configuration dictionary. See config/siem.yaml for options.
        """
        self.config = config or {}
        self._lock = threading.RLock()
        self._running = False
        self._start_time = None
        self._maintenance_thread = None

        # Initialize components
        self._init_storage()
        self._init_core_engines()
        self._init_parsers()
        self._init_pipeline()
        self._init_collectors()
        self._init_query_engine()
        self._init_default_rules()
        self._init_default_user()
        self._init_audit_log()

        logger.info("SIEM Engine initialized")

    def _init_storage(self):
        """Initialize storage backend."""
        storage_type = self.config.get("storage", {}).get("type", "memory")
        storage_config = self.config.get("storage", {})

        if storage_type == "sqlite":
            db_path = storage_config.get("path", os.path.join(BASE_DIR, "siem.db"))
            self.storage = SQLiteBackend(db_path, storage_config)
        else:
            self.storage = InMemoryBackend(storage_config)

        logger.info("Storage backend: %s", storage_type)

    def _init_core_engines(self):
        """Initialize core processing engines."""
        # Normalizer
        self.normalizer = Normalizer(
            config=self.config.get("normalizer", {})
        )

        # Enrichment
        self.enrichment = EnrichmentEngine(
            config=self.config.get("enrichment", {})
        )

        # Threat intelligence
        self.threat_intel = ThreatIntelEngine(
            config=self.config.get("threat_intel", {})
        )

        # Risk scoring
        self.risk_scorer = RiskScoringEngine(
            config=self.config.get("risk_scoring", {})
        )

        # Aggregation
        self.aggregation = AggregationEngine(
            config=self.config.get("aggregation", {})
        )

        # Alerting engine (will be connected after storage)
        self.alerting = AlertingEngine(
            storage=self.storage,
            config=self.config.get("alerting", {})
        )

        # Rules engine
        self.rules_engine = RulesEngine(
            alert_handler=self.alerting.handle_alert,
            config=self.config.get("rules", {})
        )

        # Correlation engine
        self.correlation_engine = CorrelationEngine(
            alert_handler=self.alerting.handle_alert,
            config=self.config.get("correlation", {})
        )

        # Anomaly engine
        self.anomaly_engine = AnomalyEngine(
            alert_handler=self.alerting.handle_alert,
            config=self.config.get("anomaly", {})
        )

    def _init_parsers(self):
        """Initialize parser registry."""
        from ..parsers.json_parser import JSONParser, KeyValueParser
        from ..parsers.cef_parser import CEFParser
        from ..parsers.leef_parser import LEEFParser
        from ..parsers.syslog_parser import SyslogParser, RFC3164Parser, RFC5424Parser
        from ..parsers.apache_parser import ApacheAccessParser, NginxAccessParser, ApacheErrorParser

        self.parser_registry = ParserRegistry()
        self.parser_registry.register(JSONParser())
        self.parser_registry.register(CEFParser())
        self.parser_registry.register(LEEFParser())
        self.parser_registry.register(RFC5424Parser())
        self.parser_registry.register(RFC3164Parser())
        self.parser_registry.register(SyslogParser())
        self.parser_registry.register(ApacheAccessParser())
        self.parser_registry.register(NginxAccessParser())
        self.parser_registry.register(ApacheErrorParser())
        self.parser_registry.register(KeyValueParser())

    def _init_pipeline(self):
        """Initialize the processing pipeline."""
        self.pipeline = ProcessingPipeline(
            parser_registry=self.parser_registry,
            normalizer=self.normalizer,
            enrichment_engine=self.enrichment,
            threat_intel=self.threat_intel,
            rules_engine=self.rules_engine,
            correlation_engine=self.correlation_engine,
            anomaly_engine=self.anomaly_engine,
            risk_scorer=self.risk_scorer,
            storage=self.storage,
            aggregation_engine=self.aggregation,
            config=self.config.get("pipeline", {}),
        )

    def _init_collectors(self):
        """Initialize collector registry."""
        self.collector_registry = CollectorRegistry()

    def _init_query_engine(self):
        """Initialize query engine."""
        self.query_engine = QueryEngine(
            storage=self.storage,
            config=self.config.get("query", {})
        )

    def _init_default_rules(self):
        """Load default detection and correlation rules."""
        # Load from YAML if available
        rules_dir = os.path.join(BASE_DIR, "config", "rules")
        if os.path.isdir(rules_dir):
            for filename in os.listdir(rules_dir):
                if filename.endswith((".yaml", ".yml")):
                    filepath = os.path.join(rules_dir, filename)
                    self._load_rules_file(filepath)

        logger.info("Loaded %d rules", len(self.rules_engine.get_all_rules()))

    def _load_rules_file(self, filepath):
        """Load rules from a YAML file."""
        try:
            import yaml
            with open(filepath, "r") as f:
                data = yaml.safe_load(f)
            if not data:
                return

            rules_list = data.get("rules", data) if isinstance(data, dict) else data
            for rule_data in rules_list:
                try:
                    rule = Rule.from_dict(rule_data)
                    if rule.rule_type in (RuleType.DETECTION, RuleType.THREAT_INTEL):
                        self.rules_engine.add_rule(rule)
                    elif rule.rule_type in (RuleType.CORRELATION, RuleType.AGGREGATION):
                        self.correlation_engine.add_rule(rule)
                except Exception as exc:
                    logger.error("Failed to load rule from %s: %s", filepath, exc)
        except Exception as exc:
            logger.error("Failed to load rules file %s: %s", filepath, exc)

    def _init_default_user(self):
        """Initialize default users. Loads from persistent user store if available."""
        self.users = {}
        self._users_file = os.path.join(BASE_DIR, "config", "users.json")
        loaded = self._load_users()
        if not loaded:
            # First run — create default accounts that MUST be changed
            admin = User.create(
                username="admin",
                password="admin123",
                email="admin@siem.local",
                roles=["admin"],
                full_name="System Administrator",
            )
            admin.must_change_password = True
            self.users[admin.username] = admin

            analyst = User.create(
                username="analyst",
                password="analyst123",
                email="analyst@siem.local",
                roles=["analyst"],
                full_name="Security Analyst",
            )
            analyst.must_change_password = True
            self.users[analyst.username] = analyst
            self._save_users()
            logger.info("Created default users (password change required on first login)")

    def _load_users(self):
        """Load users from persistent JSON store."""
        if not os.path.exists(self._users_file):
            return False
        try:
            with open(self._users_file, "r") as f:
                users_data = json.load(f)
            for username, udata in users_data.items():
                self.users[username] = User.from_dict(udata)
            logger.info("Loaded %d users from %s", len(self.users), self._users_file)
            return len(self.users) > 0
        except Exception as exc:
            logger.error("Failed to load users: %s", exc)
            return False

    def _save_users(self):
        """Persist users to JSON store."""
        try:
            users_data = {}
            for username, user in self.users.items():
                users_data[username] = user.to_dict(include_sensitive=True)
            os.makedirs(os.path.dirname(self._users_file), exist_ok=True)
            with open(self._users_file, "w") as f:
                json.dump(users_data, f, indent=2, default=str)
        except Exception as exc:
            logger.error("Failed to save users: %s", exc)

    def _init_audit_log(self):
        """Initialize audit logging."""
        self._audit_log = []
        self._max_audit_log = 10000

    # --- Lifecycle management ---

    def start(self):
        """Start the SIEM engine and all collectors."""
        with self._lock:
            if self._running:
                logger.warning("SIEM engine already running")
                return

            self._running = True
            self._start_time = datetime.now(timezone.utc)

            # Start collectors
            self.collector_registry.start_all()

            # Start maintenance thread
            self._maintenance_thread = threading.Thread(
                target=self._maintenance_loop, daemon=True
            )
            self._maintenance_thread.start()

            self._audit("system", "start", "SIEM engine started")
            logger.info("SIEM engine started")

    def stop(self):
        """Stop the SIEM engine."""
        with self._lock:
            if not self._running:
                return

            self._running = False

            # Stop collectors
            self.collector_registry.stop_all()

            # Flush pipeline
            if self.pipeline:
                self.pipeline.flush()

            self._audit("system", "stop", "SIEM engine stopped")
            logger.info("SIEM engine stopped")

    def _maintenance_loop(self):
        """Background maintenance tasks."""
        while self._running:
            try:
                # Cleanup old events
                retention_days = self.config.get("retention_days", 30)
                if retention_days > 0:
                    removed = self.storage.delete_old_events(retention_days)
                    if removed > 0:
                        logger.debug("Cleaned up %d old events", removed)

                # Cleanup correlation windows
                if self.correlation_engine:
                    self.correlation_engine._cleanup_windows()

                # Cleanup aggregation buckets
                if self.aggregation:
                    self.aggregation.cleanup()

                # Check alert escalations
                if self.alerting:
                    escalated = self.alerting.check_escalations()
                    if escalated > 0:
                        logger.info("Auto-escalated %d alerts", escalated)

                # Suppresssion cleanup
                if self.rules_engine:
                    self.rules_engine._suppression.cleanup()

            except Exception as exc:
                logger.error("Maintenance error: %s", exc)

            time.sleep(60)

    # --- Event ingestion ---

    def ingest(self, raw_data, metadata=None):
        """Ingest raw log data.

        Args:
            raw_data: Raw log string or bytes.
            metadata: Optional metadata dict.

        Returns:
            Processed Event or None.
        """
        return self.pipeline.ingest(raw_data, metadata)

    def ingest_event(self, event):
        """Ingest a pre-constructed Event."""
        return self.pipeline.ingest_event(event)

    def ingest_batch(self, items):
        """Ingest a batch of items."""
        return self.pipeline.ingest_batch(items)

    # --- Querying ---

    def search(self, query, **kwargs):
        """Search events.

        Args:
            query: Query string, Query object, or dict.
            **kwargs: Additional query parameters.

        Returns:
            Search results dict.
        """
        if isinstance(query, str):
            q = Query.parse(query)
        elif isinstance(query, dict):
            q = Query.from_dict(query)
        else:
            q = query

        for key, value in kwargs.items():
            if key == "limit":
                q.limit(value)
            elif key == "offset":
                q.offset(value)
            elif key == "sort":
                q.sort(value)
            elif key == "time_range":
                q.time_range(value)

        return self.query_engine.search(q)

    def get_event(self, event_id):
        """Get a single event by ID."""
        return self.storage.get_event(event_id)

    def get_alert(self, alert_id):
        """Get an alert by ID."""
        return self.storage.get_alert(alert_id)

    def get_alerts(self, status=None, severity=None, limit=100, offset=0):
        """Query alerts."""
        query = {}
        if status:
            query["status"] = status
        if severity:
            query["severity"] = severity
        return self.storage.query_alerts(query, limit=limit, offset=offset)

    # --- Rule management ---

    def add_rule(self, rule_data):
        """Add a detection or correlation rule."""
        rule = Rule.from_dict(rule_data) if isinstance(rule_data, dict) else rule_data
        if rule.rule_type in (RuleType.DETECTION, RuleType.THREAT_INTEL):
            self.rules_engine.add_rule(rule)
        elif rule.rule_type in (RuleType.CORRELATION, RuleType.AGGREGATION):
            self.correlation_engine.add_rule(rule)
        self._audit("system", "rule_add", f"Added rule: {rule.name}")
        return rule

    def remove_rule(self, rule_id):
        """Remove a rule."""
        self.rules_engine.remove_rule(rule_id)
        self.correlation_engine.remove_rule(rule_id)
        self._audit("system", "rule_remove", f"Removed rule: {rule_id}")

    def get_rules(self):
        """Get all rules."""
        return [r.to_dict() for r in self.rules_engine.get_all_rules() +
                list(self.correlation_engine._rules.values())]

    def test_rule(self, rule_data, event_ids=None):
        """Test a rule against events."""
        rule = Rule.from_dict(rule_data) if isinstance(rule_data, dict) else rule_data
        if event_ids:
            events = []
            for eid in event_ids:
                evt_data = self.storage.get_event(eid)
                if evt_data:
                    events.append(Event.from_dict(evt_data))
        else:
            result = self.storage.query_events(limit=1000)
            events = [Event.from_dict(e) for e in result.get("events", [])]
        return self.rules_engine.test_rule(rule, events)

    # --- User management ---

    def authenticate(self, username, password, ip_address=None):
        """Authenticate a user."""
        user = self.users.get(username)
        if not user:
            self._audit(username, "auth_failed", "User not found", ip_address)
            return None
        if not user.is_active:
            self._audit(username, "auth_failed", "User inactive", ip_address)
            return None
        if user.is_locked_out():
            self._audit(username, "auth_failed", "User locked out", ip_address)
            return None

        if user.verify_password(password):
            user.record_login(True, ip_address)
            session = user.create_session()
            self._audit(username, "auth_success", "Login successful", ip_address)
            return session
        else:
            user.record_login(False, ip_address)
            self._audit(username, "auth_failed", "Invalid password", ip_address)
            return None

    def create_user(self, username, password, email="", roles=None, **kwargs):
        """Create a new user."""
        if username in self.users:
            raise ValueError(f"User {username} already exists")
        user = User.create(username, password, email, roles or ["viewer"], **kwargs)
        self.users[username] = user
        self._save_users()
        self._audit(username, "user_create", f"Created user: {username}")
        return user

    def change_password(self, username, old_password, new_password):
        """Change a user's password after verifying the old one.

        Returns (success, error_message).
        """
        user = self.users.get(username)
        if not user:
            return False, "User not found"
        if not user.verify_password(old_password):
            self._audit(username, "password_change_failed", "Incorrect old password")
            return False, "Current password is incorrect"
        # Strength check
        is_strong, issues = user.check_password_strength(new_password)
        if not is_strong:
            return False, "Password too weak: " + "; ".join(issues)
        user.set_password(new_password)
        user.must_change_password = False
        self._save_users()
        self._audit(username, "password_changed", "Password changed successfully")
        return True, "Password changed successfully"

    def admin_reset_password(self, username, new_password, admin_user):
        """Admin-forced password reset (requires the target to change on next login)."""
        user = self.users.get(username)
        if not user:
            return False, "User not found"
        is_strong, issues = user.check_password_strength(new_password)
        if not is_strong:
            return False, "Password too weak: " + "; ".join(issues)
        user.set_password(new_password)
        user.must_change_password = True
        user.failed_login_attempts = 0
        user.is_locked = False
        self._save_users()
        self._audit(admin_user, "password_reset", f"Admin reset password for {username}")
        return True, "Password reset; user must change on next login"

    def update_user_profile(self, username, **kwargs):
        """Update user profile fields (email, full_name, display_name)."""
        user = self.users.get(username)
        if not user:
            return False, "User not found"
        for field in ("email", "full_name", "display_name"):
            if field in kwargs and kwargs[field]:
                setattr(user, field, kwargs[field])
        if "preferences" in kwargs:
            user.preferences.update(kwargs["preferences"])
        user.updated_at = datetime.now(timezone.utc)
        self._save_users()
        self._audit(username, "profile_updated", "Profile updated")
        return True, "Profile updated"

    def delete_user(self, username, admin_user):
        """Delete a user account."""
        if username not in self.users:
            return False, "User not found"
        if username == "admin":
            return False, "Cannot delete the primary admin account"
        if username == admin_user:
            return False, "Cannot delete your own account"
        del self.users[username]
        self._save_users()
        self._audit(admin_user, "user_deleted", f"Deleted user: {username}")
        return True, "User deleted"

    def get_user(self, username):
        """Get a user by username."""
        return self.users.get(username)

    def get_users(self):
        """Get all users."""
        return [u.to_dict() for u in self.users.values()]

    # --- Asset management ---

    def add_asset(self, asset_data):
        """Add an asset to the inventory."""
        asset = Asset.from_dict(asset_data) if isinstance(asset_data, dict) else asset_data
        self.enrichment.add_asset(asset)
        self.risk_scorer.set_asset_criticality(asset.asset_id, asset.criticality.value)
        return asset

    # --- Threat intel management ---

    def add_indicator(self, indicator_type, value, **kwargs):
        """Add a threat intelligence indicator."""
        from .threat_intel import Indicator
        indicator = Indicator(indicator_type, value, **kwargs)
        self.threat_intel.add_indicator(indicator)
        return indicator

    # --- Statistics and health ---

    def get_dashboard_stats(self):
        """Get statistics for dashboards."""
        storage_stats = self.storage.get_stats()

        # Event counts by type/severity
        type_counts = defaultdict(int)
        severity_counts = defaultdict(int)
        recent_result = self.storage.query_events(limit=10000)
        for event in recent_result.get("events", []):
            etype = event.get("event_type", "unknown")
            severity = event.get("severity", "info")
            type_counts[etype] += 1
            severity_counts[severity] += 1

        # Alert stats
        open_alerts = self.storage.query_alerts({"status": "open"}, limit=10000)
        alert_count = open_alerts.get("total", 0)

        return {
            "uptime": (datetime.now(timezone.utc) - self._start_time).total_seconds() if self._start_time else 0,
            "events_total": storage_stats.get("current_events", 0),
            "alerts_total": storage_stats.get("current_alerts", 0),
            "open_alerts": alert_count,
            "events_by_type": dict(type_counts),
            "events_by_severity": dict(severity_counts),
            "active_rules": self.rules_engine.get_stats()["active_rules"],
            "total_rules": self.rules_engine.get_stats()["total_rules"],
            "threat_indicators": self.threat_intel.get_indicator_count(),
            "pipeline_stats": self.pipeline.get_stats(),
        }

    def get_health(self):
        """Get system health status."""
        return {
            "running": self._running,
            "uptime": (datetime.now(timezone.utc) - self._start_time).total_seconds() if self._start_time else 0,
            "storage": self.storage.get_stats(),
            "pipeline": self.pipeline.get_stats(),
            "collectors": self.collector_registry.get_all_stats(),
            "stages": self.pipeline.get_stage_stats(),
        }

    def get_stats(self):
        """Get comprehensive statistics."""
        return {
            "engine": {
                "running": self._running,
                "uptime": (datetime.now(timezone.utc) - self._start_time).total_seconds() if self._start_time else 0,
            },
            "pipeline": self.pipeline.get_stats(),
            "storage": self.storage.get_stats(),
            "rules": self.rules_engine.get_stats(),
            "correlation": self.correlation_engine.get_stats(),
            "anomaly": self.anomaly_engine.get_stats(),
            "risk_scoring": self.risk_scorer.get_stats(),
            "threat_intel": self.threat_intel.get_stats(),
            "enrichment": self.enrichment.get_stats(),
            "aggregation": self.aggregation.get_stats(),
            "query": self.query_engine.get_stats(),
            "alerting": self.alerting.get_stats(),
            "parsers": self.parser_registry.all_stats(),
        }

    # --- Audit logging ---

    def _audit(self, actor, action, description, ip_address=None):
        """Record an audit log entry."""
        entry = {
            "id": len(self._audit_log) + 1,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actor": actor,
            "action": action,
            "description": description,
            "ip_address": ip_address,
        }
        self._audit_log.append(entry)
        if len(self._audit_log) > self._max_audit_log:
            self._audit_log = self._audit_log[-self._max_audit_log:]
        logger.debug("AUDIT: %s - %s - %s", actor, action, description)

    def get_audit_log(self, limit=100, offset=0):
        """Get audit log entries."""
        entries = list(reversed(self._audit_log))
        return {
            "entries": entries[offset:offset + limit],
            "total": len(entries),
            "limit": limit,
            "offset": offset,
        }

    # --- Collector management ---

    def add_collector(self, collector):
        """Add a collector."""
        collector.set_event_handler(self._collector_handler)
        self.collector_registry.register(collector)

    def _collector_handler(self, raw_data, metadata):
        """Handler for collector events."""
        self.ingest(raw_data, metadata)

    def start_collector(self, name):
        """Start a specific collector."""
        collector = self.collector_registry.get(name)
        if collector:
            collector.set_event_handler(self._collector_handler)
            collector.start()

    def stop_collector(self, name):
        """Stop a specific collector."""
        collector = self.collector_registry.get(name)
        if collector:
            collector.stop()

    # --- Cleanup ---

    def close(self):
        """Clean up resources."""
        self.stop()
        if hasattr(self.storage, "close"):
            self.storage.close()
        logger.info("SIEM engine closed")

    def __repr__(self):
        return (f"SIEMEngine(running={self._running}, "
                f"events={self.storage.get_stats().get('current_events', 0)}, "
                f"rules={self.rules_engine.get_stats()['total_rules']})")
