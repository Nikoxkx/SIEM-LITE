"""
Test suite for the SIEM-Lite engine.

Run with: pytest tests/ -v
"""

import sys
import os
import json
import time
import pytest
from datetime import datetime, timezone

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from siem_lite.models.event import Event, EventStatus, EventType
from siem_lite.models.alert import Alert, AlertStatus, AlertSeverity
from siem_lite.models.rule import Rule, RuleType, RuleStatus, RuleCondition
from siem_lite.models.user import User, Role, Permission
from siem_lite.models.incident import Incident, IncidentStatus
from siem_lite.models.asset import Asset, AssetType, AssetCriticality

from siem_lite.parsers.base import ParserRegistry, ParseError
from siem_lite.parsers.syslog_parser import SyslogParser, RFC3164Parser, RFC5424Parser
from siem_lite.parsers.json_parser import JSONParser, KeyValueParser
from siem_lite.parsers.cef_parser import CEFParser
from siem_lite.parsers.leef_parser import LEEFParser
from siem_lite.parsers.apache_parser import ApacheAccessParser
from siem_lite.parsers.regex_parser import RegexParser, GrokParser

from siem_lite.core.normalizer import Normalizer
from siem_lite.core.enrichment import EnrichmentEngine
from siem_lite.core.threat_intel import ThreatIntelEngine, Indicator
from siem_lite.core.storage import InMemoryBackend, SQLiteBackend
from siem_lite.core.rules_engine import RulesEngine
from siem_lite.core.correlation import CorrelationEngine
from siem_lite.core.risk_scoring import RiskScoringEngine
from siem_lite.core.alerting import AlertingEngine
from siem_lite.core.query import QueryEngine, Query
from siem_lite.core.engine import SIEMEngine

from siem_lite.utils.time_utils import parse_timestamp, parse_duration, format_duration
from siem_lite.utils.geoip import IPClassifier
from siem_lite.utils.crypto import hash_string, generate_token, generate_jwt, verify_jwt
from siem_lite.utils.validators import validate_ip, validate_email, validate_severity
from siem_lite.utils.helpers import deep_get, chunk_list, compute_statistics


# ============================================================================
# Event Model Tests
# ============================================================================

class TestEventModel:
    """Tests for the Event model."""

    def test_event_creation(self):
        """Test basic event creation."""
        event = Event()
        assert event.event_id is not None
        assert event.get("event_status") == EventStatus.NEW.value

    def test_event_with_data(self):
        """Test event creation with data."""
        event = Event(data={
            "source_ip": "192.168.1.1",
            "dest_ip": "10.0.0.1",
            "action": "connect",
            "source_port": 12345,
        })
        assert event.get("source_ip") == "192.168.1.1"
        assert event.get("source_port") == 12345

    def test_event_field_access(self):
        """Test dict-like field access."""
        event = Event()
        event["source_ip"] = "1.2.3.4"
        assert event["source_ip"] == "1.2.3.4"
        assert "source_ip" in event
        assert "nonexistent" not in event

    def test_event_tags(self):
        """Test tag management."""
        event = Event()
        event.add_tag("malware")
        event.add_tag("c2")
        event.add_tag("malware")  # duplicate
        assert event.has_tag("malware")
        assert len(event.get("tags")) == 2

    def test_event_serialization(self):
        """Test event serialization."""
        event = Event(data={"source_ip": "192.168.1.1", "action": "logon"})
        d = event.to_dict()
        assert d["source_ip"] == "192.168.1.1"
        assert d["action"] == "logon"

        # Test JSON round-trip
        json_str = event.to_json()
        assert json.loads(json_str)["source_ip"] == "192.168.1.1"

    def test_event_validation(self):
        """Test event validation."""
        event = Event()
        is_valid, errors = event.validate()
        assert not is_valid
        assert any("event_id" not in e for e in errors) or errors  # Has errors

    def test_event_dedup(self):
        """Test event deduplication."""
        event1 = Event(data={
            "source_ip": "1.2.3.4", "dest_ip": "5.6.7.8",
            "action": "connect", "message": "test",
        })
        event2 = Event(data={
            "source_ip": "1.2.3.4", "dest_ip": "5.6.7.8",
            "action": "connect", "message": "test",
        })
        assert event1.dedup_hash() == event2.dedup_hash()
        assert event1.is_duplicate_of(event2)

    def test_event_copy(self):
        """Test event copying."""
        event = Event(data={"source_ip": "1.2.3.4"})
        copy = event.copy()
        assert copy.get("source_ip") == "1.2.3.4"
        assert copy.event_id != event.event_id

    def test_event_cef_format(self):
        """Test CEF output."""
        event = Event(data={
            "vendor": "Cisco", "product": "ASA", "action": "deny",
            "source_ip": "1.2.3.4", "dest_ip": "5.6.7.8",
            "severity": "high",
        })
        cef = event.to_cef()
        assert "CEF:0|Cisco|ASA" in cef

    def test_event_type_coercion(self):
        """Test type coercion."""
        event = Event()
        event.set("source_port", "8080")
        assert event.get("source_port") == 8080
        event.set("bytes_sent", "1234.5")
        assert event.get("bytes_sent") == 1234.5


# ============================================================================
# Parser Tests
# ============================================================================

class TestParsers:
    """Tests for log parsers."""

    def test_rfc3164_parser(self):
        """Test RFC 3164 syslog parsing."""
        parser = RFC3164Parser()
        raw = "<34>Oct 11 22:14:15 mymachine su: 'su root' failed"
        result = parser.parse(raw)
        assert result.is_valid
        assert result.fields["source_host"] == "mymachine"
        assert result.fields["severity"] == "critical"

    def test_rfc5424_parser(self):
        """Test RFC 5424 syslog parsing."""
        parser = RFC5424Parser()
        raw = "<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - 'su root' failed"
        result = parser.parse(raw)
        assert result.is_valid
        assert result.fields["source_host"] == "mymachine.example.com"
        assert result.fields["version"] == 1

    def test_json_parser(self):
        """Test JSON parsing."""
        parser = JSONParser()
        raw = json.dumps({
            "timestamp": "2024-01-15T10:30:00Z",
            "source_ip": "192.168.1.1",
            "action": "logon",
            "message": "User login",
        })
        result = parser.parse(raw)
        assert result.is_valid
        assert result.fields["source_ip"] == "192.168.1.1"

    def test_cef_parser(self):
        """Test CEF parsing."""
        parser = CEFParser()
        raw = "CEF:0|Cisco|ASA|1.0|100|Test Event|6|src=10.0.0.1 dst=192.168.1.1 spt=1234 dpt=80 act=deny"
        result = parser.parse(raw)
        assert result.is_valid
        assert result.fields["vendor"] == "Cisco"
        assert result.fields["source_ip"] == "10.0.0.1"
        assert result.fields["dest_ip"] == "192.168.1.1"

    def test_leef_parser(self):
        """Test LEEF parsing."""
        parser = LEEFParser()
        raw = "LEEF:1.0|IBM|Product|1.0|100|src=10.0.0.1\tdst=192.168.1.1\tsev=5"
        result = parser.parse(raw)
        assert result.is_valid
        assert result.fields["vendor"] == "IBM"
        assert result.fields["source_ip"] == "10.0.0.1"

    def test_apache_parser(self):
        """Test Apache access log parsing."""
        parser = ApacheAccessParser()
        raw = '127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://example.com/" "Mozilla/4.08"'
        result = parser.parse(raw)
        assert result.is_valid
        assert result.fields["source_ip"] == "127.0.0.1"
        assert result.fields["http_method"] == "GET"
        assert result.fields["status_code"] == 200

    def test_keyvalue_parser(self):
        """Test key-value parsing."""
        parser = KeyValueParser()
        raw = "date=2024-01-15 time=10:30:00 src=192.168.1.1 dst=10.0.0.1 action=allow proto=TCP"
        result = parser.parse(raw)
        assert result.is_valid
        assert result.fields["source_ip"] == "192.168.1.1"

    def test_regex_parser(self):
        """Test regex parser."""
        parser = RegexParser(
            pattern=r'^SRC=(?P<source_ip>\d+\.\d+\.\d+\.\d+)\s+DST=(?P<dest_ip>\d+\.\d+\.\d+\.\d+)$'
        )
        result = parser.parse("SRC=1.2.3.4 DST=5.6.7.8")
        assert result.is_valid
        assert result.fields["source_ip"] == "1.2.3.4"
        assert result.fields["dest_ip"] == "5.6.7.8"

    def test_grok_parser(self):
        """Test Grok parser."""
        parser = GrokParser(grok_pattern="%{IP:source_ip} %{WORD:action} %{NUMBER:status}")
        result = parser.parse("192.168.1.1 connect 200")
        assert result.is_valid
        assert result.fields["source_ip"] == "192.168.1.1"
        assert result.fields["action"] == "connect"

    def test_parser_registry(self):
        """Test parser auto-detection."""
        registry = ParserRegistry()
        registry.register(JSONParser())
        registry.register(CEFParser())
        registry.register(RFC3164Parser())

        # JSON auto-detection
        result = registry.auto_parse('{"source_ip": "1.2.3.4"}')
        assert result is not None
        assert result.parser_name == "json"

        # CEF auto-detection
        result = registry.auto_parse("CEF:0|Vendor|Product|1.0|1|Test|5|src=1.2.3.4")
        assert result is not None
        assert result.parser_name == "cef"

    def test_parser_can_parse(self):
        """Test parser format detection."""
        json_parser = JSONParser()
        assert json_parser.can_parse('{"test": 1}')
        assert not json_parser.can_parse("not json")


# ============================================================================
# Normalizer Tests
# ============================================================================

class TestNormalizer:
    """Tests for the event normalizer."""

    def test_normalize_basic(self):
        """Test basic normalization."""
        norm = Normalizer()
        event = norm.normalize({
            "source_ip": "192.168.1.1",
            "severity": "HIGH",
            "action": "FAILED",
            "result": "SUCCESSFUL",
        }, source_log="test")
        assert event.get("source_ip") == "192.168.1.1"
        assert event.get("severity") == "high"
        assert event.get("action") == "logon_failed"
        assert event.get("result") == "success"

    def test_normalize_severity(self):
        """Test severity normalization."""
        norm = Normalizer()
        for input_sev, expected in [("CRITICAL", "critical"), ("info", "info"),
                                     ("WARN", "warning"), ("5", "notice"),
                                     ("emergency", "emergency")]:
            event = norm.normalize({"severity": input_sev})
            assert event.get("severity") == expected

    def test_normalize_event_type_inference(self):
        """Test event type inference."""
        norm = Normalizer()
        event = norm.normalize({
            "product": "sshd",
            "action": "logon_failed",
            "message": "Failed password",
        })
        assert event.get("event_type") == "authentication"

    def test_normalize_ip_classification(self):
        """Test IP internal/external classification."""
        norm = Normalizer()
        event = norm.normalize({"source_ip": "192.168.1.1"})
        assert event.get("source_is_internal") is True

        event = norm.normalize({"source_ip": "8.8.8.8"})
        assert event.get("source_is_internal") is False

    def test_normalize_port_category(self):
        """Test port-to-category mapping."""
        norm = Normalizer()
        event = norm.normalize({"dest_port": 443})
        assert event.get("category") == "https"

        event = norm.normalize({"dest_port": 22})
        assert event.get("category") == "ssh"


# ============================================================================
# Rules Engine Tests
# ============================================================================

class TestRulesEngine:
    """Tests for the rules engine."""

    def test_rule_creation(self):
        """Test rule creation."""
        rule = Rule(
            name="Test Rule",
            rule_type="detection",
            severity="high",
            conditions=[[{"field": "action", "operator": "eq", "value": "logon_failed"}]],
        )
        assert rule.name == "Test Rule"
        assert rule.enabled
        assert len(rule.conditions) == 1

    def test_rule_evaluation(self):
        """Test rule evaluation."""
        alerts = []
        def handler(alert, event, rule):
            alerts.append(alert)

        engine = RulesEngine(alert_handler=handler)
        rule = Rule(
            name="Failed Login",
            rule_type="detection",
            severity="medium",
            conditions=[[{"field": "action", "operator": "eq", "value": "logon_failed"}]],
        )
        engine.add_rule(rule)

        # Matching event
        event = Event(data={"action": "logon_failed", "source_ip": "1.2.3.4"})
        fired = engine.evaluate(event)
        assert len(fired) == 1
        assert len(alerts) == 1

        # Non-matching event
        event2 = Event(data={"action": "logon", "source_ip": "1.2.3.4"})
        fired = engine.evaluate(event2)
        assert len(fired) == 0

    def test_rule_condition_operators(self):
        """Test different condition operators."""
        cond = RuleCondition("source_ip", "eq", "1.2.3.4")
        event = Event(data={"source_ip": "1.2.3.4"})
        assert cond.evaluate(event)

        cond = RuleCondition("source_ip", "ne", "5.6.7.8")
        assert cond.evaluate(event)

        cond = RuleCondition("dest_port", "gt", 80)
        event = Event(data={"dest_port": 443})
        assert cond.evaluate(event)

        cond = RuleCondition("action", "in", ["logon", "logoff"])
        event = Event(data={"action": "logon"})
        assert cond.evaluate(event)

        cond = RuleCondition("message", "contains", "failed")
        event = Event(data={"message": "login failed for user"})
        assert cond.evaluate(event)

        cond = RuleCondition("source_ip", "regex", r"\d+\.\d+\.\d+\.\d+")
        event = Event(data={"source_ip": "192.168.1.1"})
        assert cond.evaluate(event)

    def test_rule_with_or_logic(self):
        """Test OR logic between condition groups."""
        engine = RulesEngine()
        rule = Rule(
            name="Multi-match",
            rule_type="detection",
            severity="medium",
            conditions=[
                [{"field": "action", "operator": "eq", "value": "logon_failed"}],
                [{"field": "severity", "operator": "eq", "value": "critical"}],
            ],
            logic="or",
        )
        engine.add_rule(rule)

        # First group matches
        event = Event(data={"action": "logon_failed"})
        assert len(engine.evaluate(event)) == 1

        # Second group matches
        event = Event(data={"severity": "critical"})
        assert len(engine.evaluate(event)) == 1

        # Neither matches
        event = Event(data={"action": "logon", "severity": "info"})
        assert len(engine.evaluate(event)) == 0

    def test_rule_enable_disable(self):
        """Test rule enable/disable."""
        engine = RulesEngine()
        rule = Rule(
            name="Test",
            rule_type="detection",
            conditions=[[{"field": "action", "operator": "eq", "value": "test"}]],
        )
        engine.add_rule(rule)

        event = Event(data={"action": "test"})
        assert len(engine.evaluate(event)) == 1

        engine.disable_rule(rule.rule_id)
        assert len(engine.evaluate(event)) == 0

        engine.enable_rule(rule.rule_id)
        assert len(engine.evaluate(event)) == 1


# ============================================================================
# Correlation Engine Tests
# ============================================================================

class TestCorrelationEngine:
    """Tests for the correlation engine."""

    def test_threshold_correlation(self):
        """Test threshold-based correlation."""
        alerts = []
        def handler(alert, event, rule):
            alerts.append(alert)

        engine = CorrelationEngine(alert_handler=handler)
        rule = Rule(
            name="Brute Force",
            rule_type="correlation",
            severity="high",
            conditions=[[{"field": "action", "operator": "eq", "value": "logon_failed"}]],
            window=60,
            threshold=3,
            group_by=["source_ip"],
        )
        engine.add_rule(rule)

        # Send events below threshold
        for i in range(2):
            event = Event(data={"action": "logon_failed", "source_ip": "1.2.3.4"})
            engine.process(event)
        assert len(alerts) == 0

        # Third event triggers threshold
        event = Event(data={"action": "logon_failed", "source_ip": "1.2.3.4"})
        engine.process(event)
        assert len(alerts) == 1

    def test_correlation_grouping(self):
        """Test correlation grouping by field."""
        alerts = []
        def handler(alert, event, rule):
            alerts.append(alert)

        engine = CorrelationEngine(alert_handler=handler)
        rule = Rule(
            name="Multi-source",
            rule_type="correlation",
            conditions=[[{"field": "action", "operator": "eq", "value": "logon_failed"}]],
            window=60,
            threshold=2,
            group_by=["source_ip"],
        )
        engine.add_rule(rule)

        # Different sources shouldn't trigger
        engine.process(Event(data={"action": "logon_failed", "source_ip": "1.1.1.1"}))
        engine.process(Event(data={"action": "logon_failed", "source_ip": "2.2.2.2"}))
        assert len(alerts) == 0

        # Same source twice triggers
        engine.process(Event(data={"action": "logon_failed", "source_ip": "1.1.1.1"}))
        assert len(alerts) == 1


# ============================================================================
# Threat Intel Tests
# ============================================================================

class TestThreatIntel:
    """Tests for threat intelligence engine."""

    def test_indicator_matching(self):
        """Test IOC matching."""
        engine = ThreatIntelEngine()
        event = Event(data={"source_ip": "45.227.255.206"})  # Known malicious IP
        matches = engine.check_event(event)
        assert len(matches) > 0

    def test_indicator_no_match(self):
        """Test no IOC match."""
        engine = ThreatIntelEngine()
        event = Event(data={"source_ip": "8.8.8.8"})
        matches = engine.check_event(event)
        assert len(matches) == 0

    def test_add_indicator(self):
        """Test adding custom indicators."""
        engine = ThreatIntelEngine()
        engine.add_indicator(Indicator("ip", "99.99.99.99", severity="high",
                                        tags=["test"]))
        event = Event(data={"source_ip": "99.99.99.99"})
        matches = engine.check_event(event)
        assert len(matches) == 1

    def test_threat_enrichment(self):
        """Test event enrichment with threat intel."""
        engine = ThreatIntelEngine()
        event = Event(data={"source_ip": "45.227.255.206"})
        engine.enrich_event(event)
        assert event.has_tag("threat_intel_match")
        assert event.get("ioc_matched") is not None


# ============================================================================
# Risk Scoring Tests
# ============================================================================

class TestRiskScoring:
    """Tests for the risk scoring engine."""

    def test_basic_scoring(self):
        """Test basic risk scoring."""
        scorer = RiskScoringEngine()
        event = Event(data={
            "severity": "critical",
            "source_ip": "8.8.8.8",
            "dest_ip": "192.168.1.1",
            "action": "logon_failed",
        })
        score = scorer.score(event)
        assert 0 <= score <= 100

    def test_severity_impact(self):
        """Test that severity impacts score."""
        scorer = RiskScoringEngine()
        low_event = Event(data={"severity": "info", "action": "read"})
        high_event = Event(data={"severity": "critical", "action": "delete"})

        low_score = scorer.score(low_event)
        high_score = scorer.score(high_event)
        assert high_score > low_score

    def test_internal_vs_external(self):
        """Test that external connections score higher."""
        scorer = RiskScoringEngine()
        internal = Event(data={
            "severity": "warning",
            "source_ip": "192.168.1.1",
            "dest_ip": "10.0.0.1",
        })
        external = Event(data={
            "severity": "warning",
            "source_ip": "8.8.8.8",
            "dest_ip": "192.168.1.1",
        })
        assert scorer.score(external) > scorer.score(internal)


# ============================================================================
# Storage Tests
# ============================================================================

class TestStorage:
    """Tests for storage backends."""

    def test_memory_storage(self):
        """Test in-memory storage."""
        storage = InMemoryBackend()
        event = Event(data={"source_ip": "1.2.3.4", "action": "test"})
        storage.store_event(event)

        retrieved = storage.get_event(event.event_id)
        assert retrieved is not None
        assert retrieved["source_ip"] == "1.2.3.4"

    def test_memory_query(self):
        """Test querying in-memory storage."""
        storage = InMemoryBackend()
        for i in range(10):
            event = Event(data={"source_ip": f"10.0.0.{i}", "action": "test"})
            storage.store_event(event)

        result = storage.query_events({"source_ip": "10.0.0.5"})
        assert result["total"] == 1

    def test_sqlite_storage(self):
        """Test SQLite storage."""
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

        try:
            storage = SQLiteBackend(db_path)
            event = Event(data={"source_ip": "1.2.3.4", "action": "test"})
            storage.store_event(event)

            retrieved = storage.get_event(event.event_id)
            assert retrieved is not None
            assert retrieved["source_ip"] == "1.2.3.4"

            storage.close()
        finally:
            os.unlink(db_path)

    def test_alert_storage(self):
        """Test alert storage."""
        storage = InMemoryBackend()
        alert = Alert(title="Test Alert", severity="high", rule_id="TEST-001")
        storage.store_alert(alert)

        retrieved = storage.get_alert(alert.alert_id)
        assert retrieved is not None
        assert retrieved["title"] == "Test Alert"


# ============================================================================
# Query Engine Tests
# ============================================================================

class TestQueryEngine:
    """Tests for the query engine."""

    def test_query_builder(self):
        """Test query builder."""
        q = Query()
        q.field("source_ip").equals("1.2.3.4")
        q.field("severity").in_(["high", "critical"])
        q.limit(10)
        q.sort("-timestamp")

        assert ("source_ip", "eq", "1.2.3.4") in q.filters
        assert q.limit_value == 10

    def test_query_string_parsing(self):
        """Test query string parsing."""
        q = Query.parse("source_ip:192.168.1.1 severity:high")
        assert len(q.filters) == 2

    def test_search(self):
        """Test event search."""
        storage = InMemoryBackend()
        for i in range(5):
            event = Event(data={"source_ip": "10.0.0.1", "action": "logon",
                                "severity": "info"})
            storage.store_event(event)

        engine = QueryEngine(storage=storage)
        result = engine.search(Query().field("source_ip").equals("10.0.0.1"))
        assert result["total"] == 5


# ============================================================================
# Utility Tests
# ============================================================================

class TestUtils:
    """Tests for utility functions."""

    def test_parse_timestamp(self):
        """Test timestamp parsing."""
        ts = parse_timestamp("2024-01-15T10:30:00Z")
        assert ts is not None
        assert ts.year == 2024

        ts = parse_timestamp("2024-01-15 10:30:00")
        assert ts is not None

    def test_parse_duration(self):
        """Test duration parsing."""
        assert parse_duration("60") == 60
        assert parse_duration("5m") == 300
        assert parse_duration("1h") == 3600
        assert parse_duration("1d") == 86400
        assert parse_duration("1h30m") == 5400

    def test_ip_classifier(self):
        """Test IP classification."""
        assert IPClassifier.is_internal("192.168.1.1")
        assert IPClassifier.is_internal("10.0.0.1")
        assert not IPClassifier.is_internal("8.8.8.8")
        assert IPClassifier.is_valid_ip("1.2.3.4")
        assert not IPClassifier.is_valid_ip("not-an-ip")

    def test_hash_string(self):
        """Test string hashing."""
        h = hash_string("test", "sha256")
        assert len(h) == 64  # SHA256 hex length
        assert h == hash_string("test", "sha256")  # deterministic

    def test_jwt(self):
        """Test JWT generation and verification."""
        payload = {"user": "admin", "role": "admin"}
        token = generate_jwt(payload, "secret")
        decoded = verify_jwt(token, "secret")
        assert decoded is not None
        assert decoded["user"] == "admin"

    def test_validators(self):
        """Test input validators."""
        valid, _ = validate_ip("192.168.1.1")
        assert valid
        valid, _ = validate_ip("not-an-ip")
        assert not valid

        valid, _ = validate_email("user@example.com")
        assert valid
        valid, _ = validate_email("not-email")
        assert not valid

        valid, _ = validate_severity("critical")
        assert valid

    def test_helpers(self):
        """Test helper functions."""
        data = {"a": {"b": {"c": 42}}}
        assert deep_get(data, "a.b.c") == 42

        chunks = chunk_list([1, 2, 3, 4, 5], 2)
        assert len(chunks) == 3
        assert chunks[0] == [1, 2]

        stats = compute_statistics([1, 2, 3, 4, 5])
        assert stats["mean"] == 3
        assert stats["min"] == 1
        assert stats["max"] == 5


# ============================================================================
# User Model Tests
# ============================================================================

class TestUserModel:
    """Tests for the user model."""

    def test_user_creation(self):
        """Test user creation."""
        user = User.create("testuser", "password123", "test@example.com", ["analyst"])
        assert user.username == "testuser"
        assert "analyst" in user.roles

    def test_password_verification(self):
        """Test password verification."""
        user = User.create("testuser", "password123")
        assert user.verify_password("password123")
        assert not user.verify_password("wrongpassword")

    def test_permissions(self):
        """Test permission checking."""
        user = User.create("admin", "pass", roles=["admin"])
        assert user.has_permission(Permission.SYSTEM_ADMIN)

        analyst = User.create("analyst", "pass", roles=["analyst"])
        assert analyst.has_permission(Permission.VIEW_EVENTS)
        assert not analyst.has_permission(Permission.SYSTEM_ADMIN)

    def test_login_attempts(self):
        """Test login attempt tracking."""
        user = User.create("user", "pass")
        for _ in range(5):
            user.record_login(False)
        assert user.is_locked_out()


# ============================================================================
# Integration Test
# ============================================================================

class TestSIEMEngine:
    """Integration tests for the full SIEM engine."""

    def test_engine_initialization(self):
        """Test engine initialization."""
        engine = SIEMEngine(config={"storage": {"type": "memory"}})
        assert engine.storage is not None
        assert engine.rules_engine is not None
        assert engine.pipeline is not None
        engine.close()

    def test_event_ingestion(self):
        """Test event ingestion through the pipeline."""
        engine = SIEMEngine(config={"storage": {"type": "memory"}})
        engine.start()

        event = engine.ingest("<34>Oct 11 22:14:15 host sshd[1234]: Failed password for user from 1.2.3.4 port 22")
        assert event is not None

        stats = engine.get_stats()
        assert stats["pipeline"]["events_processed"] >= 1

        engine.close()

    def test_search(self):
        """Test search functionality."""
        engine = SIEMEngine(config={"storage": {"type": "memory"}})
        engine.start()

        engine.ingest('{"source_ip": "192.168.1.1", "action": "logon", "event_type": "authentication"}')
        engine.ingest('{"source_ip": "192.168.1.2", "action": "logoff", "event_type": "authentication"}')

        results = engine.search("source_ip:192.168.1.1")
        assert results["total"] >= 1

        engine.close()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
