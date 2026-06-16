"""
Threat intelligence engine: matches events against known indicators of
compromise (IOCs) and threat intelligence feeds.

Supports matching against:
- Malicious IP addresses
- Malicious domains
- File hashes (MD5, SHA1, SHA256)
- URLs
- Email addresses
- CIDR ranges
- Regex patterns
"""

import re
import time
import ipaddress
import logging
from datetime import datetime, timezone, timedelta
from collections import defaultdict

from ..utils.geoip import IPClassifier
from ..utils.validators import validate_hash

logger = logging.getLogger(__name__)


class Indicator:
    """A single threat intelligence indicator."""

    __slots__ = ("id", "type", "value", "source", "severity", "confidence",
                 "tags", "description", "first_seen", "last_seen", "expires",
                 "metadata")

    INDICATOR_TYPES = {"ip", "domain", "url", "hash", "email", "cidr", "regex", "asn"}

    def __init__(self, indicator_type, value, source="manual", severity="medium",
                 confidence=0.8, tags=None, description="", expires=None, metadata=None):
        self.id = f"IOC-{abs(hash(f'{indicator_type}:{value}')) % 1000000:06d}"
        if indicator_type not in self.INDICATOR_TYPES:
            raise ValueError(f"Unknown indicator type: {indicator_type}")
        self.type = indicator_type
        self.value = value
        self.source = source
        self.severity = severity
        self.confidence = confidence
        self.tags = tags or []
        self.description = description
        now = datetime.now(timezone.utc)
        self.first_seen = now
        self.last_seen = now
        self.expires = expires
        self.metadata = metadata or {}

    @property
    def is_expired(self):
        """Check if the indicator has expired."""
        if self.expires is None:
            return False
        if isinstance(self.expires, str):
            from ..utils.time_utils import parse_timestamp
            self.expires = parse_timestamp(self.expires)
        return datetime.now(timezone.utc) > self.expires

    def matches(self, value):
        """Check if a value matches this indicator."""
        if not value:
            return False
        value_str = str(value).strip()

        if self.type == "ip":
            return value_str == self.value
        elif self.type == "cidr":
            return IPClassifier.in_cidr(value_str, self.value)
        elif self.type == "domain":
            return value_str.lower() == self.value.lower() or value_str.lower().endswith("." + self.value.lower())
        elif self.type == "url":
            return self.value.lower() in value_str.lower()
        elif self.type == "hash":
            return value_str.lower() == self.value.lower()
        elif self.type == "email":
            return value_str.lower() == self.value.lower()
        elif self.type == "regex":
            try:
                return bool(re.search(self.value, value_str))
            except re.error:
                return False
        elif self.type == "asn":
            return value_str == str(self.value)
        return False

    def to_dict(self):
        return {
            "id": self.id,
            "type": self.type,
            "value": self.value,
            "source": self.source,
            "severity": self.severity,
            "confidence": self.confidence,
            "tags": self.tags,
            "description": self.description,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "expires": self.expires.isoformat() if self.expires else None,
            "metadata": self.metadata,
        }


class ThreatIntelFeed:
    """A threat intelligence feed source."""

    def __init__(self, name, feed_type="static", url=None, api_key=None,
                 update_interval=3600, auto_update=False):
        self.name = name
        self.feed_type = feed_type
        self.url = url
        self.api_key = api_key
        self.update_interval = update_interval
        self.auto_update = auto_update
        self._indicators = {}
        self._last_update = None
        self._indicator_count = 0

    def add_indicator(self, indicator):
        """Add an indicator to the feed."""
        self._indicators[indicator.id] = indicator
        self._indicator_count = len(self._indicators)

    def remove_indicator(self, indicator_id):
        """Remove an indicator."""
        if indicator_id in self._indicators:
            del self._indicators[indicator_id]
            self._indicator_count = len(self._indicators)

    def get_indicators(self, indicator_type=None):
        """Get indicators from this feed."""
        if indicator_type:
            return [i for i in self._indicators.values() if i.type == indicator_type]
        return list(self._indicators.values())

    @property
    def needs_update(self):
        """Check if feed needs updating."""
        if not self._last_update:
            return True
        elapsed = datetime.now(timezone.utc) - self._last_update
        return elapsed.total_seconds() > self.update_interval

    def update(self):
        """Update the feed from source (override in subclasses)."""
        self._last_update = datetime.now(timezone.utc)
        return self._indicator_count

    def get_stats(self):
        return {
            "name": self.name,
            "type": self.feed_type,
            "indicator_count": self._indicator_count,
            "last_update": self._last_update.isoformat() if self._last_update else None,
        }


class ThreatIntelEngine:
    """Threat intelligence matching engine.

    Maintains multiple feeds and indexes indicators for fast matching.
    Provides methods to check events against known threats.
    """

    def __init__(self, config=None):
        self.config = config or {}
        self._feeds = {}
        self._indicators_by_type = defaultdict(dict)  # type -> {value: indicator}
        self._match_count = 0
        self._check_count = 0
        self._auto_detect_type = True

        # Create default feeds
        self._init_default_feeds()

    def _init_default_feeds(self):
        """Initialize default threat intel feeds."""
        # Local manual feed
        self.add_feed(ThreatIntelFeed("local", feed_type="static"))

        # Known Tor exit nodes (sample)
        tor_feed = ThreatIntelFeed("tor_exit_nodes", feed_type="reputation")
        for ip in ["171.25.193.78", "185.220.101.1", "185.220.101.47",
                    "193.218.118.200", "199.249.230.107"]:
            tor_feed.add_indicator(Indicator(
                "ip", ip, source="tor_project", severity="medium",
                confidence=0.7, tags=["tor", "anonymizer"],
                description="Known Tor exit node"
            ))
        self.add_feed(tor_feed)

        # Known malicious IPs (sample)
        malicious_feed = ThreatIntelFeed("malicious_ips", feed_type="reputation")
        for ip in ["45.227.255.206", "45.148.10.24", "51.91.111.152",
                    "51.158.144.227", "61.177.172.28", "61.177.173.18",
                    "78.188.143.50", "106.13.63.76", "114.67.107.173",
                    "139.59.66.36", "141.98.10.63", "159.65.14.205",
                    "176.111.174.26", "193.169.254.80", "222.186.30.35"]:
            malicious_feed.add_indicator(Indicator(
                "ip", ip, source="internal_research", severity="high",
                confidence=0.85, tags=["malicious", "scanner", "brute_force"],
                description="Known malicious IP - active scanner/attacker"
            ))
        self.add_feed(malicious_feed)

        # Suspicious domains (sample)
        domain_feed = ThreatIntelFeed("suspicious_domains", feed_type="reputation")
        for domain in ["malware-c2.example.net", "phishing-login.example.tk",
                        "bad-update-server.example.xyz", "dropper.example.top"]:
            domain_feed.add_indicator(Indicator(
                "domain", domain, source="internal_research", severity="high",
                confidence=0.8, tags=["c2", "malware", "phishing"],
                description="Known malicious domain"
            ))
        self.add_feed(domain_feed)

        # Suspicious CIDRs
        cidr_feed = ThreatIntelFeed("suspicious_cidrs", feed_type="reputation")
        for cidr in ["45.155.205.0/24", "193.27.228.0/24"]:
            cidr_feed.add_indicator(Indicator(
                "cidr", cidr, source="internal_research", severity="medium",
                confidence=0.7, tags=["botnet"],
                description="Suspicious network range"
            ))
        self.add_feed(cidr_feed)

        logger.info("ThreatIntelEngine initialized with %d feeds, %d total indicators",
                    len(self._feeds), self.get_indicator_count())

    def add_feed(self, feed):
        """Add a threat intel feed."""
        self._feeds[feed.name] = feed
        for indicator in feed.get_indicators():
            self._index_indicator(indicator)

    def remove_feed(self, feed_name):
        """Remove a feed and its indicators."""
        if feed_name in self._feeds:
            feed = self._feeds[feed_name]
            for indicator in feed.get_indicators():
                self._unindex_indicator(indicator)
            del self._feeds[feed_name]

    def add_indicator(self, indicator, feed_name="local"):
        """Add an indicator to a feed."""
        if feed_name not in self._feeds:
            self.add_feed(ThreatIntelFeed(feed_name))
        self._feeds[feed_name].add_indicator(indicator)
        self._index_indicator(indicator)

    def _index_indicator(self, indicator):
        """Index an indicator for fast lookup."""
        self._indicators_by_type[indicator.type][indicator.value] = indicator

    def _unindex_indicator(self, indicator):
        """Remove an indicator from the index."""
        if indicator.type in self._indicators_by_type:
            self._indicators_by_type[indicator.type].pop(indicator.value, None)

    def check_event(self, event):
        """Check an event against all threat indicators.

        Returns list of matching indicators.
        """
        self._check_count += 1
        matches = []

        # Extract values to check from event
        values_to_check = {
            "ip": [event.get("source_ip"), event.get("dest_ip")],
            "domain": [event.get("dns_query"), event.get("dest_host"),
                       event.get("source_host")],
            "url": [event.get("url")],
            "hash": [event.get("file_hash")],
            "email": [event.get("email_from"), event.get("email_to")],
        }

        for ioc_type, values in values_to_check.items():
            for value in values:
                if value:
                    matches.extend(self._check_value(ioc_type, str(value)))

        # Also check CIDR and regex indicators
        for ip_val in [event.get("source_ip"), event.get("dest_ip")]:
            if ip_val and IPClassifier.is_valid_ip(str(ip_val)):
                for indicator in self._indicators_by_type.get("cidr", {}).values():
                    if indicator.matches(ip_val):
                        matches.append(indicator)

        if matches:
            self._match_count += 1

        return matches

    def _check_value(self, ioc_type, value):
        """Check a single value against indicators of a given type."""
        matches = []
        indicators = self._indicators_by_type.get(ioc_type, {})

        # Exact match
        if value in indicators:
            matches.append(indicators[value])

        # Domain suffix match for domains
        if ioc_type == "domain":
            for ind_value, indicator in indicators.items():
                if not indicator.is_expired and indicator.matches(value):
                    if indicator not in matches:
                        matches.append(indicator)

        # Filter out expired
        matches = [m for m in matches if not m.is_expired]
        return matches

    def enrich_event(self, event):
        """Check event for threat intel matches and enrich it.

        Returns the event with threat intel fields populated.
        """
        matches = self.check_event(event)

        if matches:
            max_severity = "info"
            all_tags = []
            all_sources = []
            ioc_values = []

            for match in matches:
                # Track highest severity
                severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
                if severity_order.get(match.severity, 0) > severity_order.get(max_severity, 0):
                    max_severity = match.severity

                all_tags.extend(match.tags)
                all_sources.append(match.source)
                ioc_values.append(match.value)

                # Add specific match metadata
                event.add_threat_tag(match.tags[0] if match.tags else match.type)

            event.set("ioc_matched", ",".join(ioc_values[:5]))
            event.set("threat_tags", list(set(all_tags)))
            event.add_tag("threat_intel_match")
            event.add_tag(f"threat_severity:{max_severity}")

            # Update reputation score based on matches
            if max_severity == "critical":
                event.set("reputation_score", 10)
            elif max_severity == "high":
                event.set("reputation_score", 25)
            elif max_severity == "medium":
                event.set("reputation_score", 45)
            else:
                event.set("reputation_score", 60)

            # Boost risk score
            current_risk = event.get("risk_score", 0)
            risk_boost = {"critical": 50, "high": 30, "medium": 15, "low": 5, "info": 0}
            event.set("risk_score", current_risk + risk_boost.get(max_severity, 0))

        return event

    def get_indicator_count(self, indicator_type=None):
        """Get count of indicators."""
        if indicator_type:
            return len(self._indicators_by_type.get(indicator_type, {}))
        return sum(len(v) for v in self._indicators_by_type.values())

    def get_feed_stats(self):
        """Get statistics for all feeds."""
        return {name: feed.get_stats() for name, feed in self._feeds.items()}

    def get_stats(self):
        """Get overall threat intel statistics."""
        return {
            "check_count": self._check_count,
            "match_count": self._match_count,
            "match_rate": self._match_count / max(self._check_count, 1),
            "total_indicators": self.get_indicator_count(),
            "feeds": len(self._feeds),
            "indicators_by_type": {t: len(v) for t, v in self._indicators_by_type.items()},
        }

    def search_indicators(self, query, indicator_type=None):
        """Search for indicators matching a query."""
        results = []
        query_lower = query.lower()
        for ioc_type, indicators in self._indicators_by_type.items():
            if indicator_type and ioc_type != indicator_type:
                continue
            for value, indicator in indicators.items():
                if (query_lower in value.lower() or
                    query_lower in indicator.description.lower() or
                    any(query_lower in tag.lower() for tag in indicator.tags)):
                    results.append(indicator)
        return results

    def export_indicators(self, indicator_type=None, format="json"):
        """Export indicators in the specified format."""
        indicators = []
        for ioc_type, ind_dict in self._indicators_by_type.items():
            if indicator_type and ioc_type != indicator_type:
                continue
            indicators.extend(ind_dict.values())

        if format == "json":
            import json
            return json.dumps([i.to_dict() for i in indicators], indent=2)
        elif format == "csv":
            lines = ["type,value,severity,source,tags,description"]
            for ind in indicators:
                tags = "|".join(ind.tags)
                lines.append(f"{ind.type},{ind.value},{ind.severity},{ind.source},{tags},{ind.description}")
            return "\n".join(lines)
        elif format == "stix":
            return self._export_stix(indicators)
        return str(indicators)

    def _export_stix(self, indicators):
        """Export in simplified STIX-like format."""
        import json
        stix_objects = []
        for ind in indicators:
            stix_type_map = {
                "ip": "ipv4-addr", "domain": "domain-name",
                "url": "url", "hash": "file", "email": "email-addr",
            }
            stix_type = stix_type_map.get(ind.type, "indicator")
            obj = {
                "type": "indicator",
                "id": f"indicator--{ind.id}",
                "created": ind.first_seen.isoformat() if ind.first_seen else None,
                "modified": ind.last_seen.isoformat() if ind.last_seen else None,
                "name": ind.description or ind.value,
                "description": ind.description,
                "pattern": f"[{stix_type}:value = '{ind.value}']",
                "pattern_type": "stix",
                "valid_from": ind.first_seen.isoformat() if ind.first_seen else None,
                "labels": ind.tags,
                "confidence": int(ind.confidence * 100),
            }
            stix_objects.append(obj)
        return json.dumps(stix_objects, indent=2)

    def reset_stats(self):
        """Reset statistics."""
        self._match_count = 0
        self._check_count = 0
