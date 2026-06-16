"""
Alerting engine: manages alert lifecycle, routing, and notification.

Handles:
- Alert creation and storage
- Alert deduplication and grouping
- Notification routing (email, webhook, syslog, console)
- Alert escalation policies
- Alert lifecycle management
"""

import json
import time
import logging
import threading
import urllib.request
from datetime import datetime, timezone, timedelta
from collections import defaultdict, deque

from ..models.alert import Alert, AlertStatus, AlertSeverity
from ..utils.crypto import generate_token

logger = logging.getLogger(__name__)


class NotificationChannel:
    """Base class for notification channels."""

    def __init__(self, name, config=None):
        self.name = name
        self.config = config or {}
        self._sent_count = 0
        self._error_count = 0

    def send(self, alert, message=""):
        """Send a notification for an alert."""
        raise NotImplementedError

    def get_stats(self):
        return {"name": self.name, "sent": self._sent_count, "errors": self._error_count}


class ConsoleNotification(NotificationChannel):
    """Prints alerts to console/log."""

    def send(self, alert, message=""):
        sev_label = alert.get("severity", "medium") if isinstance(alert, dict) else alert.severity_label
        title = alert.get("title", "") if isinstance(alert, dict) else alert.title
        rule = alert.get("rule_name", "") if isinstance(alert, dict) else alert.rule_name
        logger.warning("🚨 ALERT [%s] %s (rule: %s) - %s", sev_label.upper(), title, rule, message)
        self._sent_count += 1
        return True


class WebhookNotification(NotificationChannel):
    """Sends alert notifications to a webhook URL."""

    def send(self, alert, message=""):
        url = self.config.get("url")
        if not url:
            return False

        alert_data = alert.to_dict() if hasattr(alert, "to_dict") else alert
        payload = {
            "alert": alert_data,
            "message": message,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "siem-lite",
        }

        try:
            data = json.dumps(payload).encode("utf-8")
            headers = {"Content-Type": "application/json"}
            if self.config.get("auth_token"):
                headers["Authorization"] = f"Bearer {self.config['auth_token']}"

            req = urllib.request.Request(url, data=data, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=self.config.get("timeout", 10)) as resp:
                if resp.getcode() < 300:
                    self._sent_count += 1
                    return True
        except Exception as exc:
            self._error_count += 1
            logger.error("Webhook notification failed: %s", exc)
        return False


class EmailNotification(NotificationChannel):
    """Sends alert notifications via email (simulated)."""

    def send(self, alert, message=""):
        # In production, use smtplib or an email service
        recipients = self.config.get("recipients", [])
        subject = f"[SIEM Alert] {alert.title if hasattr(alert, 'title') else alert.get('title', 'Alert')}"
        logger.info("📧 Email alert to %s: %s", ", ".join(recipients), subject)
        self._sent_count += 1
        return True


class SyslogNotification(NotificationChannel):
    """Sends alert notifications via syslog."""

    def send(self, alert, message=""):
        import socket
        host = self.config.get("host", "localhost")
        port = self.config.get("port", 514)
        facility = self.config.get("facility", "local0")

        title = alert.title if hasattr(alert, "title") else alert.get("title", "Alert")
        severity = alert.severity_label if hasattr(alert, "severity_label") else alert.get("severity", "medium")

        sev_map = {"critical": 2, "high": 3, "medium": 4, "low": 5, "info": 6}
        sev_code = sev_map.get(str(severity).lower(), 4)

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            msg = f"<{sev_code * 8}>{facility}: SIEM Alert: {title} - {message}"
            sock.sendto(msg.encode("utf-8"), (host, port))
            sock.close()
            self._sent_count += 1
            return True
        except Exception as exc:
            self._error_count += 1
            logger.error("Syslog notification failed: %s", exc)
            return False


class AlertDeduplicator:
    """Deduplicates alerts to prevent alert fatigue.

    Uses a fingerprint based on rule ID and key entities to identify
    duplicate alerts within a time window.
    """

    def __init__(self, window=300, max_size=10000):
        self.window = window  # seconds
        self.max_size = max_size
        self._fingerprints = {}  # fingerprint -> (alert, first_seen, count)
        self._lock = threading.Lock()

    def check(self, alert):
        """Check if an alert is a duplicate.

        Returns:
            (is_duplicate, original_alert_or_None, count)
        """
        fp = self._compute_fingerprint(alert)
        now = datetime.now(timezone.utc)

        with self._lock:
            # Clean expired
            expired = [k for k, (a, ts, c) in self._fingerprints.items()
                       if (now - ts).total_seconds() > self.window]
            for k in expired:
                del self._fingerprints[k]

            if fp in self._fingerprints:
                orig_alert, first_seen, count = self._fingerprints[fp]
                count += 1
                self._fingerprints[fp] = (orig_alert, first_seen, count)
                return True, orig_alert, count
            else:
                self._fingerprints[fp] = (alert, now, 1)
                # Evict if too large
                if len(self._fingerprints) > self.max_size:
                    oldest = min(self._fingerprints, key=lambda k: self._fingerprints[k][1])
                    del self._fingerprints[oldest]
                return False, None, 1

    def _compute_fingerprint(self, alert):
        """Compute a fingerprint for an alert."""
        rule_id = alert.get("rule_id", "") if isinstance(alert, dict) else alert.rule_id
        entities = alert.get("entities", {}) if isinstance(alert, dict) else alert.entities
        entity_str = json.dumps(entities, sort_keys=True, default=str)
        return f"{rule_id}:{hash(entity_str)}"

    def clear(self):
        """Clear all fingerprints."""
        with self._lock:
            self._fingerprints.clear()


class AlertingEngine:
    """Manages alert lifecycle, routing, and notifications.

    Coordinates alert creation, deduplication, storage, notification,
    and escalation.
    """

    def __init__(self, storage=None, config=None):
        self.storage = storage
        self.config = config or {}
        self._channels = {}  # name -> NotificationChannel
        self._deduplicator = AlertDeduplicator(
            window=self.config.get("dedup_window", 300)
        )
        self._lock = threading.RLock()
        self._escalation_policies = {}
        self._alert_handlers = []

        # Alert routing rules: severity -> [channel_names]
        self._routing = self.config.get("routing", {
            "critical": ["console", "webhook", "email", "syslog"],
            "high": ["console", "webhook", "email"],
            "medium": ["console", "webhook"],
            "low": ["console"],
            "info": ["console"],
        })

        # Initialize default channels
        self._init_default_channels()

        self._stats = {
            "alerts_created": 0,
            "alerts_deduplicated": 0,
            "notifications_sent": 0,
            "notification_errors": 0,
        }

    def _init_default_channels(self):
        """Initialize default notification channels."""
        self._channels["console"] = ConsoleNotification("console")
        if self.config.get("webhook_url"):
            self._channels["webhook"] = WebhookNotification(
                "webhook", {"url": self.config["webhook_url"],
                            "auth_token": self.config.get("webhook_token")}
            )
        if self.config.get("email_recipients"):
            self._channels["email"] = EmailNotification(
                "email", {"recipients": self.config["email_recipients"]}
            )
        if self.config.get("syslog_host"):
            self._channels["syslog"] = SyslogNotification(
                "syslog", {"host": self.config["syslog_host"],
                           "port": self.config.get("syslog_port", 514)}
            )

    def add_channel(self, channel):
        """Add a notification channel."""
        self._channels[channel.name] = channel

    def add_handler(self, handler):
        """Add a custom alert handler function."""
        self._alert_handlers.append(handler)

    def handle_alert(self, alert, event=None, rule=None):
        """Handle a new alert.

        This is the main entry point called by rules/correlation engines.
        """
        self._stats["alerts_created"] += 1

        # Check for duplicates
        is_dup, original, count = self._deduplicator.check(alert)
        if is_dup:
            self._stats["alerts_deduplicated"] += 1
            # Merge into original if it exists in storage
            if original and self.storage:
                stored = self.storage.get_alert(original.alert_id if hasattr(original, "alert_id")
                                                 else original.get("alert_id"))
                if stored:
                    logger.debug("Alert deduplicated (count: %d)", count)
            return

        # Store the alert
        if self.storage:
            try:
                self.storage.store_alert(alert)
            except Exception as exc:
                logger.error("Failed to store alert: %s", exc)

        # Route notifications
        self._route_notification(alert)

        # Call custom handlers
        for handler in self._alert_handlers:
            try:
                handler(alert, event, rule)
            except Exception as exc:
                logger.error("Alert handler error: %s", exc)

    def _route_notification(self, alert):
        """Route alert to appropriate notification channels."""
        severity = alert.severity if isinstance(alert, Alert) else alert.get("severity", "medium")
        if isinstance(severity, AlertSeverity):
            severity = severity.to_label().lower()
        severity = str(severity).lower()

        # Map to routing severity
        if severity in ("critical", "5"):
            route_key = "critical"
        elif severity in ("high", "4"):
            route_key = "high"
        elif severity in ("medium", "3"):
            route_key = "medium"
        elif severity in ("low", "2"):
            route_key = "low"
        else:
            route_key = "info"

        channels = self._routing.get(route_key, ["console"])

        for channel_name in channels:
            channel = self._channels.get(channel_name)
            if channel:
                try:
                    message = self._build_message(alert)
                    channel.send(alert, message)
                    self._stats["notifications_sent"] += 1
                except Exception as exc:
                    self._stats["notification_errors"] += 1
                    logger.error("Notification error on channel %s: %s", channel_name, exc)

    def _build_message(self, alert):
        """Build a notification message for an alert."""
        if isinstance(alert, Alert):
            title = alert.title
            sev = alert.severity_label
            rule = alert.rule_name
            desc = alert.description[:200]
        else:
            title = alert.get("title", "Alert")
            sev = alert.get("severity", "medium")
            rule = alert.get("rule_name", "")
            desc = alert.get("description", "")[:200]
        return f"{sev}: {title} (Rule: {rule}) - {desc}"

    def acknowledge_alert(self, alert_id, user, reason=""):
        """Acknowledge an alert."""
        if self.storage:
            alert_data = self.storage.get_alert(alert_id)
            if alert_data:
                alert = Alert.from_dict(alert_data)
                alert.acknowledge(user, reason)
                self.storage.store_alert(alert)
                return alert
        return None

    def resolve_alert(self, alert_id, user, resolution=""):
        """Resolve an alert."""
        if self.storage:
            alert_data = self.storage.get_alert(alert_id)
            if alert_data:
                alert = Alert.from_dict(alert_data)
                alert.resolve(user, resolution)
                self.storage.store_alert(alert)
                return alert
        return None

    def add_escalation_policy(self, name, severity, delay_minutes, escalate_to):
        """Add an escalation policy."""
        self._escalation_policies[name] = {
            "severity": severity,
            "delay_minutes": delay_minutes,
            "escalate_to": escalate_to,
        }

    def check_escalations(self):
        """Check for alerts that need escalation."""
        if not self.storage:
            return 0

        escalated = 0
        now = datetime.now(timezone.utc)

        result = self.storage.query_alerts({"status": "open"}, limit=1000)
        for alert_data in result.get("alerts", []):
            created = alert_data.get("created_at")
            if created:
                try:
                    created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                    age_minutes = (now - created_dt).total_seconds() / 60

                    for policy_name, policy in self._escalation_policies.items():
                        if (alert_data.get("severity") == policy["severity"] and
                            age_minutes > policy["delay_minutes"]):
                            alert = Alert.from_dict(alert_data)
                            alert.escalate("system", f"Auto-escalated by policy {policy_name}")
                            self.storage.store_alert(alert)
                            escalated += 1
                except (ValueError, TypeError):
                    pass

        return escalated

    def get_channel_stats(self):
        """Get statistics for all channels."""
        return {name: ch.get_stats() for name, ch in self._channels.items()}

    def get_stats(self):
        """Get alerting engine statistics."""
        return {
            **self._stats,
            "channels": len(self._channels),
            "dedup_window": self._deduplicator.window,
            "routing": self._routing,
        }

    def reset_stats(self):
        """Reset statistics."""
        self._stats = {
            "alerts_created": 0,
            "alerts_deduplicated": 0,
            "notifications_sent": 0,
            "notification_errors": 0,
        }
