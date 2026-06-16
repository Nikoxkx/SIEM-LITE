"""
Storage backends for persisting events, alerts, and other data.

Provides pluggable storage backends:
- InMemoryBackend: Fast in-memory storage (no persistence)
- SQLiteBackend: Persistent storage using SQLite
- FileBackend: Append-only file-based storage

All backends implement the same interface for storing and querying events.
"""

import os
import json
import time
import sqlite3
import hashlib
import logging
import threading
from datetime import datetime, timezone, timedelta
from collections import deque, defaultdict

from ..models.event import Event
from ..models.alert import Alert
from ..utils.time_utils import parse_timestamp, to_epoch

logger = logging.getLogger(__name__)


class StorageBackend:
    """Abstract storage backend interface."""

    def __init__(self, config=None):
        self.config = config or {}

    def store_event(self, event):
        """Store an event."""
        raise NotImplementedError

    def store_events(self, events):
        """Store multiple events (batch)."""
        for event in events:
            self.store_event(event)

    def get_event(self, event_id):
        """Retrieve an event by ID."""
        raise NotImplementedError

    def query_events(self, query=None, limit=100, offset=0, sort=None):
        """Query events with optional filtering."""
        raise NotImplementedError

    def count_events(self, query=None):
        """Count events matching a query."""
        raise NotImplementedError

    def delete_event(self, event_id):
        """Delete an event."""
        raise NotImplementedError

    def delete_old_events(self, max_age_days):
        """Delete events older than max_age_days."""
        raise NotImplementedError

    def store_alert(self, alert):
        """Store an alert."""
        raise NotImplementedError

    def get_alert(self, alert_id):
        """Retrieve an alert by ID."""
        raise NotImplementedError

    def query_alerts(self, query=None, limit=100, offset=0):
        """Query alerts."""
        raise NotImplementedError

    def get_stats(self):
        """Get storage statistics."""
        raise NotImplementedError

    def close(self):
        """Clean up resources."""
        pass


class InMemoryBackend(StorageBackend):
    """Fast in-memory storage backend.

    Uses a deque with configurable max size for events and a dict index
    for fast lookups. Also maintains secondary indexes on common fields.
    """

    def __init__(self, config=None):
        super().__init__(config)
        self._max_events = config.get("max_events", 100000) if config else 100000
        self._events = deque(maxlen=self._max_events)
        self._event_index = {}  # event_id -> event dict
        self._alerts = {}
        self._lock = threading.RLock()

        # Secondary indexes
        self._index_by_source_ip = defaultdict(list)
        self._index_by_dest_ip = defaultdict(list)
        self._index_by_severity = defaultdict(list)
        self._index_by_event_type = defaultdict(list)

        self._stats = {
            "events_stored": 0,
            "events_dropped": 0,
            "alerts_stored": 0,
            "queries": 0,
        }

    def store_event(self, event):
        """Store an event in memory."""
        with self._lock:
            if isinstance(event, Event):
                event_dict = event.to_dict()
            else:
                event_dict = event

            event_id = event_dict.get("event_id")
            if not event_id:
                return

            # Check if we're evicting
            if len(self._events) >= self._max_events:
                self._stats["events_dropped"] += 1
                old = self._events[0]
                if isinstance(old, dict) and "event_id" in old:
                    old_id = old["event_id"]
                    self._event_index.pop(old_id, None)

            self._events.append(event_dict)
            self._event_index[event_id] = event_dict

            # Update indexes
            src_ip = event_dict.get("source_ip")
            if src_ip:
                self._index_by_source_ip[src_ip].append(event_id)
            dst_ip = event_dict.get("dest_ip")
            if dst_ip:
                self._index_by_dest_ip[dst_ip].append(event_id)
            severity = event_dict.get("severity")
            if severity:
                self._index_by_severity[severity].append(event_id)
            event_type = event_dict.get("event_type")
            if event_type:
                self._index_by_event_type[event_type].append(event_id)

            self._stats["events_stored"] += 1

    def store_events(self, events):
        """Store multiple events."""
        with self._lock:
            for event in events:
                self.store_event(event)

    def get_event(self, event_id):
        """Get an event by ID."""
        with self._lock:
            self._stats["queries"] += 1
            return self._event_index.get(event_id)

    def query_events(self, query=None, limit=100, offset=0, sort=None):
        """Query events with filtering."""
        with self._lock:
            self._stats["queries"] += 1
            events = list(self._events)

        # Apply query filter
        if query:
            events = [e for e in events if self._matches_query(e, query)]

        # Apply sorting
        if sort:
            reverse = sort.startswith("-")
            sort_field = sort.lstrip("-+")
            events.sort(
                key=lambda e: (e.get(sort_field) is None, str(e.get(sort_field, "")).lower()),
                reverse=reverse
            )

        # Apply pagination
        total = len(events)
        events = events[offset:offset + limit]

        return {
            "events": events,
            "total": total,
            "limit": limit,
            "offset": offset,
        }

    def _matches_query(self, event, query):
        """Check if event matches query filter."""
        if not query:
            return True
        for field, expected in query.items():
            if field == "time_range":
                continue
            if field == "severity_min":
                sev_order = {"debug": 0, "info": 1, "notice": 2, "warning": 3,
                             "error": 4, "critical": 5, "alert": 6, "emergency": 7,
                             "low": 3, "medium": 4, "high": 5}
                event_sev = sev_order.get(event.get("severity", "info"), 1)
                if event_sev < sev_order.get(expected, 0):
                    return False
                continue
            actual = event.get(field)
            if isinstance(expected, list):
                if actual not in expected:
                    return False
            elif isinstance(expected, dict):
                if "$contains" in expected and expected["$contains"] not in str(actual or ""):
                    return False
                elif "$regex" in expected:
                    import re
                    if not re.search(expected["$regex"], str(actual or "")):
                        return False
            elif actual != expected:
                return False
        return True

    def count_events(self, query=None):
        """Count matching events."""
        with self._lock:
            events = list(self._events)
        if query:
            events = [e for e in events if self._matches_query(e, query)]
        return len(events)

    def delete_event(self, event_id):
        """Delete an event."""
        with self._lock:
            if event_id in self._event_index:
                event_dict = self._event_index.pop(event_id)
                try:
                    self._events.remove(event_dict)
                except ValueError:
                    pass
                return True
            return False

    def delete_old_events(self, max_age_days):
        """Delete events older than max_age_days."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)
        cutoff_epoch = to_epoch(cutoff)
        removed = 0
        with self._lock:
            new_events = deque(maxlen=self._max_events)
            for event_dict in self._events:
                ts = event_dict.get("timestamp")
                if ts:
                    try:
                        event_epoch = to_epoch(parse_timestamp(ts)) if isinstance(ts, str) else to_epoch(ts)
                        if event_epoch < cutoff_epoch:
                            self._event_index.pop(event_dict.get("event_id"), None)
                            removed += 1
                            continue
                    except (ValueError, TypeError):
                        pass
                new_events.append(event_dict)
            self._events = new_events
        return removed

    def store_alert(self, alert):
        """Store an alert."""
        with self._lock:
            if isinstance(alert, Alert):
                self._alerts[alert.alert_id] = alert.to_dict()
            else:
                self._alerts[alert.get("alert_id")] = alert
            self._stats["alerts_stored"] += 1

    def get_alert(self, alert_id):
        """Get an alert by ID."""
        with self._lock:
            return self._alerts.get(alert_id)

    def query_alerts(self, query=None, limit=100, offset=0):
        """Query alerts."""
        with self._lock:
            alerts = list(self._alerts.values())
        if query:
            alerts = [a for a in alerts if self._matches_query(a, query)]
        total = len(alerts)
        alerts = sorted(alerts, key=lambda a: a.get("created_at", ""), reverse=True)
        alerts = alerts[offset:offset + limit]
        return {"alerts": alerts, "total": total, "limit": limit, "offset": offset}

    def get_stats(self):
        """Get storage statistics."""
        with self._lock:
            return {
                **self._stats,
                "current_events": len(self._events),
                "current_alerts": len(self._alerts),
                "max_events": self._max_events,
                "backend": "memory",
            }

    def clear(self):
        """Clear all stored data."""
        with self._lock:
            self._events.clear()
            self._event_index.clear()
            self._alerts.clear()
            self._index_by_source_ip.clear()
            self._index_by_dest_ip.clear()
            self._index_by_severity.clear()
            self._index_by_event_type.clear()


class SQLiteBackend(StorageBackend):
    """SQLite-based persistent storage backend.

    Stores events and alerts in SQLite databases with full-text search
    and efficient indexing.
    """

    SCHEMA_EVENTS = """
    CREATE TABLE IF NOT EXISTS events (
        event_id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        ingest_time TEXT,
        event_type TEXT,
        severity TEXT,
        source_ip TEXT,
        source_port INTEGER,
        source_host TEXT,
        source_user TEXT,
        dest_ip TEXT,
        dest_port INTEGER,
        dest_host TEXT,
        dest_user TEXT,
        protocol TEXT,
        action TEXT,
        result TEXT,
        product TEXT,
        vendor TEXT,
        message TEXT,
        category TEXT,
        risk_score REAL,
        rule_id TEXT,
        source_country TEXT,
        dest_country TEXT,
        source_is_internal INTEGER,
        dest_is_internal INTEGER,
        ioc_matched TEXT,
        source_log TEXT,
        raw_data TEXT,
        full_data TEXT
    );
    """

    SCHEMA_INDEXES = """
    CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
    CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);
    CREATE INDEX IF NOT EXISTS idx_events_dest_ip ON events(dest_ip);
    CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
    CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
    CREATE INDEX IF NOT EXISTS idx_events_action ON events(action);
    CREATE INDEX IF NOT EXISTS idx_events_rule ON events(rule_id);
    """

    SCHEMA_ALERTS = """
    CREATE TABLE IF NOT EXISTS alerts (
        alert_id TEXT PRIMARY KEY,
        title TEXT,
        severity TEXT,
        status TEXT,
        rule_id TEXT,
        rule_name TEXT,
        created_at TEXT,
        updated_at TEXT,
        risk_score REAL,
        source_events TEXT,
        data TEXT
    );
    """

    SCHEMA_ALERT_INDEXES = """
    CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);
    CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
    CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
    """

    def __init__(self, db_path="siem.db", config=None):
        super().__init__(config)
        self.db_path = db_path
        self._lock = threading.RLock()
        self._conn = None
        self._connect()
        self._init_schema()
        self._stats = {
            "events_stored": 0,
            "events_queried": 0,
            "alerts_stored": 0,
        }

    def _connect(self):
        """Connect to the SQLite database."""
        # Create directory if needed
        db_dir = os.path.dirname(self.db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)

        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA cache_size=-64000")  # 64MB cache
        logger.info("SQLite backend connected to %s", self.db_path)

    def _init_schema(self):
        """Initialize database schema."""
        with self._lock:
            cursor = self._conn.cursor()
            cursor.executescript(self.SCHEMA_EVENTS)
            cursor.executescript(self.SCHEMA_INDEXES)
            cursor.executescript(self.SCHEMA_ALERTS)
            cursor.executescript(self.SCHEMA_ALERT_INDEXES)
            self._conn.commit()

    def store_event(self, event):
        """Store an event."""
        with self._lock:
            if isinstance(event, Event):
                event_dict = event.to_dict()
            else:
                event_dict = event

            event_id = event_dict.get("event_id")
            if not event_id:
                return

            cursor = self._conn.cursor()
            try:
                cursor.execute("""
                    INSERT OR REPLACE INTO events
                    (event_id, timestamp, ingest_time, event_type, severity,
                     source_ip, source_port, source_host, source_user,
                     dest_ip, dest_port, dest_host, dest_user,
                     protocol, action, result, product, vendor,
                     message, category, risk_score, rule_id,
                     source_country, dest_country, source_is_internal, dest_is_internal,
                     ioc_matched, source_log, raw_data, full_data)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, (
                    event_id,
                    self._serialize_ts(event_dict.get("timestamp")),
                    self._serialize_ts(event_dict.get("ingest_time")),
                    event_dict.get("event_type"),
                    event_dict.get("severity"),
                    event_dict.get("source_ip"),
                    event_dict.get("source_port"),
                    event_dict.get("source_host"),
                    event_dict.get("source_user"),
                    event_dict.get("dest_ip"),
                    event_dict.get("dest_port"),
                    event_dict.get("dest_host"),
                    event_dict.get("dest_user"),
                    event_dict.get("protocol"),
                    event_dict.get("action"),
                    event_dict.get("result"),
                    event_dict.get("product"),
                    event_dict.get("vendor"),
                    event_dict.get("message"),
                    event_dict.get("category"),
                    event_dict.get("risk_score", 0),
                    event_dict.get("rule_id"),
                    event_dict.get("source_country"),
                    event_dict.get("dest_country"),
                    1 if event_dict.get("source_is_internal") else 0,
                    1 if event_dict.get("dest_is_internal") else 0,
                    event_dict.get("ioc_matched"),
                    event_dict.get("source_log"),
                    event_dict.get("raw_data"),
                    json.dumps(event_dict, default=str),
                ))
                self._conn.commit()
                self._stats["events_stored"] += 1
            except sqlite3.Error as exc:
                logger.error("Failed to store event %s: %s", event_id, exc)

    @staticmethod
    def _serialize_ts(ts):
        """Serialize timestamp for SQLite."""
        if ts is None:
            return None
        if isinstance(ts, str):
            return ts
        if isinstance(ts, datetime):
            return ts.isoformat()
        return str(ts)

    def store_events(self, events):
        """Batch store events."""
        with self._lock:
            cursor = self._conn.cursor()
            for event in events:
                if isinstance(event, Event):
                    event_dict = event.to_dict()
                else:
                    event_dict = event

                event_id = event_dict.get("event_id")
                if not event_id:
                    continue

                try:
                    cursor.execute("""
                        INSERT OR REPLACE INTO events
                        (event_id, timestamp, ingest_time, event_type, severity,
                         source_ip, source_port, source_host, source_user,
                         dest_ip, dest_port, dest_host, dest_user,
                         protocol, action, result, product, vendor,
                         message, category, risk_score, rule_id,
                         source_country, dest_country, source_is_internal, dest_is_internal,
                         ioc_matched, source_log, raw_data, full_data)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """, (
                        event_id, self._serialize_ts(event_dict.get("timestamp")),
                        self._serialize_ts(event_dict.get("ingest_time")),
                        event_dict.get("event_type"), event_dict.get("severity"),
                        event_dict.get("source_ip"), event_dict.get("source_port"),
                        event_dict.get("source_host"), event_dict.get("source_user"),
                        event_dict.get("dest_ip"), event_dict.get("dest_port"),
                        event_dict.get("dest_host"), event_dict.get("dest_user"),
                        event_dict.get("protocol"), event_dict.get("action"),
                        event_dict.get("result"), event_dict.get("product"),
                        event_dict.get("vendor"), event_dict.get("message"),
                        event_dict.get("category"), event_dict.get("risk_score", 0),
                        event_dict.get("rule_id"), event_dict.get("source_country"),
                        event_dict.get("dest_country"),
                        1 if event_dict.get("source_is_internal") else 0,
                        1 if event_dict.get("dest_is_internal") else 0,
                        event_dict.get("ioc_matched"), event_dict.get("source_log"),
                        event_dict.get("raw_data"), json.dumps(event_dict, default=str),
                    ))
                    self._stats["events_stored"] += 1
                except sqlite3.Error as exc:
                    logger.debug("Batch store error for %s: %s", event_id, exc)
            self._conn.commit()

    def get_event(self, event_id):
        """Get event by ID."""
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute("SELECT full_data FROM events WHERE event_id = ?", (event_id,))
            row = cursor.fetchone()
            if row:
                self._stats["events_queried"] += 1
                return json.loads(row["full_data"])
            return None

    def query_events(self, query=None, limit=100, offset=0, sort=None):
        """Query events with SQL-based filtering."""
        with self._lock:
            where_clauses = []
            params = []

            if query:
                for field, value in query.items():
                    if field in ("time_range",):
                        continue
                    col = field
                    if isinstance(value, list):
                        placeholders = ",".join("?" * len(value))
                        where_clauses.append(f"{col} IN ({placeholders})")
                        params.extend(value)
                    elif isinstance(value, dict):
                        if "$contains" in value:
                            where_clauses.append(f"{col} LIKE ?")
                            params.append(f"%{value['$contains']}%")
                    else:
                        where_clauses.append(f"{col} = ?")
                        params.append(value)

            where_sql = " WHERE " + " AND ".join(where_clauses) if where_clauses else ""

            sort_sql = ""
            if sort:
                reverse = sort.startswith("-")
                sort_field = sort.lstrip("-+")
                valid_sort = {"timestamp", "severity", "risk_score", "source_ip", "event_type"}
                if sort_field in valid_sort:
                    sort_sql = f" ORDER BY {sort_field} {'DESC' if reverse else 'ASC'}"
            else:
                sort_sql = " ORDER BY timestamp DESC"

            # Get total count
            cursor = self._conn.cursor()
            cursor.execute(f"SELECT COUNT(*) as cnt FROM events{where_sql}", params)
            total = cursor.fetchone()["cnt"]

            # Get events
            cursor.execute(
                f"SELECT full_data FROM events{where_sql}{sort_sql} LIMIT ? OFFSET ?",
                params + [limit, offset]
            )
            rows = cursor.fetchall()
            events = [json.loads(row["full_data"]) for row in rows]
            self._stats["events_queried"] += len(events)

            return {
                "events": events,
                "total": total,
                "limit": limit,
                "offset": offset,
            }

    def count_events(self, query=None):
        """Count events."""
        with self._lock:
            where_clauses = []
            params = []
            if query:
                for field, value in query.items():
                    if isinstance(value, list):
                        placeholders = ",".join("?" * len(value))
                        where_clauses.append(f"{field} IN ({placeholders})")
                        params.extend(value)
                    else:
                        where_clauses.append(f"{field} = ?")
                        params.append(value)
            where_sql = " WHERE " + " AND ".join(where_clauses) if where_clauses else ""
            cursor = self._conn.cursor()
            cursor.execute(f"SELECT COUNT(*) as cnt FROM events{where_sql}", params)
            return cursor.fetchone()["cnt"]

    def delete_event(self, event_id):
        """Delete an event."""
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute("DELETE FROM events WHERE event_id = ?", (event_id,))
            self._conn.commit()
            return cursor.rowcount > 0

    def delete_old_events(self, max_age_days):
        """Delete events older than max_age_days."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=max_age_days)).isoformat()
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute("DELETE FROM events WHERE timestamp < ?", (cutoff,))
            self._conn.commit()
            return cursor.rowcount

    def store_alert(self, alert):
        """Store an alert."""
        with self._lock:
            if isinstance(alert, Alert):
                alert_dict = alert.to_dict()
            else:
                alert_dict = alert

            cursor = self._conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO alerts
                (alert_id, title, severity, status, rule_id, rule_name,
                 created_at, updated_at, risk_score, source_events, data)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
            """, (
                alert_dict.get("alert_id"),
                alert_dict.get("title"),
                alert_dict.get("severity"),
                alert_dict.get("status"),
                alert_dict.get("rule_id"),
                alert_dict.get("rule_name"),
                alert_dict.get("created_at"),
                alert_dict.get("updated_at"),
                alert_dict.get("risk_score", 0),
                json.dumps(alert_dict.get("source_events", [])),
                json.dumps(alert_dict, default=str),
            ))
            self._conn.commit()
            self._stats["alerts_stored"] += 1

    def get_alert(self, alert_id):
        """Get alert by ID."""
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute("SELECT data FROM alerts WHERE alert_id = ?", (alert_id,))
            row = cursor.fetchone()
            if row:
                return json.loads(row["data"])
            return None

    def query_alerts(self, query=None, limit=100, offset=0):
        """Query alerts."""
        with self._lock:
            where_clauses = []
            params = []
            if query:
                for field, value in query.items():
                    where_clauses.append(f"{field} = ?")
                    params.append(value)
            where_sql = " WHERE " + " AND ".join(where_clauses) if where_clauses else ""
            cursor = self._conn.cursor()
            cursor.execute(f"SELECT COUNT(*) as cnt FROM alerts{where_sql}", params)
            total = cursor.fetchone()["cnt"]
            cursor.execute(
                f"SELECT data FROM alerts{where_sql} ORDER BY created_at DESC LIMIT ? OFFSET ?",
                params + [limit, offset]
            )
            rows = cursor.fetchall()
            alerts = [json.loads(row["data"]) for row in rows]
            return {"alerts": alerts, "total": total, "limit": limit, "offset": offset}

    def get_stats(self):
        """Get storage statistics."""
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute("SELECT COUNT(*) as cnt FROM events")
            event_count = cursor.fetchone()["cnt"]
            cursor.execute("SELECT COUNT(*) as cnt FROM alerts")
            alert_count = cursor.fetchone()["cnt"]

            # Get DB file size
            db_size = 0
            if os.path.exists(self.db_path):
                db_size = os.path.getsize(self.db_path)

            return {
                **self._stats,
                "current_events": event_count,
                "current_alerts": alert_count,
                "db_size_bytes": db_size,
                "backend": "sqlite",
                "db_path": self.db_path,
            }

    def close(self):
        """Close the database connection."""
        with self._lock:
            if self._conn:
                self._conn.close()
                self._conn = None
                logger.info("SQLite backend closed")
