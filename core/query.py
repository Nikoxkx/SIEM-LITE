"""
Query engine: provides search and filtering capabilities for events.

Supports a query DSL with:
- Field-level equality and comparison
- Full-text search
- Range queries
- Logical operators (AND, OR, NOT)
- Time range filtering
- Wildcard and regex matching
- Aggregation queries
"""

import re
import time
import logging
from datetime import datetime, timezone, timedelta
from collections import defaultdict, Counter

from ..utils.time_utils import parse_timestamp, get_time_range
from ..utils.helpers import deep_get

logger = logging.getLogger(__name__)


class Query:
    """Represents a search query.

    Provides a fluent interface for building complex queries.

    Example:
        query = Query() \\
            .field("source_ip").equals("192.168.1.1") \\
            .field("severity").in_(["critical", "high"]) \\
            .time_range("1h") \\
            .limit(100) \\
            .sort("-timestamp")
    """

    def __init__(self):
        self._filters = []  # List of (field, operator, value) tuples
        self._text_search = None
        self._time_range = None
        self._limit = 100
        self._offset = 0
        self._sort = "-timestamp"
        self._fields = None  # Fields to return (None = all)
        self._aggregations = []

    def field(self, field_name):
        """Start a field filter chain."""
        return FieldFilter(self, field_name)

    def add_filter(self, field, operator, value):
        """Add a filter condition."""
        self._filters.append((field, operator, value))
        return self

    def text(self, search_text):
        """Add full-text search."""
        self._text_search = search_text
        return self

    def time_range(self, spec, end=None):
        """Set time range.

        Args:
            spec: Duration ("1h"), relative ("-1h"), or tuple (start, end).
            end: Optional end time.
        """
        tr = get_time_range(spec, end)
        self._time_range = tr
        return self

    def limit(self, n):
        """Set result limit."""
        self._limit = n
        return self

    def offset(self, n):
        """Set result offset."""
        self._offset = n
        return self

    def sort(self, field):
        """Set sort field (prefix with - for descending)."""
        self._sort = field
        return self

    def fields(self, *field_names):
        """Set fields to return."""
        self._fields = list(field_names)
        return self

    def aggregate(self, field, function="count", interval=None):
        """Add an aggregation."""
        self._aggregations.append({
            "field": field,
            "function": function,
            "interval": interval,
        })
        return self

    @property
    def filters(self):
        return self._filters

    @property
    def text_search(self):
        return self._text_search

    @property
    def time_range_spec(self):
        return self._time_range

    @property
    def limit_value(self):
        return self._limit

    @property
    def offset_value(self):
        return self._offset

    @property
    def sort_field(self):
        return self._sort

    @property
    def return_fields(self):
        return self._fields

    @property
    def aggregations(self):
        return self._aggregations

    def to_dict(self):
        """Serialize query to dictionary."""
        return {
            "filters": self._filters,
            "text_search": self._text_search,
            "time_range": {
                "start": self._time_range.start.isoformat() if self._time_range else None,
                "end": self._time_range.end.isoformat() if self._time_range else None,
            },
            "limit": self._limit,
            "offset": self._offset,
            "sort": self._sort,
            "fields": self._fields,
            "aggregations": self._aggregations,
        }

    @classmethod
    def from_dict(cls, data):
        """Create a query from a dictionary."""
        q = cls()
        q._filters = data.get("filters", [])
        q._text_search = data.get("text_search")
        tr = data.get("time_range", {})
        if tr.get("start") or tr.get("end"):
            from ..utils.time_utils import TimeRange
            start = parse_timestamp(tr.get("start")) if tr.get("start") else datetime.now(timezone.utc) - timedelta(hours=1)
            end = parse_timestamp(tr.get("end")) if tr.get("end") else datetime.now(timezone.utc)
            q._time_range = TimeRange(start, end)
        q._limit = data.get("limit", 100)
        q._offset = data.get("offset", 0)
        q._sort = data.get("sort", "-timestamp")
        q._fields = data.get("fields")
        q._aggregations = data.get("aggregations", [])
        return q

    @classmethod
    def parse(cls, query_string):
        """Parse a query string in simple syntax.

        Supported syntax:
            field:value            - field equals value
            field>=value           - comparison
            field:value1,value2    - field in list
            "full text"            - full text search
            -field:value           - NOT field equals value
            field:/regex/          - regex match
        """
        q = cls()
        tokens = cls._tokenize(query_string)

        for token in tokens:
            token = token.strip()
            if not token:
                continue

            # Full text search (quoted)
            if token.startswith('"') and token.endswith('"'):
                q.text(token[1:-1])
                continue

            # NOT prefix
            negate = False
            if token.startswith("-") and ":" in token:
                negate = True
                token = token[1:]

            # Comparison operators
            for op_str, op_name in [(">=", "gte"), ("<=", "lte"), (">", "gt"),
                                      ("<", "lt"), (":", "eq"), ("!=", "ne")]:
                if op_str in token:
                    parts = token.split(op_str, 1)
                    if len(parts) == 2:
                        field, value = parts
                        field = field.strip()
                        value = value.strip()

                        # Handle list values (comma-separated)
                        if "," in value and op_str == ":":
                            values = [v.strip() for v in value.split(",")]
                            q.add_filter(field, "in", values)
                        # Handle regex
                        elif value.startswith("/") and value.endswith("/") and op_str == ":":
                            q.add_filter(field, "regex", value[1:-1])
                        elif negate:
                            q.add_filter(field, "not_eq", value)
                        else:
                            q.add_filter(field, op_name, value)
                        break
            else:
                # No operator found, treat as text search
                q.text(token)

        return q

    @staticmethod
    def _tokenize(query_string):
        """Tokenize a query string, respecting quotes."""
        tokens = []
        current = ""
        in_quotes = False
        for char in query_string:
            if char == '"':
                in_quotes = not in_quotes
                current += char
            elif char == " " and not in_quotes:
                if current:
                    tokens.append(current)
                    current = ""
            else:
                current += char
        if current:
            tokens.append(current)
        return tokens


class FieldFilter:
    """Fluent field filter builder."""

    def __init__(self, query, field_name):
        self._query = query
        self._field = field_name

    def equals(self, value):
        self._query.add_filter(self._field, "eq", value)
        return self._query

    def not_equals(self, value):
        self._query.add_filter(self._field, "ne", value)
        return self._query

    def greater_than(self, value):
        self._query.add_filter(self._field, "gt", value)
        return self._query

    def greater_equal(self, value):
        self._query.add_filter(self._field, "gte", value)
        return self._query

    def less_than(self, value):
        self._query.add_filter(self._field, "lt", value)
        return self._query

    def less_equal(self, value):
        self._query.add_filter(self._field, "lte", value)
        return self._query

    def in_(self, values):
        self._query.add_filter(self._field, "in", values)
        return self._query

    def contains(self, value):
        self._query.add_filter(self._field, "contains", value)
        return self._query

    def startswith(self, value):
        self._query.add_filter(self._field, "startswith", value)
        return self._query

    def endswith(self, value):
        self._query.add_filter(self._field, "endswith", value)
        return self._query

    def regex(self, pattern):
        self._query.add_filter(self._field, "regex", pattern)
        return self._query

    def exists(self):
        self._query.add_filter(self._field, "exists", True)
        return self._query

    def between(self, low, high):
        self._query.add_filter(self._field, "gte", low)
        self._query.add_filter(self._field, "lte", high)
        return self._query


class QueryEngine:
    """Executes queries against the event store.

    Supports filtering, full-text search, sorting, pagination,
    and aggregations.
    """

    def __init__(self, storage=None, config=None):
        self.storage = storage
        self.config = config or {}
        self._stats = {
            "queries_executed": 0,
            "total_results": 0,
            "avg_query_time": 0.0,
        }

    def search(self, query):
        """Execute a query and return results.

        Args:
            query: Query object or query string.

        Returns:
            Dict with events, total, and aggregations.
        """
        if isinstance(query, str):
            query = Query.parse(query)
        elif isinstance(query, dict):
            query = Query.from_dict(query)

        start_time = time.perf_counter()
        self._stats["queries_executed"] += 1

        # Build storage query from Query object
        storage_query = self._build_storage_query(query)

        # Execute query
        if self.storage:
            result = self.storage.query_events(
                query=storage_query,
                limit=query.limit_value,
                offset=query.offset_value,
                sort=query.sort_field,
            )
        else:
            result = {"events": [], "total": 0}

        # Apply text search if specified
        if query.text_search:
            result["events"] = self._apply_text_search(result["events"], query.text_search)
            result["total"] = len(result["events"])

        # Apply field projection
        if query.return_fields:
            result["events"] = self._project_fields(result["events"], query.return_fields)

        # Compute aggregations
        if query.aggregations:
            result["aggregations"] = self._compute_aggregations(result["events"], query.aggregations)

        elapsed = time.perf_counter() - start_time
        self._stats["total_results"] += result.get("total", 0)
        self._stats["avg_query_time"] = self._stats["avg_query_time"] * 0.9 + elapsed * 0.1

        result["query_time"] = elapsed
        return result

    def _build_storage_query(self, query):
        """Convert Query object to storage filter dict."""
        storage_query = {}

        for field, operator, value in query.filters:
            if operator == "eq":
                storage_query[field] = value
            elif operator == "ne":
                storage_query[field] = {"$ne": value}
            elif operator == "in":
                storage_query[field] = list(value)
            elif operator == "contains":
                storage_query[field] = {"$contains": value}
            elif operator == "regex":
                storage_query[field] = {"$regex": value}
            elif operator == "gt":
                storage_query[field] = {"$gt": value}
            elif operator == "gte":
                storage_query[field] = {"$gte": value}
            elif operator == "lt":
                storage_query[field] = {"$lt": value}
            elif operator == "lte":
                storage_query[field] = {"$lte": value}

        # Add time range
        if query.time_range_spec:
            storage_query["time_range"] = {
                "start": query.time_range_spec.start,
                "end": query.time_range_spec.end,
            }

        return storage_query

    def _apply_text_search(self, events, text):
        """Apply full-text search to results."""
        text_lower = text.lower()
        results = []
        for event in events:
            # Search in key fields
            searchable = " ".join(str(v) for v in [
                event.get("message", ""),
                event.get("raw_data", ""),
                event.get("source_ip", ""),
                event.get("dest_ip", ""),
                event.get("source_user", ""),
                event.get("action", ""),
                event.get("product", ""),
                event.get("file_name", ""),
                event.get("process_name", ""),
                event.get("command_line", ""),
            ] if v)
            if text_lower in searchable.lower():
                results.append(event)
        return results

    def _project_fields(self, events, fields):
        """Project only specified fields."""
        return [{f: e.get(f) for f in fields if f in e} for e in events]

    def _compute_aggregations(self, events, aggregations):
        """Compute aggregation results."""
        results = {}
        for agg in aggregations:
            field = agg["field"]
            func = agg["function"]

            if func == "count":
                counts = Counter()
                for event in events:
                    val = event.get(field)
                    if val is not None:
                        counts[str(val)] += 1
                results[f"{field}_{func}"] = dict(counts.most_common(20))

            elif func == "sum":
                total = sum(float(e.get(field, 0) or 0) for e in events)
                results[f"{field}_{func}"] = total

            elif func == "avg":
                values = [float(e.get(field, 0) or 0) for e in events if e.get(field) is not None]
                results[f"{field}_{func}"] = sum(values) / len(values) if values else 0

            elif func == "min":
                values = [float(e.get(field) or 0) for e in events if e.get(field) is not None]
                results[f"{field}_{func}"] = min(values) if values else None

            elif func == "max":
                values = [float(e.get(field) or 0) for e in events if e.get(field) is not None]
                results[f"{field}_{func}"] = max(values) if values else None

            elif func == "cardinality":
                unique = set(str(e.get(field)) for e in events if e.get(field) is not None)
                results[f"{field}_{func}"] = len(unique)

        return results

    def count(self, query):
        """Count events matching a query."""
        if isinstance(query, str):
            query = Query.parse(query)
        if self.storage:
            storage_query = self._build_storage_query(query)
            return self.storage.count_events(storage_query)
        return 0

    def histogram(self, field, interval=3600, duration=86400, query=None):
        """Generate a time histogram.

        Args:
            field: Field to histogram (usually "timestamp").
            interval: Bucket size in seconds.
            duration: Duration to look back.
            query: Optional additional query filters.

        Returns:
            List of (timestamp, count) tuples.
        """
        from ..utils.time_utils import floor_to_interval

        if query is None:
            query = Query()
        query.time_range(f"{duration}s")

        result = self.search(query)
        events = result.get("events", [])

        histogram = defaultdict(int)
        for event in events:
            ts = event.get(field)
            if ts:
                if isinstance(ts, str):
                    ts = parse_timestamp(ts)
                if ts:
                    bucket = floor_to_interval(ts, interval)
                    histogram[bucket] += 1

        return sorted(histogram.items())

    def top_values(self, field, limit=10, query=None):
        """Get top values for a field."""
        if query is None:
            query = Query()
        result = self.search(query.limit(10000))
        events = result.get("events", [])

        counts = Counter()
        for event in events:
            val = event.get(field)
            if val is not None:
                counts[str(val)] += 1

        return counts.most_common(limit)

    def get_stats(self):
        """Get query engine statistics."""
        return dict(self._stats)

    def reset_stats(self):
        """Reset statistics."""
        self._stats = {
            "queries_executed": 0,
            "total_results": 0,
            "avg_query_time": 0.0,
        }
