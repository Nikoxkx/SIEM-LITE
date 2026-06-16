"""
HTTP and webhook collectors.

HTTPCollector polls an HTTP endpoint for logs.
WebhookCollector receives logs pushed to an HTTP endpoint.
"""

import json
import time
import logging
import threading
from datetime import datetime, timezone
from .base import BaseCollector, CollectorResult

logger = logging.getLogger(__name__)


class HTTPCollector(BaseCollector):
    """Collector that polls an HTTP endpoint for log data.

    Supports:
    - GET polling with configurable interval
    - Various response formats (JSON, plain text, NDJSON)
    - Authentication (basic, bearer, API key)
    - Custom headers and query parameters
    - Pagination via cursor or offset
    """

    def __init__(self, name, url, method="GET", interval=30, headers=None,
                 auth=None, params=None, body=None, response_format="json",
                 data_path=None, cursor_field=None, config=None):
        super().__init__(name=name, source=f"http://{url}", config=config or {})
        self.url = url
        self.method = method.upper()
        self.interval = interval
        self.headers = headers or {"Content-Type": "application/json", "Accept": "application/json"}
        self.params = params or {}
        self.body = body
        self.response_format = response_format  # json, ndjson, text
        self.data_path = data_path  # JSON path to log data array
        self.cursor_field = cursor_field
        self._cursor = None
        self._last_timestamp = None

        # Parse auth
        self.auth_type = None
        self.auth_value = None
        if auth:
            if isinstance(auth, dict):
                self.auth_type = auth.get("type", "bearer")
                if auth.get("type") == "basic":
                    import base64
                    cred = f"{auth.get('username', '')}:{auth.get('password', '')}"
                    self.auth_value = f"Basic {base64.b64encode(cred.encode()).decode()}"
                elif auth.get("type") == "api_key":
                    self.auth_value = auth.get("key", "")
                    self._api_key_header = auth.get("header", "X-API-Key")
                else:
                    self.auth_value = f"Bearer {auth.get('token', '')}"
            elif isinstance(auth, str):
                self.auth_type = "bearer"
                self.auth_value = f"Bearer {auth}"

    def _build_headers(self):
        """Build request headers with auth."""
        headers = dict(self.headers)
        if self.auth_value:
            if self.auth_type == "api_key":
                headers[self._api_key_header] = self.auth_value
            else:
                headers["Authorization"] = self.auth_value
        return headers

    def _build_params(self):
        """Build query parameters with cursor."""
        params = dict(self.params)
        if self.cursor and self.cursor_field:
            params[self.cursor_field] = self.cursor
        if self._last_timestamp:
            params.setdefault("since", self._last_timestamp)
        return params

    def collect(self):
        """Poll the HTTP endpoint."""
        try:
            import urllib.request
            import urllib.error
            import urllib.parse
        except ImportError:
            return CollectorResult(success=False, error="urllib not available")

        params = self._build_params()
        url = self.url
        if params:
            url += "?" + urllib.parse.urlencode(params)

        headers = self._build_headers()
        req = urllib.request.Request(url, method=self.method, headers=headers)

        if self.body and self.method in ("POST", "PUT", "PATCH"):
            if isinstance(self.body, dict):
                req.data = json.dumps(self.body).encode("utf-8")
            else:
                req.data = str(self.body).encode("utf-8")

        try:
            with urllib.request.urlopen(req, timeout=self.config.get("timeout", 30)) as response:
                status = response.getcode()
                if status >= 400:
                    return CollectorResult(success=False,
                                          error=f"HTTP {status}: {response.read().decode('utf-8', errors='replace')[:500]}")
                raw_response = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            return CollectorResult(success=False, error=f"HTTP Error {exc.code}: {exc.reason}")
        except urllib.error.URLError as exc:
            return CollectorResult(success=False, error=f"URL Error: {exc.reason}")
        except Exception as exc:
            return CollectorResult(success=False, error=str(exc))

        events_collected = 0
        bytes_collected = len(raw_response)

        # Parse response
        if self.response_format == "json":
            try:
                data = json.loads(raw_response)
            except json.JSONDecodeError as exc:
                return CollectorResult(success=False, error=f"JSON decode error: {exc}")

            # Extract data array if path specified
            if self.data_path:
                from ..utils.helpers import deep_get
                items = deep_get(data, self.data_path, [])
            elif isinstance(data, list):
                items = data
            elif isinstance(data, dict) and "events" in data:
                items = data["events"]
            elif isinstance(data, dict) and "data" in data:
                items = data["data"]
            elif isinstance(data, dict) and "logs" in data:
                items = data["logs"]
            else:
                items = [data]

            for item in items:
                if isinstance(item, dict):
                    item_str = json.dumps(item)
                else:
                    item_str = str(item)

                metadata = {
                    "source_url": self.url,
                    "collection_method": "http_poll",
                }

                # Update cursor
                if isinstance(item, dict) and self.cursor_field:
                    self._cursor = item.get(self.cursor_field, self._cursor)
                    if "timestamp" in item:
                        self._last_timestamp = item["timestamp"]

                self._emit(item_str, metadata)
                events_collected += 1

        elif self.response_format == "ndjson":
            for line in raw_response.strip().split("\n"):
                line = line.strip()
                if line:
                    self._emit(line, {"source_url": self.url, "collection_method": "http_poll"})
                    events_collected += 1
        else:
            # Plain text
            for line in raw_response.strip().split("\n"):
                line = line.strip()
                if line:
                    self._emit(line, {"source_url": self.url, "collection_method": "http_poll"})
                    events_collected += 1

        self._stats["events_collected"] += events_collected
        self._stats["bytes_collected"] += bytes_collected
        self._stats["last_collection"] = datetime.now(timezone.utc).isoformat()

        return CollectorResult(success=True, events_collected=events_collected,
                               bytes_collected=bytes_collected)


class WebhookCollector(BaseCollector):
    """Collector that receives logs via HTTP webhook.

    This collector doesn't poll; instead, it provides a method to inject
    data received from external HTTP endpoints.
    """

    def __init__(self, name="webhook", config=None):
        super().__init__(name=name, source="webhook://incoming", config=config or {})
        self._received_count = 0

    def collect(self):
        """No-op for webhook collectors."""
        return CollectorResult(success=True, events_collected=0)

    def receive(self, raw_data, metadata=None):
        """Receive data from a webhook POST.

        Args:
            raw_data: The raw data (string, dict, or bytes).
            metadata: Additional metadata about the submission.
        """
        if metadata is None:
            metadata = {}

        if isinstance(raw_data, dict):
            raw_data = json.dumps(raw_data)
        elif isinstance(raw_data, bytes):
            raw_data = raw_data.decode("utf-8", errors="replace")

        # Handle batch submissions
        lines = raw_data.strip().split("\n") if "\n" in raw_data else [raw_data]

        events = 0
        for line in lines:
            line = line.strip()
            if line:
                self._emit(line, {**metadata, "collection_method": "webhook"})
                events += 1

        self._received_count += events
        self._stats["events_collected"] += events
        self._stats["bytes_collected"] += len(raw_data)
        self._stats["last_collection"] = datetime.now(timezone.utc).isoformat()

        return events

    def _run_loop(self):
        """Webhook collector doesn't run a polling loop."""
        self.status = CollectorStatus.RUNNING
        logger.info("Webhook collector %s ready to receive data", self.name)
        while not self._stop_event.is_set():
            self._stop_event.wait(1.0)
        self.status = CollectorStatus.STOPPED
