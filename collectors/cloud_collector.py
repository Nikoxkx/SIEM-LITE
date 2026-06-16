"""
Cloud log collectors for AWS CloudTrail, CloudWatch, and Google Cloud.

These collectors poll cloud APIs for log events. In production, they would
use the cloud SDKs; here they simulate the collection interface with
optional real API support if credentials are configured.
"""

import os
import json
import time
import hmac
import hashlib
import logging
import urllib.request
import urllib.parse
from datetime import datetime, timezone, timedelta
from .base import BaseCollector, CollectorResult

logger = logging.getLogger(__name__)


class CloudTrailCollector(BaseCollector):
    """Collector for AWS CloudTrail logs.

    Polls CloudTrail for new events. In production, uses boto3;
    here provides the interface with optional real API support.
    """

    def __init__(self, name="cloudtrail", region="us-east-1",
                 access_key=None, secret_key=None, session_token=None,
                 event_categories=None, config=None):
        super().__init__(name=name, source=f"aws:cloudtrail:{region}",
                         config=config or {})
        self.region = region
        self.access_key = access_key or os.environ.get("AWS_ACCESS_KEY_ID")
        self.secret_key = secret_key or os.environ.get("AWS_SECRET_ACCESS_KEY")
        self.session_token = session_token or os.environ.get("AWS_SESSION_TOKEN")
        self.event_categories = event_categories or ["Management", "Data"]
        self._last_lookup_time = datetime.now(timezone.utc) - timedelta(minutes=5)
        self._use_boto3 = False

        try:
            import boto3  # noqa: F401
            self._use_boto3 = True
            logger.info("CloudTrail collector using boto3")
        except ImportError:
            logger.info("boto3 not available; CloudTrail collector in simulation mode")

    def collect(self):
        """Collect CloudTrail events."""
        if self._use_boto3 and self.access_key:
            return self._collect_with_boto3()
        else:
            return self._collect_simulated()

    def _collect_with_boto3(self):
        """Collect using boto3 SDK."""
        try:
            import boto3

            client = boto3.client(
                "cloudtrail",
                region_name=self.region,
                aws_access_key_id=self.access_key,
                aws_secret_access_key=self.secret_key,
                aws_session_token=self.session_token,
            )

            events_collected = 0
            bytes_collected = 0

            for category in self.event_categories:
                response = client.lookup_events(
                    LookupAttributes=[],
                    MaxResults=50,
                    StartTime=self._last_lookup_time,
                    EndTime=datetime.now(timezone.utc),
                    EventCategory=category,
                )

                for event in response.get("Events", []):
                    event_json = json.dumps(event, default=str)
                    metadata = {
                        "cloud_provider": "aws",
                        "region": self.region,
                        "event_category": category,
                        "collection_method": "cloudtrail_api",
                    }
                    self._emit(event_json, metadata)
                    events_collected += 1
                    bytes_collected += len(event_json)

            self._last_lookup_time = datetime.now(timezone.utc)
            self._stats["events_collected"] += events_collected
            self._stats["bytes_collected"] += bytes_collected

            return CollectorResult(success=True, events_collected=events_collected,
                                   bytes_collected=bytes_collected)

        except Exception as exc:
            logger.error("CloudTrail collection error: %s", exc)
            return CollectorResult(success=False, error=str(exc))

    def _collect_simulated(self):
        """Simulate collection (no real AWS credentials)."""
        # Generate simulated CloudTrail events
        simulated_events = [
            {
                "EventName": "ConsoleLogin",
                "EventSource": "signin.amazonaws.com",
                "EventTime": datetime.now(timezone.utc).isoformat(),
                "UserIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123456789012:user/test"},
                "SourceIPAddress": "203.0.113.50",
                "AwsRegion": self.region,
                "ResponseElements": {"ConsoleLogin": "Success"},
            },
            {
                "EventName": "AssumeRole",
                "EventSource": "sts.amazonaws.com",
                "EventTime": datetime.now(timezone.utc).isoformat(),
                "UserIdentity": {"type": "AssumedRole"},
                "SourceIPAddress": "198.51.100.25",
                "AwsRegion": self.region,
            },
        ]

        events_collected = 0
        for event in simulated_events:
            event_json = json.dumps(event)
            metadata = {
                "cloud_provider": "aws",
                "region": self.region,
                "collection_method": "cloudtrail_simulated",
            }
            self._emit(event_json, metadata)
            events_collected += 1

        self._stats["events_collected"] += events_collected
        self._stats["last_collection"] = datetime.now(timezone.utc).isoformat()

        return CollectorResult(success=True, events_collected=events_collected,
                               bytes_collected=sum(len(json.dumps(e)) for e in simulated_events))


class CloudWatchCollector(BaseCollector):
    """Collector for AWS CloudWatch Logs."""

    def __init__(self, name="cloudwatch", region="us-east-1",
                 log_groups=None, access_key=None, secret_key=None,
                 config=None):
        super().__init__(name=name, source=f"aws:cloudwatch:{region}",
                         config=config or {})
        self.region = region
        self.log_groups = log_groups or []
        self.access_key = access_key or os.environ.get("AWS_ACCESS_KEY_ID")
        self.secret_key = secret_key or os.environ.get("AWS_SECRET_ACCESS_KEY")
        self._cursors = {}  # log_group -> next_token

    def collect(self):
        """Collect CloudWatch log events."""
        if not self.log_groups:
            return CollectorResult(success=True, events_collected=0)

        try:
            import boto3
            client = boto3.client("logs", region_name=self.region,
                                  aws_access_key_id=self.access_key,
                                  aws_secret_access_key=self.secret_key)
        except ImportError:
            logger.debug("boto3 not available")
            return CollectorResult(success=True, events_collected=0)

        total_events = 0
        total_bytes = 0

        for log_group in self.log_groups:
            try:
                kwargs = {
                    "logGroupName": log_group,
                    "limit": 100,
                    "startFromHead": False,
                }
                token = self._cursors.get(log_group)
                if token:
                    kwargs["nextToken"] = token

                response = client.get_log_events(**kwargs)

                for event in response.get("events", []):
                    event_json = json.dumps(event, default=str)
                    metadata = {
                        "cloud_provider": "aws",
                        "log_group": log_group,
                        "region": self.region,
                        "collection_method": "cloudwatch_api",
                    }
                    self._emit(event_json, metadata)
                    total_events += 1
                    total_bytes += len(event_json)

                self._cursors[log_group] = response.get("nextForwardToken")

            except Exception as exc:
                logger.error("CloudWatch error for %s: %s", log_group, exc)

        self._stats["events_collected"] += total_events
        self._stats["bytes_collected"] += total_bytes

        return CollectorResult(success=True, events_collected=total_events,
                               bytes_collected=total_bytes)


class GCPCloudCollector(BaseCollector):
    """Collector for Google Cloud Platform logs."""

    def __init__(self, name="gcp_logging", project_id=None,
                 filter_expr=None, credentials_path=None, config=None):
        super().__init__(name=name, source=f"gcp:logging:{project_id}",
                         config=config or {})
        self.project_id = project_id or os.environ.get("GOOGLE_CLOUD_PROJECT")
        self.filter_expr = filter_expr or 'severity>=INFO'
        self.credentials_path = credentials_path or os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
        self._page_token = None

    def collect(self):
        """Collect GCP Cloud Logging entries."""
        if not self.project_id:
            logger.debug("No GCP project ID configured")
            return CollectorResult(success=True, events_collected=0)

        try:
            from google.cloud import logging as gcp_logging
            client = gcp_logging.Client(project=self.project_id)
            if self.credentials_path:
                client._credentials_path = self.credentials_path

            logger.info("Collecting GCP logs for project %s", self.project_id)

            entries = list(client.list_entries(
                filter_=self.filter_expr,
                page_size=100,
            ))

            total_events = 0
            total_bytes = 0

            for entry in entries:
                entry_dict = {
                    "log_name": entry.log_name,
                    "timestamp": entry.timestamp.isoformat() if entry.timestamp else None,
                    "severity": entry.severity.name if entry.severity else "DEFAULT",
                    "resource": entry.resource.type if entry.resource else None,
                    "payload": str(entry.payload) if entry.payload else None,
                    "labels": dict(entry.labels) if entry.labels else {},
                    "insert_id": entry.insert_id,
                }
                entry_json = json.dumps(entry_dict, default=str)
                metadata = {
                    "cloud_provider": "gcp",
                    "project_id": self.project_id,
                    "collection_method": "gcp_logging_api",
                }
                self._emit(entry_json, metadata)
                total_events += 1
                total_bytes += len(entry_json)

            self._stats["events_collected"] += total_events
            self._stats["bytes_collected"] += total_bytes

            return CollectorResult(success=True, events_collected=total_events,
                                   bytes_collected=total_bytes)

        except ImportError:
            logger.debug("google-cloud-logging not available")
            return CollectorResult(success=True, events_collected=0)
        except Exception as exc:
            logger.error("GCP collection error: %s", exc)
            return CollectorResult(success=False, error=str(exc))


class AzureLogCollector(BaseCollector):
    """Collector for Azure Monitor / Log Analytics."""

    def __init__(self, name="azure_monitor", workspace_id=None,
                 tenant_id=None, client_id=None, client_secret=None, config=None):
        super().__init__(name=name, source="azure:log_analytics",
                         config=config or {})
        self.workspace_id = workspace_id
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self._token = None
        self._token_expiry = None

    def _get_auth_token(self):
        """Get Azure AD authentication token."""
        if self._token and self._token_expiry and datetime.now(timezone.utc) < self._token_expiry:
            return self._token

        token_url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        data = urllib.parse.urlencode({
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": "https://api.loganalytics.io/.default",
            "grant_type": "client_credentials",
        }).encode()

        try:
            req = urllib.request.Request(token_url, data=data, method="POST")
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
            with urllib.request.urlopen(req, timeout=30) as resp:
                result = json.loads(resp.read().decode())
            self._token = result["access_token"]
            self._token_expiry = datetime.now(timezone.utc) + timedelta(seconds=result.get("expires_in", 3600) - 60)
            return self._token
        except Exception as exc:
            logger.error("Azure auth failed: %s", exc)
            return None

    def collect(self):
        """Collect Azure Log Analytics data."""
        if not all([self.workspace_id, self.tenant_id, self.client_id, self.client_secret]):
            return CollectorResult(success=True, events_collected=0)

        token = self._get_auth_token()
        if not token:
            return CollectorResult(success=False, error="Authentication failed")

        query = self.config.get("query", "SecurityEvent | take 50")
        url = f"https://api.loganalytics.io/v1/workspaces/{self.workspace_id}/query"

        try:
            req = urllib.request.Request(url, method="POST")
            req.add_header("Authorization", f"Bearer {token}")
            req.add_header("Content-Type", "application/json")
            req.data = json.dumps({"query": query}).encode()

            with urllib.request.urlopen(req, timeout=30) as resp:
                result = json.loads(resp.read().decode())

            tables = result.get("tables", [])
            total_events = 0
            total_bytes = 0

            for table in tables:
                columns = [c["name"] for c in table.get("columns", [])]
                for row in table.get("rows", []):
                    row_dict = dict(zip(columns, row))
                    row_json = json.dumps(row_dict, default=str)
                    metadata = {
                        "cloud_provider": "azure",
                        "workspace_id": self.workspace_id,
                        "collection_method": "azure_log_analytics",
                    }
                    self._emit(row_json, metadata)
                    total_events += 1
                    total_bytes += len(row_json)

            self._stats["events_collected"] += total_events
            self._stats["bytes_collected"] += total_bytes

            return CollectorResult(success=True, events_collected=total_events,
                                   bytes_collected=total_bytes)

        except Exception as exc:
            logger.error("Azure collection error: %s", exc)
            return CollectorResult(success=False, error=str(exc))
