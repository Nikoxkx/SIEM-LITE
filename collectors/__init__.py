"""
Log collectors module.

Provides collectors for gathering logs from various sources:
- Syslog (UDP/TCP)
- File tailing
- HTTP endpoints
- Windows Event Logs
- Cloud APIs
- Message queues
"""

from .base import BaseCollector, CollectorResult, CollectorStatus, CollectorRegistry
from .syslog_collector import SyslogCollector, UDPSyslogCollector, TCPSyslogCollector
from .file_collector import FileCollector, DirectoryCollector
from .http_collector import HTTPCollector, WebhookCollector
from .windows_collector import WindowsEventCollector, WinevtCollector
from .cloud_collector import CloudTrailCollector, CloudWatchCollector, GCPCloudCollector

__all__ = [
    "BaseCollector", "CollectorResult", "CollectorStatus", "CollectorRegistry",
    "SyslogCollector", "UDPSyslogCollector", "TCPSyslogCollector",
    "FileCollector", "DirectoryCollector",
    "HTTPCollector", "WebhookCollector",
    "WindowsEventCollector", "WinevtCollector",
    "CloudTrailCollector", "CloudWatchCollector", "GCPCloudCollector",
]
