"""
Asset model: network asset inventory for enrichment and context.

Assets provide context about the systems involved in events, including
criticality, ownership, and classification.
"""

import uuid
import json
import ipaddress
from datetime import datetime, timezone
from enum import Enum


class AssetType(Enum):
    """Type of network asset."""
    SERVER = "server"
    WORKSTATION = "workstation"
    NETWORK_DEVICE = "network_device"
    SECURITY_DEVICE = "security_device"
    DATABASE = "database"
    CLOUD_INSTANCE = "cloud_instance"
    CONTAINER = "container"
    IOT_DEVICE = "iot_device"
    MOBILE = "mobile"
    VIRTUAL_MACHINE = "virtual_machine"
    LOAD_BALANCER = "load_balancer"
    FIREWALL = "firewall"
    ROUTER = "router"
    SWITCH = "switch"
    PRINTER = "printer"
    OTHER = "other"
    UNKNOWN = "unknown"


class AssetCriticality(Enum):
    """Business criticality of an asset."""
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_string(cls, name):
        return {
            "none": cls.NONE, "low": cls.LOW, "medium": cls.MEDIUM,
            "high": cls.HIGH, "critical": cls.CRITICAL,
        }.get(name.lower(), cls.MEDIUM)

    def to_label(self):
        return {0: "None", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}[self.value]


class Asset:
    """
    A network asset in the inventory.

    Assets can be looked up by IP, hostname, MAC, or asset ID to provide
    context during event enrichment.
    """

    def __init__(self, **kwargs):
        self.asset_id = kwargs.get("asset_id") or f"AST-{uuid.uuid4().hex[:8].upper()}"
        self.name = kwargs.get("name", "")
        self.hostname = kwargs.get("hostname", "")
        self.fqdn = kwargs.get("fqdn", "")
        self.asset_type = AssetType(kwargs.get("asset_type", AssetType.UNKNOWN.value))
        self.criticality = AssetCriticality.from_string(kwargs.get("criticality", "medium"))

        # Network identifiers
        self.ip_addresses = kwargs.get("ip_addresses", [])
        self.mac_address = kwargs.get("mac_address")
        self.aliases = kwargs.get("aliases", [])

        # Location
        self.location = kwargs.get("location", "")
        self.site = kwargs.get("site", "")
        self.building = kwargs.get("building", "")
        self.floor = kwargs.get("floor", "")
        self.room = kwargs.get("room", "")

        # Ownership
        self.owner = kwargs.get("owner")
        self.department = kwargs.get("department")
        self.custodian = kwargs.get("custodian")

        # Classification
        self.data_classification = kwargs.get("data_classification", "internal")
        self.environment = kwargs.get("environment", "production")  # prod, staging, dev, test
        self.tags = kwargs.get("tags", [])

        # OS / Software
        self.os_type = kwargs.get("os_type", "")
        self.os_version = kwargs.get("os_version", "")
        self.installed_software = kwargs.get("installed_software", [])
        self.open_ports = kwargs.get("open_ports", [])

        # Security
        self.compliance_status = kwargs.get("compliance_status", "unknown")
        self.patch_level = kwargs.get("patch_level", "unknown")
        self.last_scan = kwargs.get("last_scan")
        self.vulnerabilities = kwargs.get("vulnerabilities", [])
        self.security_score = kwargs.get("security_score", 0)

        # Cloud
        self.cloud_provider = kwargs.get("cloud_provider")
        self.cloud_instance_id = kwargs.get("cloud_instance_id")
        self.cloud_region = kwargs.get("cloud_region")
        self.cloud_tags = kwargs.get("cloud_tags", {})

        # Timing
        now = datetime.now(timezone.utc)
        self.created_at = kwargs.get("created_at", now)
        self.updated_at = kwargs.get("updated_at", now)
        self.last_seen = kwargs.get("last_seen")
        self.first_seen = kwargs.get("first_seen", now)

        # Status
        self.is_active = kwargs.get("is_active", True)
        self.is_monitored = kwargs.get("is_monitored", True)

        # Metadata
        self.metadata = kwargs.get("metadata", {})
        self.notes = kwargs.get("notes", "")

    def matches_ip(self, ip):
        """Check if this asset has the given IP."""
        return ip in self.ip_addresses

    def matches_hostname(self, hostname):
        """Check if this asset has the given hostname."""
        hostnames = {h.lower() for h in [self.hostname, self.fqdn, self.name] + self.aliases if h}
        return hostname.lower() in hostnames

    def matches_mac(self, mac):
        """Check if this asset has the given MAC address."""
        if not self.mac_address:
            return False
        return mac.lower().replace(":", "").replace("-", "") == \
               self.mac_address.lower().replace(":", "").replace("-", "")

    def is_in_cidr(self, cidr):
        """Check if any of this asset's IPs are in the given CIDR."""
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            for ip in self.ip_addresses:
                try:
                    if ipaddress.ip_address(ip) in network:
                        return True
                except ValueError:
                    continue
        except ValueError:
            pass
        return False

    def add_ip(self, ip):
        """Add an IP address to the asset."""
        if ip and ip not in self.ip_addresses:
            self.ip_addresses.append(ip)
            self.updated_at = datetime.now(timezone.utc)

    def add_alias(self, alias):
        """Add an alias/hostname."""
        if alias and alias not in self.aliases:
            self.aliases.append(alias)
            self.updated_at = datetime.now(timezone.utc)

    def add_software(self, name, version=""):
        """Add installed software."""
        entry = {"name": name, "version": version}
        if entry not in self.installed_software:
            self.installed_software.append(entry)
            self.updated_at = datetime.now(timezone.utc)

    def add_vulnerability(self, cve_id, severity="medium", description=""):
        """Add a vulnerability."""
        vuln = {
            "cve_id": cve_id,
            "severity": severity,
            "description": description,
            "discovered_at": datetime.now(timezone.utc).isoformat(),
        }
        self.vulnerabilities.append(vuln)
        self.updated_at = datetime.now(timezone.utc)

    def add_tag(self, tag):
        """Add a tag."""
        if tag not in self.tags:
            self.tags.append(tag)

    def update_last_seen(self):
        """Update the last seen timestamp."""
        self.last_seen = datetime.now(timezone.utc)
        self.is_active = True

    def to_dict(self):
        return {
            "asset_id": self.asset_id,
            "name": self.name,
            "hostname": self.hostname,
            "fqdn": self.fqdn,
            "asset_type": self.asset_type.value,
            "criticality": self.criticality.to_label(),
            "ip_addresses": self.ip_addresses,
            "mac_address": self.mac_address,
            "aliases": self.aliases,
            "location": self.location,
            "site": self.site,
            "building": self.building,
            "owner": self.owner,
            "department": self.department,
            "data_classification": self.data_classification,
            "environment": self.environment,
            "tags": self.tags,
            "os_type": self.os_type,
            "os_version": self.os_version,
            "installed_software": self.installed_software,
            "open_ports": self.open_ports,
            "compliance_status": self.compliance_status,
            "patch_level": self.patch_level,
            "vulnerabilities": self.vulnerabilities,
            "security_score": self.security_score,
            "cloud_provider": self.cloud_provider,
            "cloud_instance_id": self.cloud_instance_id,
            "cloud_region": self.cloud_region,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "is_active": self.is_active,
            "is_monitored": self.is_monitored,
            "metadata": self.metadata,
            "notes": self.notes,
        }

    def to_json(self, indent=None):
        return json.dumps(self.to_dict(), indent=indent, default=str)

    @classmethod
    def from_dict(cls, data):
        return cls(**data)

    def __repr__(self):
        return f"Asset(id={self.asset_id}, name={self.name!r}, type={self.asset_type.value})"

    def __eq__(self, other):
        if not isinstance(other, Asset):
            return False
        return self.asset_id == other.asset_id

    def __hash__(self):
        return hash(self.asset_id)
