"""
Enrichment engine: adds contextual data to events.

Enrichment includes:
- GeoIP lookups (country, city, ASN)
- Asset inventory correlation
- User identity resolution
- Threat reputation scores
- Network classification (internal/external)
- Known-bad indicator flagging
"""

import logging
from datetime import datetime, timezone

from ..utils.geoip import GeoIPLookup, IPClassifier
from ..models.asset import Asset, AssetType

logger = logging.getLogger(__name__)


# Well-known service port mapping for enrichment
WELL_KNOWN_PORTS = {
    20: ("FTP", "ftp-data"), 21: ("FTP", "ftp"), 22: ("SSH", "ssh"),
    23: ("Telnet", "telnet"), 25: ("SMTP", "smtp"), 53: ("DNS", "dns"),
    67: ("DHCP", "dhcp"), 68: ("DHCP", "dhcp"), 69: ("TFTP", "tftp"),
    80: ("HTTP", "http"), 88: ("Kerberos", "kerberos"), 110: ("POP3", "pop3"),
    111: ("RPC", "rpcbind"), 123: ("NTP", "ntp"), 135: ("MS-RPC", "msrpc"),
    137: ("NetBIOS", "netbios-ns"), 138: ("NetBIOS", "netbios-dgm"),
    139: ("NetBIOS", "netbios-ssn"), 143: ("IMAP", "imap"),
    161: ("SNMP", "snmp"), 389: ("LDAP", "ldap"), 443: ("HTTPS", "https"),
    445: ("SMB", "smb"), 465: ("SMTPS", "smtps"), 514: ("Syslog", "syslog"),
    587: ("SMTP", "smtp-submission"), 636: ("LDAPS", "ldaps"),
    993: ("IMAPS", "imaps"), 995: ("POP3S", "pop3s"),
    1433: ("MSSQL", "mssql"), 1521: ("Oracle", "oracle"),
    1723: ("PPTP", "pptp"), 3306: ("MySQL", "mysql"),
    3389: ("RDP", "rdp"), 5432: ("PostgreSQL", "postgresql"),
    5900: ("VNC", "vnc"), 6379: ("Redis", "redis"),
    8080: ("HTTP-Proxy", "http-proxy"), 8443: ("HTTPS", "https-alt"),
    9200: ("Elasticsearch", "elasticsearch"), 27017: ("MongoDB", "mongodb"),
}


class EnrichmentEngine:
    """Enriches events with contextual data.

    Applies multiple enrichers to events in a configurable order:
    1. GeoIP enrichment (IP -> country, city, ASN)
    2. Asset inventory lookup (IP/hostname -> asset metadata)
    3. Port/service mapping
    4. Network classification
    5. Custom enrichers via plugins
    """

    def __init__(self, geoip=None, asset_inventory=None, config=None):
        """Initialize enrichment engine.

        Args:
            geoip: GeoIPLookup instance.
            asset_inventory: Asset inventory dict or lookup function.
            config: Configuration dict.
        """
        self.config = config or {}
        self.geoip = geoip or GeoIPLookup()
        self.asset_inventory = asset_inventory if asset_inventory is not None else {}
        self._custom_enrichers = []
        self._enrich_count = 0
        self._error_count = 0

        # IP reputation cache (in production, from threat intel)
        self._reputation_cache = {}

    def enrich(self, event):
        """Apply all enrichments to an event.

        Args:
            event: Event object to enrich.

        Returns:
            The enriched Event (modified in place).
        """
        self._enrich_count += 1

        try:
            # GeoIP enrichment
            if self.config.get("enable_geoip", True):
                self._enrich_geoip(event)

            # Asset inventory lookup
            if self.config.get("enable_asset_lookup", True):
                self._enrich_asset(event)

            # Port/service enrichment
            if self.config.get("enable_port_mapping", True):
                self._enrich_ports(event)

            # Protocol classification
            self._enrich_protocol(event)

            # Time-based enrichment
            self._enrich_time(event)

            # Custom enrichers
            for enricher in self._custom_enrichers:
                try:
                    enricher(event)
                except Exception as exc:
                    logger.debug("Custom enricher error: %s", exc)

            event.add_tag("enriched")

        except Exception as exc:
            self._error_count += 1
            logger.error("Enrichment error: %s", exc, exc_info=True)

        return event

    def _enrich_geoip(self, event):
        """Enrich with GeoIP data."""
        # Source IP enrichment
        src_ip = event.get("source_ip")
        if src_ip and IPClassifier.is_valid_ip(src_ip):
            result = self.geoip.lookup(src_ip)
            if result:
                if result.country:
                    event.set("source_country", result.country)
                if result.city:
                    event.set("source_city", result.city)
                if result.asn:
                    event.set("source_asn", result.asn)
                if result.isp:
                    event.set("source_isp", result.isp)
                event.set("source_is_internal", result.is_internal)

        # Destination IP enrichment
        dst_ip = event.get("dest_ip")
        if dst_ip and IPClassifier.is_valid_ip(dst_ip):
            result = self.geoip.lookup(dst_ip)
            if result:
                if result.country:
                    event.set("dest_country", result.country)
                if result.city:
                    event.set("dest_city", result.city)
                if result.asn:
                    event.set("dest_asn", result.asn)
                event.set("dest_is_internal", result.is_internal)

    def _enrich_asset(self, event):
        """Enrich with asset inventory data."""
        # Look up source asset
        src_ip = event.get("source_ip")
        src_host = event.get("source_host")

        src_asset = self._lookup_asset(ip=src_ip, hostname=src_host)
        if src_asset:
            event.set("source_asset", src_asset.asset_id)
            if not event.get("source_host") and src_asset.hostname:
                event.set("source_host", src_asset.hostname)
            # Add asset tags
            for tag in src_asset.tags:
                event.add_tag(f"asset:{tag}")

        # Look up destination asset
        dst_ip = event.get("dest_ip")
        dst_host = event.get("dest_host")

        dst_asset = self._lookup_asset(ip=dst_ip, hostname=dst_host)
        if dst_asset:
            event.set("dest_asset", dst_asset.asset_id)
            if not event.get("dest_host") and dst_asset.hostname:
                event.set("dest_host", dst_asset.hostname)
            for tag in dst_asset.tags:
                event.add_tag(f"asset:{tag}")

    def _lookup_asset(self, ip=None, hostname=None, mac=None):
        """Look up an asset by IP, hostname, or MAC."""
        if not self.asset_inventory:
            return None

        # If it's a callable (lookup function)
        if callable(self.asset_inventory):
            return self.asset_inventory(ip=ip, hostname=hostname, mac=mac)

        # Search in dict-based inventory
        for asset in self.asset_inventory.values():
            if ip and asset.matches_ip(ip):
                return asset
            if hostname and asset.matches_hostname(hostname):
                return asset
            if mac and asset.matches_mac(mac):
                return asset

        return None

    def _enrich_ports(self, event):
        """Enrich with port/service mapping."""
        dst_port = event.get("dest_port")
        if dst_port and not event.get("category"):
            if dst_port in WELL_KNOWN_PORTS:
                service_name, service_short = WELL_KNOWN_PORTS[dst_port]
                event.set("category", service_short)

                # Check for sensitive ports
                sensitive_ports = {22, 23, 3389, 5900, 445, 135, 1433, 3306, 5432, 6379, 27017}
                if int(dst_port) in sensitive_ports:
                    event.add_tag("sensitive_port")

        # Flag well-known admin ports
        src_port = event.get("source_port")
        if src_port and int(src_port) < 1024:
            event.add_tag("privileged_source_port")

    def _enrich_protocol(self, event):
        """Enrich protocol information."""
        protocol = event.get("protocol")
        if protocol:
            protocol = str(protocol).upper()
            if protocol in ("6", "TCP"):
                event.set("protocol", "TCP")
                event.set("transport", "TCP")
            elif protocol in ("17", "UDP"):
                event.set("protocol", "UDP")
                event.set("transport", "UDP")
            elif protocol in ("1", "ICMP"):
                event.set("protocol", "ICMP")
                event.set("transport", "ICMP")
            elif protocol in ("58", "ICMPv6"):
                event.set("protocol", "ICMPv6")

    def _enrich_time(self, event):
        """Add time-based enrichment."""
        ts = event.get("timestamp")
        if ts and hasattr(ts, 'hour'):
            # Flag off-hours activity
            hour = ts.hour
            if hour < 6 or hour >= 22:
                event.add_tag("off_hours")
            # Flag weekend activity
            if ts.weekday() >= 5:
                event.add_tag("weekend")

    def add_enricher(self, func):
        """Add a custom enrichment function.

        The function should take an Event and modify it in place.
        """
        self._custom_enrichers.append(func)
        logger.debug("Added custom enricher: %s", func.__name__)

    def add_asset(self, asset):
        """Add an asset to the inventory."""
        if not isinstance(self.asset_inventory, dict):
            self.asset_inventory = {}
        if isinstance(asset, Asset):
            self.asset_inventory[asset.asset_id] = asset
        elif isinstance(asset, dict):
            a = Asset(**asset)
            self.asset_inventory[a.asset_id] = a

    def load_assets_from_list(self, assets):
        """Load assets from a list of dicts or Asset objects."""
        if not isinstance(self.asset_inventory, dict):
            self.asset_inventory = {}
        for asset_data in assets:
            self.add_asset(asset_data)

    def get_reputation(self, ip):
        """Get reputation score for an IP (from cache or threat intel)."""
        if ip in self._reputation_cache:
            return self._reputation_cache[ip]

        # Default neutral reputation
        reputation = 50  # 0-100, lower is worse
        self._reputation_cache[ip] = reputation
        return reputation

    def set_reputation(self, ip, score):
        """Set reputation score for an IP."""
        self._reputation_cache[ip] = max(0, min(100, score))

    def get_stats(self):
        """Get enrichment statistics."""
        return {
            "enrich_count": self._enrich_count,
            "error_count": self._error_count,
            "geoip_available": self.geoip.available,
            "assets_tracked": len(self.asset_inventory) if isinstance(self.asset_inventory, dict) else 0,
            "custom_enrichers": len(self._custom_enrichers),
        }

    def reset_stats(self):
        """Reset statistics."""
        self._enrich_count = 0
        self._error_count = 0
