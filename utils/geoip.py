"""
GeoIP and IP classification utilities.

Provides IP geolocation lookups and internal/external IP classification.
Uses a built-in offline database for common private ranges, with optional
support for MaxMind GeoIP2 databases if available.
"""

import os
import ipaddress
import logging
from collections import namedtuple

logger = logging.getLogger(__name__)

GeoIPResult = namedtuple("GeoIPResult", [
    "ip", "country", "country_code", "city", "region",
    "latitude", "longitude", "asn", "isp", "timezone",
    "is_internal", "is_anonymizer", "is_satellite",
])


# Private/reserved CIDR ranges
PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),    # CGNAT
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),         # IPv6 private
    ipaddress.ip_network("fe80::/10"),        # IPv6 link-local
]

# Known anonymizer/VPN exit ranges (subset for demonstration)
ANONYMIZER_RANGES = set()


class IPClassifier:
    """Classify IP addresses as internal, external, multicast, etc."""

    @staticmethod
    def is_internal(ip_str):
        """Check if an IP is in a private/reserved range."""
        try:
            ip = ipaddress.ip_address(ip_str)
            for network in PRIVATE_RANGES:
                if ip in network:
                    return True
            if ip.is_loopback or ip.is_link_local or ip.is_multicast:
                return True
            return False
        except ValueError:
            return False

    @staticmethod
    def is_valid_ip(ip_str):
        """Check if a string is a valid IP address."""
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False

    @staticmethod
    def is_ipv4(ip_str):
        """Check if an IP is IPv4."""
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.version == 4
        except ValueError:
            return False

    @staticmethod
    def is_ipv6(ip_str):
        """Check if an IP is IPv6."""
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.version == 6
        except ValueError:
            return False

    @staticmethod
    def ip_version(ip_str):
        """Get IP version (4 or 6)."""
        try:
            return ipaddress.ip_address(ip_str).version
        except ValueError:
            return None

    @staticmethod
    def in_cidr(ip_str, cidr_str):
        """Check if an IP is in a CIDR range."""
        try:
            network = ipaddress.ip_network(cidr_str, strict=False)
            addr = ipaddress.ip_address(ip_str)
            return addr in network
        except (ValueError, TypeError):
            return False

    @staticmethod
    def is_in_any_cidr(ip_str, cidr_list):
        """Check if an IP is in any of a list of CIDR ranges."""
        return any(IPClassifier.in_cidr(ip_str, c) for c in cidr_list)

    @staticmethod
    def classify(ip_str):
        """Classify an IP address."""
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return "invalid"

        if ip.is_loopback:
            return "loopback"
        if ip.is_link_local:
            return "link_local"
        if ip.is_multicast:
            return "multicast"
        if ip.is_reserved:
            return "reserved"
        if IPClassifier.is_internal(ip_str):
            return "internal"
        if ip.is_private:
            return "private"
        return "external"


class GeoIPLookup:
    """
    GeoIP lookup service.

    Uses MaxMind GeoIP2 database if available, otherwise returns
    limited information (internal/external classification only).
    """

    def __init__(self, db_path=None, city_db=None, asn_db=None):
        """Initialize GeoIP lookup.

        Args:
            db_path: Path to GeoLite2-City database.
            city_db: Alternative path for city database.
            asn_db: Path to GeoLite2-ASN database.
        """
        self.city_db_path = db_path or city_db
        self.asn_db_path = asn_db
        self._city_reader = None
        self._asn_reader = None
        self._cache = {}
        self._max_cache = 10000
        self._initialized = False
        self._available = False
        self._init_databases()

    def _init_databases(self):
        """Initialize GeoIP databases if available."""
        self._initialized = True
        try:
            import geoip2.database  # type: ignore
            if self.city_db_path and os.path.exists(self.city_db_path):
                self._city_reader = geoip2.database.Reader(self.city_db_path)
                self._available = True
                logger.info("Loaded GeoIP city database: %s", self.city_db_path)
            if self.asn_db_path and os.path.exists(self.asn_db_path):
                self._asn_reader = geoip2.database.Reader(self.asn_db_path)
                self._available = True
                logger.info("Loaded GeoIP ASN database: %s", self.asn_db_path)
        except ImportError:
            logger.info("geoip2 not available; GeoIP lookups will be limited")
        except Exception as exc:
            logger.warning("Failed to load GeoIP databases: %s", exc)

    @property
    def available(self):
        """Whether GeoIP databases are loaded."""
        return self._available

    def lookup(self, ip_str):
        """Look up geolocation for an IP address.

        Returns:
            GeoIPResult namedtuple.
        """
        if not IPClassifier.is_valid_ip(ip_str):
            return GeoIPResult(
                ip=ip_str, country=None, country_code=None, city=None,
                region=None, latitude=None, longitude=None, asn=None,
                isp=None, timezone=None, is_internal=False, is_anonymizer=False,
                is_satellite=False,
            )

        # Check cache
        if ip_str in self._cache:
            return self._cache[ip_str]

        is_internal = IPClassifier.is_internal(ip_str)

        # Internal IPs get no geo data
        if is_internal:
            result = GeoIPResult(
                ip=ip_str, country="Private", country_code="LO",
                city="Internal", region="Internal", latitude=None,
                longitude=None, asn=None, isp="Internal Network",
                timezone=None, is_internal=True, is_anonymizer=False,
                is_satellite=False,
            )
            self._cache_result(ip_str, result)
            return result

        # Look up from database
        country = country_code = city = region = None
        latitude = longitude = timezone = None
        asn = isp = None

        if self._city_reader:
            try:
                resp = self._city_reader.city(ip_str)
                country = resp.country.name
                country_code = resp.country.iso_code
                city = resp.city.name
                region = resp.subdivisions.most_specific.name
                latitude = resp.location.latitude
                longitude = resp.location.longitude
                timezone = resp.location.time_zone
            except Exception as exc:
                logger.debug("GeoIP city lookup failed for %s: %s", ip_str, exc)

        if self._asn_reader:
            try:
                resp = self._asn_reader.asn(ip_str)
                asn = resp.autonomous_system_number
                isp = resp.autonomous_system_organization
            except Exception as exc:
                logger.debug("GeoIP ASN lookup failed for %s: %s", ip_str, exc)

        result = GeoIPResult(
            ip=ip_str, country=country, country_code=country_code,
            city=city, region=region, latitude=latitude, longitude=longitude,
            asn=asn, isp=isp, timezone=timezone, is_internal=is_internal,
            is_anonymizer=ip_str in ANONYMIZER_RANGES,
            is_satellite=False,
        )

        self._cache_result(ip_str, result)
        return result

    def _cache_result(self, ip_str, result):
        """Cache a lookup result with LRU eviction."""
        if len(self._cache) >= self._max_cache:
            # Evict oldest 10% of cache
            to_remove = len(self._cache) // 10
            for _ in range(to_remove):
                if self._cache:
                    self._cache.pop(next(iter(self._cache)))
        self._cache[ip_str] = result

    def get_country(self, ip_str):
        """Get country name for an IP."""
        return self.lookup(ip_str).country

    def get_country_code(self, ip_str):
        """Get country code for an IP."""
        return self.lookup(ip_str).country_code

    def get_coordinates(self, ip_str):
        """Get (latitude, longitude) for an IP."""
        result = self.lookup(ip_str)
        return (result.latitude, result.longitude)

    def get_asn(self, ip_str):
        """Get ASN for an IP."""
        return self.lookup(ip_str).asn

    def is_internal(self, ip_str):
        """Check if an IP is internal."""
        return self.lookup(ip_str).is_internal

    def batch_lookup(self, ip_list):
        """Look up multiple IPs at once."""
        return {ip: self.lookup(ip) for ip in ip_list if IPClassifier.is_valid_ip(ip)}

    def clear_cache(self):
        """Clear the lookup cache."""
        self._cache.clear()

    def close(self):
        """Close database connections."""
        if self._city_reader:
            self._city_reader.close()
        if self._asn_reader:
            self._asn_reader.close()
