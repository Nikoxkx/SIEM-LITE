#!/usr/bin/env python3
"""
SIEM-Lite Log Correlation Engine
================================

Main entry point for the SIEM-Lite system.

Usage:
    python run.py                    # Start with default config
    python run.py --port 8080        # Custom port
    python run.py --debug            # Debug mode
    python run.py --demo             # Start with demo data
    python run.py --collectors       # Start with syslog collectors

"""

import os
import sys
import time
import json
import logging
import argparse
import threading

# Ensure the package is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import siem_lite
from siem_lite.core.engine import SIEMEngine
from siem_lite.api.server import APIServer
from siem_lite import setup_logging


def load_config(config_path=None):
    """Load configuration from YAML file."""
    if config_path is None:
        config_path = os.path.join(os.path.dirname(__file__), "config", "siem.yaml")

    config = {}
    try:
        import yaml
        if os.path.exists(config_path):
            with open(config_path, "r") as f:
                config = yaml.safe_load(f) or {}
            logging.info("Loaded configuration from %s", config_path)
    except ImportError:
        logging.warning("PyYAML not available; using default configuration")
    except Exception as exc:
        logging.error("Failed to load config %s: %s", config_path, exc)

    return config


def generate_demo_data(engine, num_events=500):
    """Generate demo log events for testing."""
    import random
    from datetime import datetime, timezone, timedelta

    logging.info("Generating %d demo events...", num_events)

    internal_ips = [f"10.0.{i}.{j}" for i in range(3) for j in range(1, 20)]
    external_ips = [
        "45.227.255.206", "51.91.111.152", "61.177.172.28", "139.59.66.36",
        "185.220.101.1", "193.169.254.80", "222.186.30.35", "106.13.63.76",
        "78.188.143.50", "114.67.107.173", "203.0.113.50", "198.51.100.25",
    ]
    users = ["admin", "jsmith", "mwilliams", "root", "svc_backup", "dbadmin",
             "operator", "guest", "test_user", "developer"]

    def ts_str(offset=None):
        """Return a syslog-formatted timestamp string."""
        if offset is None:
            offset = random.randint(0, 3600)
        dt = datetime.now(timezone.utc) - timedelta(seconds=offset)
        return dt.strftime("%b %d %H:%M:%S")

    def ts_iso(offset=None):
        """Return an ISO-format timestamp string."""
        if offset is None:
            offset = random.randint(0, 3600)
        dt = datetime.now(timezone.utc) - timedelta(seconds=offset)
        return dt.isoformat()

    def ts_apache(offset=None):
        """Return an Apache-format timestamp string."""
        if offset is None:
            offset = random.randint(0, 3600)
        dt = datetime.now(timezone.utc) - timedelta(seconds=offset)
        return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")

    templates = [
        # SSH failed login
        lambda: f"<34>{ts_str()} web01 sshd[{random.randint(1000, 9999)}]: Failed password for invalid user {random.choice(users)} from {random.choice(external_ips)} port {random.randint(1024, 65535)} ssh2",

        # SSH successful login
        lambda: f"<38>{ts_str()} app01 sshd[{random.randint(1000, 9999)}]: Accepted password for {random.choice(users)} from {random.choice(internal_ips)} port {random.randint(1024, 65535)} ssh2",

        # Firewall / iptables
        lambda: f"<134>{ts_str()} fw01 kernel: [{int(time.time())}] IPTABLES IN=eth0 OUT= SRC={random.choice(external_ips)} DST=10.0.1.5 PROTO=TCP SPT={random.randint(1024, 65535)} DPT={random.choice([22, 80, 443, 3389, 445])}",

        # CEF — connection denied
        lambda: f"CEF:0|Cisco|ASA|1.0|302001|Connection Denied|6|src={random.choice(external_ips)} spt={random.randint(1024, 65535)} dst=10.0.1.10 dpt={random.choice([22, 3389, 445])} act=deny proto=TCP",

        # CEF — malware detected
        lambda: f"CEF:0|Fortinet|FortiGate|6.0|100|Malware Detected|9|src={random.choice(external_ips)} dst=10.0.1.5 act=block fname=suspicious.exe fhash={random.randint(10**31, 10**32 - 1):x}",

        # JSON — authentication
        lambda: json.dumps({
            "timestamp": ts_iso(),
            "source_ip": random.choice(external_ips),
            "dest_ip": random.choice(internal_ips),
            "dest_port": random.choice([22, 80, 443, 3389]),
            "action": random.choice(["logon", "logon_failed", "connect"]),
            "result": random.choice(["success", "failure"]),
            "user": random.choice(users),
            "event_type": "authentication",
            "severity": random.choice(["info", "warning", "error"]),
            "message": f"Authentication attempt from {random.choice(external_ips)}",
        }),

        # Web access log
        lambda: f'{random.choice(external_ips)} - {random.choice(["-", users[0]])} [{ts_apache()}] "{random.choice(["GET", "POST", "PUT", "DELETE"])} {random.choice(["/admin", "/api/login", "/wp-admin", "/index.html", "/.env", "/etc/passwd"])} HTTP/1.1" {random.choice([200, 200, 200, 401, 403, 404, 500])} {random.randint(100, 10000)} "https://example.com/" "Mozilla/5.0"',

        # DNS query
        lambda: json.dumps({
            "timestamp": ts_iso(),
            "source_ip": random.choice(internal_ips),
            "dns_query": random.choice(["malware-c2.example.net", "google.com", "github.com",
                                        "phishing-login.example.tk", "update.microsoft.com",
                                        "bad-update-server.example.xyz"]),
            "dns_record_type": random.choice(["A", "AAAA", "MX", "TXT"]),
            "event_type": "dns",
            "action": "query",
            "severity": "info",
        }),

        # Windows event
        lambda: json.dumps({
            "EventID": random.choice([4624, 4625, 4688, 4634, 4720, 4672]),
            "TimeCreated": ts_iso(),
            "Computer": random.choice(["DC01", "FILESRV01", "WKS-001", "WKS-002"]),
            "TargetUserName": random.choice(users),
            "IpAddress": random.choice(internal_ips + external_ips),
            "LogonType": random.choice([2, 3, 10]),
        }),

        # Sudo command
        lambda: f"<86>{ts_str()} web01 sudo: {random.choice(users)} : TTY=pts/0 ; PWD=/home/{users[0]} ; USER=root ; COMMAND=/bin/{random.choice(['cat', 'ls', 'grep', 'find', 'systemctl', 'apt'])} {random.choice(['/etc/shadow', '/var/log/auth.log', '/root', '--help'])}",
    ]

    for i in range(num_events):
        template = random.choice(templates)
        raw_data = template()
        metadata = {
            "collection_method": "demo",
            "demo_event": True,
        }
        engine.ingest(raw_data, metadata)

        if (i + 1) % 100 == 0:
            logging.info("Generated %d/%d events", i + 1, num_events)

    stats = engine.get_stats()
    logging.info("Demo data generation complete. Events stored: %d, Alerts: %d",
                 stats["storage"]["current_events"], stats["storage"]["current_alerts"])


def start_collectors(engine, config):
    """Start configured collectors."""
    collector_configs = config.get("collectors", {})

    for name, coll_config in collector_configs.items():
        if not coll_config.get("enabled", False):
            continue

        coll_type = coll_config.get("type", "file")

        if coll_type == "syslog":
            from siem_lite.collectors.syslog_collector import SyslogCollector
            collector = SyslogCollector(
                name=name,
                host=coll_config.get("host", "0.0.0.0"),
                port=coll_config.get("port", 514),
                protocol=coll_config.get("protocol", "udp"),
            )
        elif coll_type == "file":
            directory = coll_config.get("directory", "/var/log")
            pattern = coll_config.get("pattern", "*.log")
            from siem_lite.collectors.file_collector import DirectoryCollector
            collector = DirectoryCollector(
                name=name,
                directory=directory,
                pattern=pattern,
                recursive=coll_config.get("recursive", False),
            )
        elif coll_type == "http":
            from siem_lite.collectors.http_collector import HTTPCollector
            collector = HTTPCollector(
                name=name,
                url=coll_config.get("url"),
                interval=coll_config.get("interval", 30),
            )
        else:
            logging.warning("Unknown collector type: %s", coll_type)
            continue

        engine.add_collector(collector)
        engine.start_collector(name)
        logging.info("Started collector: %s (%s)", name, coll_type)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="SIEM-Lite Log Correlation Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--config", "-c", help="Configuration file path")
    parser.add_argument("--host", default="0.0.0.0", help="Bind host")
    parser.add_argument("--port", "-p", type=int, default=8443, help="Bind port")
    parser.add_argument("--debug", "-d", action="store_true", help="Debug mode")
    parser.add_argument("--demo", action="store_true", help="Generate demo data")
    parser.add_argument("--demo-events", type=int, default=500, help="Number of demo events")
    parser.add_argument("--collectors", action="store_true", help="Start configured collectors")
    parser.add_argument("--log-level", default="INFO", help="Log level")

    args = parser.parse_args()

    # Setup logging
    log_level = getattr(logging, args.log_level.upper(), logging.INFO)
    setup_logging(level=log_level)

    logging.info("=" * 60)
    logging.info("SIEM-Lite Log Correlation Engine v%s", siem_lite.__version__)
    logging.info("=" * 60)

    # Load configuration
    config = load_config(args.config)

    # Override with command line args
    if args.debug:
        config.setdefault("api", {})["debug"] = True
    config.setdefault("api", {})["host"] = args.host
    config.setdefault("api", {})["port"] = args.port

    # Initialize engine
    logging.info("Initializing SIEM engine...")
    engine = SIEMEngine(config)

    # Start the engine
    engine.start()
    logging.info("SIEM engine started successfully")

    # Generate demo data if requested
    if args.demo:
        generate_demo_data(engine, args.demo_events)

    # Start collectors if requested
    if args.collectors:
        start_collectors(engine, config)

    # Start the API server
    api_port = config.get("api", {}).get("port", args.port)
    api_host = config.get("api", {}).get("host", args.host)
    api_debug = config.get("api", {}).get("debug", args.debug)

    server = APIServer(engine=engine, config=config)
    server.create_app()

    logging.info("=" * 60)
    logging.info("Web UI: http://localhost:%d", api_port)
    logging.info("API:    http://localhost:%d/api/", api_port)
    logging.info("Login:  admin / admin123")
    logging.info("=" * 60)

    try:
        server.run(host=api_host, port=api_port, debug=api_debug)
    except KeyboardInterrupt:
        logging.info("Shutting down...")
    finally:
        engine.close()
        logging.info("Goodbye!")


if __name__ == "__main__":
    main()
