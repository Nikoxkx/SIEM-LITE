#!/usr/bin/env python3
"""
Log Ingest Simulator for SIEM-Lite.

Generates realistic log events and sends them to the SIEM engine via the
API endpoint for testing and demonstration.

Usage:
    python scripts/ingest_simulator.py --host localhost --port 8443 --rate 10
    python scripts/ingest_simulator.py --direct --engine-memory  # Direct to engine
"""

import os
import sys
import time
import json
import random
import logging
import argparse
import urllib.request
from datetime import datetime, timezone, timedelta
from threading import Thread

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("simulator")


class LogGenerator:
    """Generates realistic log events for testing."""

    def __init__(self):
        self.internal_ips = [f"10.0.{i}.{j}" for i in range(3) for j in range(1, 50)]
        self.external_ips = [
            "45.227.255.206", "51.91.111.152", "61.177.172.28", "139.59.66.36",
            "185.220.101.1", "193.169.254.80", "222.186.30.35", "106.13.63.76",
            "78.188.143.50", "114.67.107.173", "203.0.113.50", "198.51.100.25",
            "104.244.74.211", "185.175.93.105", "194.165.16.70",
        ]
        self.users = ["admin", "jsmith", "mwilliams", "root", "svc_backup",
                       "dbadmin", "operator", "guest", "test_user", "developer",
                       "bob", "alice", "svc_monitor", "nginx", "postgres"]
        self.hosts = ["web01", "web02", "app01", "db01", "dc01", "fileserver01",
                       "fw01", "proxy01", "mail01", "bastion01", "k8s-worker-01",
                       "k8s-master-01", "gitlab01", "jenkins01"]
        self.malware_hashes = [
            "44d88612eca4827574a1c6c8c8b1c8c8b1c8c8b1c8c8b1c8c8b1c8c8b1c",
            "a]b1c8c8b1c8c8b1c8c8b1c8c8b1c8c8b1c8c8b1c8c8b1c8c8b1c8c8b1c",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ]
        self.count = 0

    def _ts(self, offset_seconds=None):
        """Generate a timestamp."""
        if offset_seconds is None:
            offset_seconds = random.randint(0, 60)
        dt = datetime.now(timezone.utc) - timedelta(seconds=offset_seconds)
        return dt

    def _ts_str(self, fmt="%b %d %H:%M:%S", offset_seconds=None):
        """Generate a formatted timestamp string."""
        return self._ts(offset_seconds).strftime(fmt)

    def generate(self, event_type=None):
        """Generate a single log event.

        Args:
            event_type: Optional type to generate ('auth', 'firewall', 'web',
                       'dns', 'windows', 'cef', 'sudo', 'malware', 'json').
                       If None, a random type is chosen.
        """
        generators = {
            "auth_failed": self._gen_auth_failed,
            "auth_success": self._gen_auth_success,
            "firewall": self._gen_firewall,
            "web": self._gen_web,
            "dns": self._gen_dns,
            "windows": self._gen_windows,
            "cef": self._gen_cef,
            "sudo": self._gen_sudo,
            "malware": self._gen_malware,
            "json": self._gen_json,
            "syslog5424": self._gen_syslog5424,
        }

        if event_type and event_type in generators:
            return generators[event_type]()

        # Weighted random selection
        weights = {
            "auth_failed": 15, "auth_success": 20, "firewall": 15,
            "web": 15, "dns": 10, "windows": 5, "cef": 5,
            "sudo": 3, "malware": 2, "json": 7, "syslog5424": 3,
        }
        choices = []
        for etype, weight in weights.items():
            choices.extend([etype] * weight)

        return generators[random.choice(choices)]()

    def _gen_auth_failed(self):
        """Generate failed authentication event."""
        ip = random.choice(self.external_ips + self.internal_ips)
        user = random.choice(self.users)
        host = random.choice(self.hosts)
        port = random.randint(1024, 65535)
        ts = self._ts_str()
        return f"<34>{ts} {host} sshd[{random.randint(1000, 9999)}]: Failed password for {'invalid user ' if random.random() > 0.5 else ''}{user} from {ip} port {port} ssh2"

    def _gen_auth_success(self):
        """Generate successful authentication event."""
        ip = random.choice(self.internal_ips)
        user = random.choice(self.users)
        host = random.choice(self.hosts)
        port = random.randint(1024, 65535)
        ts = self._ts_str()
        return f"<38>{ts} {host} sshd[{random.randint(1000, 9999)}]: Accepted publickey for {user} from {ip} port {port} ssh2"

    def _gen_firewall(self):
        """Generate firewall event."""
        src = random.choice(self.external_ips + self.internal_ips)
        dst = random.choice(self.internal_ips)
        dport = random.choice([22, 80, 443, 3389, 445, 1433, 3306, 8080, 8443, random.randint(1024, 65535)])
        action = random.choice(["ACCEPT", "DROP", "REJECT", "ACCEPT", "ACCEPT"])
        proto = random.choice(["TCP", "UDP"])
        ts = self._ts_str()
        return f"<134>{ts} {random.choice(['fw01', 'fw02'])} kernel: [{int(time.time())}] IPTABLES {action} IN=eth0 OUT= SRC={src} DST={dst} PROTO={proto} SPT={random.randint(1024, 65535)} DPT={dport}"

    def _gen_web(self):
        """Generate web access log."""
        ip = random.choice(self.external_ips + self.internal_ips)
        method = random.choice(["GET", "GET", "GET", "POST", "PUT", "DELETE"])
        paths = ["/", "/index.html", "/api/v1/users", "/login", "/admin",
                 "/wp-admin/", "/.env", "/etc/passwd", "/api/health",
                 "/assets/app.js", "/static/style.css"]
        path = random.choice(paths)
        status = random.choice([200, 200, 200, 301, 401, 403, 404, 500, 200, 200])
        size = random.randint(100, 50000)
        ts = self._ts(offset_seconds=random.randint(0, 60))
        ts_str = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
        user_agent = random.choice([
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
            "curl/7.81.0", "python-requests/2.28.0",
            "sqlmap/1.7", "nikto/2.5.0", "nmap scanner",
        ])
        return f'{ip} - {random.choice(["-", "jsmith", "admin"])} [{ts_str}] "{method} {path} HTTP/1.1" {status} {size} "https://example.com/" "{user_agent}"'

    def _gen_dns(self):
        """Generate DNS query event."""
        src = random.choice(self.internal_ips)
        domains = ["google.com", "github.com", "cloudflare.com", "microsoft.com",
                    "amazonaws.com", "malware-c2.example.net", "phishing-login.example.tk",
                    "bad-update-server.example.xyz", "update.windows.com",
                    "cdn.cloudflare.net", "api.openai.com", "registry.npmjs.org"]
        domain = random.choice(domains)
        rtype = random.choice(["A", "AAAA", "MX", "TXT", "CNAME"])
        return json.dumps({
            "timestamp": self._ts().isoformat(),
            "source_ip": src,
            "dns_query": domain,
            "dns_record_type": rtype,
            "event_type": "dns",
            "action": "query",
            "severity": "info",
            "product": "bind",
            "vendor": "ISC",
        })

    def _gen_windows(self):
        """Generate Windows event."""
        event_ids = [4624, 4625, 4688, 4634, 4720, 4672, 4698, 7045, 1102]
        event_id = random.choice(event_ids)
        return json.dumps({
            "EventID": event_id,
            "TimeCreated": self._ts().isoformat(),
            "Computer": random.choice(["DC01", "DC02", "FILESRV01", "WKS-001", "WKS-002", "WKS-003"]),
            "TargetUserName": random.choice(self.users),
            "SubjectUserName": random.choice(self.users),
            "IpAddress": random.choice(self.internal_ips + self.external_ips),
            "LogonType": random.choice([2, 3, 10]),
            "Level": random.choice([0, 2, 3, 4]),
        })

    def _gen_cef(self):
        """Generate CEF event."""
        vendors = [("Cisco", "ASA"), ("Fortinet", "FortiGate"),
                    ("PaloAlto", "PAN-OS"), ("CheckPoint", "SmartDefense")]
        vendor, product = random.choice(vendors)
        src = random.choice(self.external_ips + self.internal_ips)
        dst = random.choice(self.internal_ips)
        action = random.choice(["allow", "deny", "drop"])
        sig_id = random.choice([100, 200, 300, 302001, 733100])
        sev = random.choice([3, 5, 6, 7, 9])
        return f"CEF:0|{vendor}|{product}|1.0|{sig_id}|Security Event|{sev}|src={src} spt={random.randint(1024,65535)} dst={dst} dpt={random.choice([22,80,443,3389,445])} act={action} proto=TCP"

    def _gen_sudo(self):
        """Generate sudo event."""
        user = random.choice(self.users)
        host = random.choice(self.hosts)
        commands = [
            "/bin/systemctl restart nginx",
            "/bin/cat /var/log/auth.log",
            "/usr/bin/apt update",
            "/bin/grep root /etc/shadow",
            "/usr/bin/find / -name *.conf",
            "/bin/systemctl status docker",
            "/usr/bin/docker ps",
            "/bin/ls -la /root",
        ]
        cmd = random.choice(commands)
        ts = self._ts_str()
        return f"<86>{ts} {host} sudo: {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={cmd}"

    def _gen_malware(self):
        """Generate malware detection event."""
        src = random.choice(self.external_ips)
        dst = random.choice(self.internal_ips)
        fname = random.choice(["trojan.exe", "malware.dll", "backdoor.sh",
                                "ransomware.ps1", "dropper.bat", "keylogger.js"])
        return json.dumps({
            "timestamp": self._ts().isoformat(),
            "source_ip": src,
            "dest_ip": dst,
            "event_type": "av_malware",
            "action": "alert",
            "severity": "critical",
            "result": "success",
            "file_name": fname,
            "file_hash": random.choice(self.malware_hashes),
            "file_path": f"/tmp/{fname}",
            "product": "Windows Defender",
            "vendor": "Microsoft",
            "message": f"Malware detected: {fname}",
        })

    def _gen_json(self):
        """Generate generic JSON event."""
        return json.dumps({
            "timestamp": self._ts().isoformat(),
            "source_ip": random.choice(self.internal_ips + self.external_ips),
            "dest_ip": random.choice(self.internal_ips),
            "event_type": random.choice(["network", "system", "application"]),
            "action": random.choice(["connect", "disconnect", "read", "write", "execute"]),
            "severity": random.choice(["info", "info", "warning", "error"]),
            "message": f"Event from {random.choice(self.hosts)}",
        })

    def _gen_syslog5424(self):
        """Generate RFC 5424 syslog event."""
        host = random.choice(self.hosts)
        app = random.choice(["sshd", "cron", "systemd", "kernel", "auditd"])
        pri = random.choice([34, 38, 86, 134, 165])
        msg = random.choice([
            "session opened for user root",
            "starting daily cleanup",
            "service started successfully",
            "disk space warning: / at 85%",
            "audit log rotation",
        ])
        return f"<{pri}>1 {self._ts().isoformat()} {host}.example.com {app} {random.randint(1000,9999)} - - {msg}"


def send_to_api(host, port, raw_data, api_key=None):
    """Send an event to the SIEM API endpoint."""
    url = f"http://{host}:{port}/api/events"
    headers = {"Content-Type": "application/json"}

    data = json.dumps({"raw_data": raw_data}).encode("utf-8")

    try:
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.getcode() == 201
    except Exception as exc:
        logger.debug("API send error: %s", exc)
        return False


def run_simulator(host, port, rate, duration, event_types=None):
    """Run the log simulator.

    Args:
        host: API host.
        port: API port.
        rate: Events per second.
        duration: Duration in seconds (0 = infinite).
        event_types: Optional list of event types to generate.
    """
    generator = LogGenerator()
    start_time = time.time()
    total_sent = 0
    total_failed = 0

    logger.info("Starting log simulator: %d events/sec to %s:%d", rate, host, port)
    logger.info("Press Ctrl+C to stop")

    interval = 1.0 / rate if rate > 0 else 1.0

    try:
        while duration == 0 or (time.time() - start_time) < duration:
            batch_start = time.time()

            # Generate and send event
            event_type = random.choice(event_types) if event_types else None
            raw_data = generator.generate(event_type)
            generator.count += 1

            if send_to_api(host, port, raw_data):
                total_sent += 1
            else:
                total_failed += 1

            # Rate limiting
            elapsed = time.time() - batch_start
            sleep_time = interval - elapsed
            if sleep_time > 0:
                time.sleep(sleep_time)

            # Progress logging
            if generator.count % 100 == 0:
                elapsed_total = time.time() - start_time
                actual_rate = generator.count / elapsed_total if elapsed_total > 0 else 0
                logger.info("Sent: %d (rate: %.1f/s, failed: %d)",
                           generator.count, actual_rate, total_failed)

    except KeyboardInterrupt:
        logger.info("Simulator stopped by user")

    elapsed_total = time.time() - start_time
    logger.info("=" * 50)
    logger.info("Simulation complete!")
    logger.info("Total events: %d", generator.count)
    logger.info("Successfully sent: %d", total_sent)
    logger.info("Failed: %d", total_failed)
    logger.info("Duration: %.1f seconds", elapsed_total)
    logger.info("Average rate: %.1f events/sec", generator.count / max(elapsed_total, 1))
    logger.info("=" * 50)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="SIEM-Lite Log Ingest Simulator")
    parser.add_argument("--host", default="localhost", help="API host")
    parser.add_argument("--port", "-p", type=int, default=8443, help="API port")
    parser.add_argument("--rate", "-r", type=float, default=10, help="Events per second")
    parser.add_argument("--duration", "-d", type=int, default=0, help="Duration in seconds (0=infinite)")
    parser.add_argument("--count", "-n", type=int, default=0, help="Total events to send (overrides duration)")
    parser.add_argument("--types", nargs="*", help="Specific event types to generate")
    parser.add_argument("--burst", type=int, default=0, help="Send N events immediately then exit")

    args = parser.parse_args()

    if args.burst > 0:
        # Burst mode: send N events immediately
        generator = LogGenerator()
        logger.info("Sending %d events in burst mode...", args.burst)
        sent = 0
        for _ in range(args.burst):
            raw_data = generator.generate()
            if send_to_api(args.host, args.port, raw_data):
                sent += 1
        logger.info("Burst complete: %d/%d sent", sent, args.burst)
        return

    if args.count > 0:
        args.duration = int(args.count / max(args.rate, 1))

    run_simulator(args.host, args.port, args.rate, args.duration, args.types)


if __name__ == "__main__":
    main()
