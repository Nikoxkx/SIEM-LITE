# SIEM-Lite: Log Correlation Engine

[![Python](https://img.shields.io/badge/Python-3.8%2B-black?logo=python)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-black)]()
[![Docker](https://img.shields.io/badge/Docker-Ready-black?logo=docker)]()

A lightweight, open-source **Security Information and Event Management** (SIEM) system for log aggregation, correlation, threat detection, and alerting.

Built for security teams who need real-time detection without the complexity or cost of enterprise SIEM platforms.

---

## Features

- **Multi-source collection** — Syslog (UDP/TCP), file tailing, HTTP polling, webhooks, Windows Events, AWS/GCP/Azure
- **Universal parsing** — Syslog (RFC 3164/5424), JSON, CEF, LEEF, Apache/Nginx, Windows Events, CSV/TSV, custom regex/Grok
- **Event normalization** — Maps all formats into one unified schema
- **Correlation engine** — Time-window pattern matching with thresholds (brute force, port scanning, C2 beaconing, etc.)
- **Detection rules** — 37 built-in rules covering authentication, malware, network, web attacks, and defense evasion
- **Threat intelligence** — IOC matching (IPs, domains, hashes, URLs, CIDR ranges) with built-in feeds
- **Anomaly detection** — Statistical baselining with Z-score, EWMA, and IQR methods
- **Risk scoring** — Multi-factor 0–100 scoring per event
- **Alert workflow** — Acknowledge, resolve, escalate with full evidence trail
- **Web dashboard** — Black-and-white security console with real-time monitoring
- **REST API** — Full programmatic access to all features
- **RBAC** — Role-based access (admin, analyst, responder, viewer)
- **Docker-ready** — One-command containerized deployment

---

## Quick Start

### Option 1: Direct (Python)

```bash
git clone https://github.com/yourusername/siem-lite.git
cd siem-lite
pip install -r requirements.txt
python run.py --demo
```

Open **http://localhost:8443** → Login: `admin` / `admin123`

> ⚠️ **You will be forced to change your password on first login.**

### Option 2: Docker

```bash
git clone https://github.com/yourusername/siem-lite.git
cd siem-lite
docker compose up -d
```

Open **http://localhost:8443**

---

## Security First

| Feature | Detail |
|---------|--------|
| **Forced password change** | Default credentials are disabled after first login |
| **Password strength enforcement** | Min 8 chars, upper+lower+number+special required |
| **Account lockout** | Automatic after 5 failed attempts |
| **PBKDF2 password hashing** | 100,000 iterations with random salt |
| **Security headers** | X-Frame-Options, X-Content-Type-Options, CSP-ready |
| **JWT tokens** | Signed API authentication |
| **Audit logging** | Every user and system action is logged |
| **Session security** | HTTPOnly, SameSite cookies |

---

## Using It in Production

### 1. Change the Secret Key

Edit `config/siem.yaml`:
```yaml
security:
  secret_key: "your-random-64-char-secret-here"
```

Generate one:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

### 2. Put It Behind HTTPS (nginx)

```nginx
server {
    listen 443 ssl;
    server_name siem.yourorg.com;

    ssl_certificate     /etc/ssl/certs/siem.crt;
    ssl_certificate_key /etc/ssl/private/siem.key;

    location / {
        proxy_pass http://127.0.0.1:8443;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### 3. Run as a Service (systemd)

```ini
# /etc/systemd/system/siem-lite.service
[Unit]
Description=SIEM-Lite
After=network.target

[Service]
Type=simple
User=siem
WorkingDirectory=/opt/siem-lite
ExecStart=/usr/bin/python3 run.py --port 8443
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable siem-lite
sudo systemctl start siem-lite
```

### 4. Feed It Real Logs

Point your log sources at SIEM-Lite:

| Source | Method |
|--------|--------|
| Linux servers | Configure rsyslog to forward to `SIEM_IP:514` |
| Firewalls | Send syslog or CEF events |
| Windows | Forward Event Logs or use the Windows collector |
| Cloud (AWS/GCP/Azure) | Enable the cloud collectors |
| Custom apps | POST to `/api/events` or `/api/ingest/webhook` |

### Production Checklist

- [ ] Changed all default passwords
- [ ] Set `secret_key` to a random value
- [ ] Deployed behind HTTPS reverse proxy
- [ ] Created individual user accounts for each analyst
- [ ] Configured real log collectors
- [ ] Tested alerting/notification channels (webhook/email)
- [ ] Set up database backups (`siem.db`)
- [ ] Reviewed the audit log

---

## Architecture

```
┌────────────┐   ┌────────────┐   ┌────────────┐   ┌──────────────┐
│ Collectors │──▶│   Parsers   │──▶│ Normalizer │──▶│  Enrichment  │
│ Syslog     │   │ Syslog/CEF  │   │ Canonical  │   │ GeoIP/Assets │
│ File       │   │ JSON/LEEF   │   │ Schema     │   │              │
│ HTTP       │   │ Regex/Win   │   │            │   │              │
└────────────┘   └────────────┘   └────────────┘   └──────┬───────┘
                                                          │
                 ┌────────────────────────────────────────┘
                 ▼
┌───────────────┴────────────────────────────────────────────┐
│                    Detection Pipeline                       │
│  ┌─────────┐  ┌───────────┐  ┌─────────┐  ┌────────────┐ │
│  │Threat   │  │   Rules   │  │Correl-  │  │  Anomaly   │ │
│  │Intel    │  │  Engine   │  │ation    │  │  Engine    │ │
│  └────┬────┘  └─────┬─────┘  └────┬────┘  └─────┬──────┘ │
│       └──────┬──────┴─────────────┴─────────────┘        │
│              ▼                                            │
│     ┌────────────┐     ┌──────────┐     ┌──────────┐     │
│     │Risk Scoring│────▶│ Alerting │────▶│ Storage  │     │
│     └────────────┘     └──────────┘     │(SQLite)  │     │
│                                         └──────────┘     │
└───────────────────────────────────────────────────────────┘
                 │                          │
                 ▼                          ▼
         ┌──────────────┐          ┌───────────────┐
         │  Web UI/API  │          │  REST API     │
         │  Dashboard   │          │  /api/*       │
         └──────────────┘          └───────────────┘
```

---

## Screenshots

| Dashboard | Events |
|-----------|--------|
| Real-time KPIs, severity breakdown, pipeline status | Filterable event stream with risk scores |
| ![Dashboard](preview_dashboard.png) | |

---

## Configuration

Main config: `config/siem.yaml`

Rules: `config/rules/detection_rules.yaml`, `config/rules/correlation_rules.yaml`

See the [Guide](web/templates/guide.html) page in the dashboard for full documentation.

---

## API Reference

```bash
# Authenticate
curl -X POST http://localhost:8443/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"yourpassword"}'

# Search events
curl "http://localhost:8443/api/events?q=severity:high"

# Ingest a log
curl -X POST http://localhost:8443/api/events \
  -H "Content-Type: application/json" \
  -d '{"raw_data": "<34> host sshd: Failed password from 1.2.3.4"}'

# List alerts
curl "http://localhost:8443/api/alerts?status=open"

# Dashboard stats
curl "http://localhost:8443/api/dashboard"
```

---

## Tech Stack

- **Backend**: Python 3.8+, Flask
- **Storage**: SQLite (built-in, zero external dependencies)
- **Frontend**: Vanilla JS + HTML + CSS (no build step)
- **Dependencies**: Only Flask + PyYAML

---

## License

MIT — see [LICENSE](LICENSE)

---

## Acknowledgments

Built as a demonstration of practical SIEM architecture. Not affiliated with any commercial SIEM vendor.
