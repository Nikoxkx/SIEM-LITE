# How to Run SIEM-Lite on Your Device

Complete step-by-step instructions for Mac, Windows, and Linux.

---

## Prerequisites

You need **Python 3.8 or newer** installed on your computer.

### Check if you have Python

Open a terminal (Mac: Terminal app, Windows: Command Prompt or PowerShell, Linux: your shell) and type:

```
python3 --version
```

You should see something like `Python 3.11.5`. If you get an error or it says Python 2, install Python first:

- **Mac**:   `brew install python` (or download from https://python.org)
- **Windows**: Download from https://python.org (check "Add Python to PATH" during install)
- **Linux**: `sudo apt install python3 python3-pip` (Ubuntu/Debian) or your distro's package manager

---

## Step 1 — Open a Terminal in the `siem_lite` Folder

Navigate to wherever you saved the `siem_lite` folder:

```
cd /path/to/siem_lite
```

For example:
- **Mac/Linux**: `cd ~/Downloads/siem_lite`
- **Windows**: `cd C:\Users\YourName\Downloads\siem_lite`

---

## Step 2 — Install the Two Dependencies

```
pip3 install Flask PyYAML
```

That's it — just two packages. Everything else is built into Python.

> **Windows note**: If `pip3` doesn't work, try `pip` or `python -m pip install Flask PyYAML`.

---

## Step 3 — Start the Server

### Quick Start (with demo data — recommended for first run)

```
python3 run.py --demo
```

This starts the server AND generates 500 realistic sample log events so you can immediately see alerts, detections, and the dashboard in action.

### Other ways to run

| Command | What it does |
|---------|-------------|
| `python3 run.py` | Start with empty database (no demo data) |
| `python3 run.py --demo --demo-events 2000` | Generate 2000 sample events |
| `python3 run.py --port 8080` | Run on a custom port |
| `python3 run.py --debug` | Debug mode (auto-reload on code changes) |
| `python3 run.py --demo --collectors` | Start with demo data + log collectors |

> **Windows**: Use `python` instead of `python3` if that's what your system uses.

---

## Step 4 — Open the Web Interface

Once the server is running, open your web browser and go to:

```
http://localhost:8443
```

You'll see the login screen. Log in with:

```
Username: admin
Password: admin123
```

(These are pre-filled on the login page — just click "Sign In".)

---

## What You'll See

After logging in, use the left sidebar to navigate:

- **Dashboard** — Overview of events, alerts, rules, and pipeline health
- **Events** — Browse all ingested log events, filter and search
- **Alerts** — Triage and respond to security alerts (acknowledge, resolve)
- **Search** — Query events with field-level syntax (`source_ip:1.2.3.4 severity:high`)
- **Threat Intel** — View and manage threat indicators
- **Rules** — View, create, enable, and disable detection rules
- **Admin** — System stats, collector status, user management, audit log

---

## Feeding It Your Own Logs

### Option A — Via the API (easiest)

Send any log line to the ingest endpoint:

```
curl -X POST http://localhost:8443/api/events \
  -H "Content-Type: application/json" \
  -d '{"raw_data": "<34>Oct 11 22:14:15 myserver sshd[1234]: Failed password for root from 1.2.3.4"}'
```

### Option B — Via the webhook endpoint

```
curl -X POST http://localhost:8443/api/ingest/webhook \
  -d 'source_ip=1.2.3.4 action=login_failed severity=high message="auth failure"'
```

### Option C — Using the log simulator (built-in)

The simulator generates realistic events continuously:

```
python3 scripts/ingest_simulator.py --rate 10
```

This sends 10 events/second to the running server. Press Ctrl+C to stop.

### Option D — Configure real collectors

Edit `config/siem.yaml` and enable collectors, then start with `--collectors`:

```yaml
collectors:
  syslog_udp:
    type: syslog
    protocol: udp
    host: 0.0.0.0
    port: 514
    enabled: true          # <-- change to true

  file_logs:
    type: file
    directory: /var/log
    pattern: "*.log"
    enabled: true          # <-- change to true
```

Then run:
```
python3 run.py --collectors
```

---

## Stopping the Server

Press `Ctrl+C` in the terminal window where the server is running.

---

## Common Issues

### "Port 8443 is already in use"

Use a different port:
```
python3 run.py --demo --port 9000
```
Then open `http://localhost:9000`

### "ModuleNotFoundError: No module named 'flask'"

Re-run the install:
```
pip3 install Flask PyYAML
```

### "Permission denied" on port 514 (syslog collector)

Ports below 1024 require admin/root. Use a higher port in `config/siem.yaml`:
```yaml
collectors:
  syslog_udp:
    port: 1514    # instead of 514
```

### The database file

The SQLite database (`siem.db`) is created in the `siem_lite` folder. Delete it to start fresh:
```
rm siem.db       # Mac/Linux
del siem.db      # Windows
```

---

## Running the Tests

```
cd siem_lite
python3 -m pytest tests/ -v
```
