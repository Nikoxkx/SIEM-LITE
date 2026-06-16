# Contributing to SIEM-Lite

Thank you for your interest in contributing! This document covers the basics.

## Development Setup

```bash
git clone https://github.com/yourusername/siem-lite.git
cd siem-lite
pip install -r requirements.txt
python run.py --demo --debug
```

Open http://localhost:8443 — login is `admin` / `admin123` (change immediately).

## Project Structure

```
siem_lite/
├── models/        # Data models (Event, Alert, Rule, User, etc.)
├── parsers/       # Log format parsers (Syslog, CEF, JSON, etc.)
├── collectors/    # Log source connectors (Syslog, File, HTTP, etc.)
├── core/          # Processing engines (pipeline, rules, correlation, etc.)
├── api/           # Flask REST API + web server
├── web/           # HTML templates, CSS, JavaScript
├── config/        # YAML configuration and rule definitions
├── utils/         # Utility functions (crypto, geoip, validators, etc.)
├── tests/         # Pytest test suite
├── scripts/       # Helper scripts (log simulator, etc.)
├── run.py         # Main entry point
└── Dockerfile     # Container deployment
```

## Adding a New Detection Rule

Edit `config/rules/detection_rules.yaml` or `correlation_rules.yaml`:

```yaml
- rule_id: "CUSTOM-001"
  name: "My Custom Rule"
  description: "What this detects"
  rule_type: detection
  severity: medium
  status: active
  category: custom
  conditions:
    - - field: action
        operator: eq
        value: logon_failed
  logic: or
  actions: [alert]
```

## Adding a New Parser

1. Create `parsers/my_parser.py` inheriting from `BaseParser`
2. Implement the `parse()` method
3. Register it in `core/engine.py` → `_init_parsers()`

## Running Tests

```bash
python -m pytest tests/ -v
```

## Code Style

- Follow PEP 8
- Add docstrings to public functions and classes
- Keep functions focused and readable

## Submitting Changes

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes
4. Push and open a Pull Request

## Reporting Security Issues

**Do not open a public issue for security vulnerabilities.** Instead, email security concerns directly so they can be addressed responsibly.
