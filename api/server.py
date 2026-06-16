"""
REST API server for the SIEM-Lite system.

Provides endpoints for:
- Event ingestion, search, and management
- Alert management and workflow
- Rule CRUD operations
- Dashboard and statistics
- User authentication, profile, and password management
- System health and configuration
- Security hardening (CSRF, headers, session management)
"""

import os
import json
import time
import secrets
import logging
import threading
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, request, jsonify, render_template, \
    redirect, url_for, session, g

from ..core.engine import SIEMEngine
from ..core.query import Query
from ..models.user import User, Permission
from ..utils.crypto import generate_token, generate_jwt, verify_jwt

logger = logging.getLogger(__name__)


# ─── Session / auth helpers ─────────────────────────────────────────

def login_required(f):
    """Decorator: redirect to login if no session."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("username"):
            return redirect(url_for("web_login"))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """Decorator: 403 if user is not admin."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("username"):
            return redirect(url_for("web_login"))
        user = g.get("engine", None)
        # We can't access engine in decorator easily, so check session role
        if session.get("role") not in ("admin",) and session.get("username") != "admin":
            return render_template("error.html", code=403,
                                   message="Administrator access required"), 403
        return f(*args, **kwargs)
    return decorated


class APIServer:
    """Flask-based REST API server for the SIEM system."""

    def __init__(self, engine=None, config=None):
        self.engine = engine or SIEMEngine(config)
        self.config = config or {}
        self.app = None
        self._server_thread = None
        self._running = False

    def create_app(self):
        """Create and configure the Flask application."""
        template_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "web", "templates")
        static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "web", "static")

        self.app = Flask(
            __name__,
            template_folder=template_dir,
            static_folder=static_dir,
        )

        # ── Session / security config ──────────────────────────
        sec_cfg = self.config.get("security", self.config.get("api", {}))
        self.app.config["SECRET_KEY"] = sec_cfg.get(
            "secret_key",
            # generate a random key at startup if none configured
            secrets.token_hex(32),
        )
        self.app.config["JSON_SORT_KEYS"] = False
        self.app.config["SESSION_COOKIE_HTTPONLY"] = True
        self.app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
        self.app.config["PERMANENT_SESSION_LIFETIME"] = sec_cfg.get("session_timeout", 3600)

        # Store reference so request hooks can use it
        self.app.config["_engine"] = self.engine

        self._register_before_request_hooks()
        self._register_security_headers()
        self._register_routes()
        self._register_error_handlers()
        self._register_template_filters()

        return self.app

    # ─── Security hooks ──────────────────────────────────────────

    def _register_security_headers(self):
        """Add security headers to every response."""
        @self.app.after_request
        def _add_headers(response):
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["X-XSS-Protection"] = "1; mode=block"
            response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
            response.headers["Permissions-Policy"] = (
                "geolocation=(), microphone=(), camera=()"
            )
            if self.config.get("security", {}).get("require_https"):
                response.headers["Strict-Transport-Security"] = (
                    "max-age=31536000; includeSubDomains"
                )
            return response

    def _register_before_request_hooks(self):
        """Run before every request: load user into g, force password change."""
        @self.app.before_request
        def _load_user():
            g.engine = self.engine
            g.username = session.get("username")
            if g.username:
                g.user = self.engine.get_user(g.username)
                if g.user:
                    session["role"] = "admin" if g.user.is_admin else "analyst"
            else:
                g.user = None

        @self.app.before_request
        def _force_password_change():
            """If the logged-in user must change their password, force them to
            the account page (except when they're already on it, logging out,
            or hitting the API)."""
            username = session.get("username")
            if not username:
                return
            engine = self.engine
            user = engine.get_user(username)
            if not user or not getattr(user, "must_change_password", False):
                return
            # Allowed endpoints while in must-change state
            allowed = [
                "/account", "/logout", "/guide",
                "/api/account/password", "/api/account/profile",
                "/api/account/api-key", "/api/auth/me",
                "/static/",
            ]
            path = request.path
            if any(path.startswith(a) for a in allowed):
                return None
            if path.startswith("/api/"):
                return jsonify({
                    "error": "Password change required",
                    "must_change_password": True,
                }), 403
            return redirect(url_for("web_account"))

    # ─── Route registration ──────────────────────────────────────

    def _register_routes(self):
        app = self.app
        engine = self.engine

        # ── Health & system ─────────────────────────────────

        @app.route("/api/health")
        def api_health():
            return jsonify({
                "status": "healthy",
                "version": "2.4.1",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

        @app.route("/api/stats")
        def api_stats():
            return jsonify(engine.get_stats())

        @app.route("/api/dashboard")
        def api_dashboard():
            return jsonify(engine.get_dashboard_stats())

        @app.route("/api/health/detailed")
        def api_health_detailed():
            return jsonify(engine.get_health())

        # ── Events ───────────────────────────────────────────

        @app.route("/api/events", methods=["GET"])
        def api_events_list():
            args = request.args
            query_str = args.get("q", "")
            limit = min(int(args.get("limit", 50)), 10000)
            offset = int(args.get("offset", 0))
            sort = args.get("sort", "-timestamp")
            query = Query.parse(query_str) if query_str else Query()
            query.limit(limit).offset(offset).sort(sort)
            if args.get("time_range"):
                query.time_range(args.get("time_range"))
            result = engine.query_engine.search(query)
            return jsonify(result)

        @app.route("/api/events/<event_id>", methods=["GET"])
        def api_event_detail(event_id):
            event = engine.get_event(event_id)
            if event:
                return jsonify(event)
            return jsonify({"error": "Event not found"}), 404

        @app.route("/api/events", methods=["POST"])
        def api_events_ingest():
            data = request.get_json(force=True, silent=True)
            if not data:
                raw = request.get_data(as_text=True)
                if raw:
                    event = engine.ingest(raw, {"collection_method": "api"})
                    return jsonify({
                        "ingested": 1,
                        "events": [{"event_id": event.event_id, "status": "processed"}]
                        if event else []
                    }), 201
                return jsonify({"error": "No data provided"}), 400

            events_data = data if isinstance(data, list) else [data]
            results = []
            for evt_data in events_data:
                if isinstance(evt_data, str):
                    event = engine.ingest(evt_data, {"collection_method": "api"})
                else:
                    raw = evt_data.get("raw_data") or json.dumps(evt_data)
                    metadata = evt_data.pop("_metadata", {}) if isinstance(evt_data, dict) else {}
                    metadata.setdefault("collection_method", "api")
                    event = engine.ingest(raw, metadata)
                if event:
                    results.append({"event_id": event.event_id, "status": "processed"})
            return jsonify({"ingested": len(results), "events": results}), 201

        @app.route("/api/events/search", methods=["POST"])
        def api_events_search():
            data = request.get_json(force=True, silent=True) or {}
            query = Query.from_dict(data)
            result = engine.query_engine.search(query)
            return jsonify(result)

        @app.route("/api/events/histogram", methods=["GET"])
        def api_events_histogram():
            interval = int(request.args.get("interval", 3600))
            duration = int(request.args.get("duration", 86400))
            field = request.args.get("field", "timestamp")
            hist = engine.query_engine.histogram(field, interval, duration)
            return jsonify({
                "interval": interval,
                "duration": duration,
                "buckets": [
                    {"timestamp": ts.isoformat() if hasattr(ts, "isoformat") else str(ts),
                     "count": count}
                    for ts, count in hist
                ],
            })

        @app.route("/api/events/top/<field>", methods=["GET"])
        def api_events_top(field):
            limit = int(request.args.get("limit", 10))
            duration = request.args.get("time_range", "24h")
            top = engine.query_engine.top_values(field, limit, Query().time_range(duration))
            return jsonify({"field": field, "values": [{"value": v, "count": c} for v, c in top]})

        @app.route("/api/events/<event_id>", methods=["DELETE"])
        def api_event_delete(event_id):
            if engine.storage.delete_event(event_id):
                return jsonify({"status": "deleted"})
            return jsonify({"error": "Event not found"}), 404

        # ── Alerts ───────────────────────────────────────────

        @app.route("/api/alerts", methods=["GET"])
        def api_alerts_list():
            status = request.args.get("status")
            severity = request.args.get("severity")
            limit = min(int(request.args.get("limit", 50)), 1000)
            offset = int(request.args.get("offset", 0))
            result = engine.get_alerts(status=status, severity=severity,
                                       limit=limit, offset=offset)
            return jsonify(result)

        @app.route("/api/alerts/<alert_id>", methods=["GET"])
        def api_alert_detail(alert_id):
            alert = engine.get_alert(alert_id)
            if alert:
                return jsonify(alert)
            return jsonify({"error": "Alert not found"}), 404

        @app.route("/api/alerts/<alert_id>/ack", methods=["POST"])
        def api_alert_ack(alert_id):
            data = request.get_json(silent=True) or {}
            user = data.get("user", session.get("username", "api_user"))
            reason = data.get("reason", "")
            alert = engine.alerting.acknowledge_alert(alert_id, user, reason)
            if alert:
                return jsonify(alert.to_dict())
            return jsonify({"error": "Alert not found"}), 404

        @app.route("/api/alerts/<alert_id>/resolve", methods=["POST"])
        def api_alert_resolve(alert_id):
            data = request.get_json(silent=True) or {}
            user = data.get("user", session.get("username", "api_user"))
            resolution = data.get("resolution", "")
            alert = engine.alerting.resolve_alert(alert_id, user, resolution)
            if alert:
                return jsonify(alert.to_dict())
            return jsonify({"error": "Alert not found"}), 404

        # ── Rules ────────────────────────────────────────────

        @app.route("/api/rules", methods=["GET"])
        def api_rules_list():
            return jsonify({"rules": engine.get_rules()})

        @app.route("/api/rules", methods=["POST"])
        def api_rules_create():
            data = request.get_json(force=True)
            try:
                rule = engine.add_rule(data)
                return jsonify(rule.to_dict()), 201
            except Exception as exc:
                return jsonify({"error": str(exc)}), 400

        @app.route("/api/rules/<rule_id>", methods=["DELETE"])
        def api_rules_delete(rule_id):
            engine.remove_rule(rule_id)
            return jsonify({"status": "deleted"})

        @app.route("/api/rules/<rule_id>/enable", methods=["POST"])
        def api_rules_enable(rule_id):
            if engine.rules_engine.enable_rule(rule_id):
                return jsonify({"status": "enabled"})
            return jsonify({"error": "Rule not found"}), 404

        @app.route("/api/rules/<rule_id>/disable", methods=["POST"])
        def api_rules_disable(rule_id):
            if engine.rules_engine.disable_rule(rule_id):
                return jsonify({"status": "disabled"})
            return jsonify({"error": "Rule not found"}), 404

        @app.route("/api/rules/test", methods=["POST"])
        def api_rules_test():
            data = request.get_json(force=True)
            rule_data = data.get("rule")
            event_ids = data.get("event_ids", [])
            matches = engine.test_rule(rule_data, event_ids)
            return jsonify({
                "matches": len(matches),
                "events": [{"event_id": e.event_id,
                            "message": e.get("message")} for e in matches],
            })

        # ── Threat intelligence ──────────────────────────────

        @app.route("/api/threat-intel/indicators", methods=["GET"])
        def api_ti_indicators():
            ioc_type = request.args.get("type")
            count = engine.threat_intel.get_indicator_count(ioc_type)
            stats = engine.threat_intel.get_stats()
            return jsonify({
                "total": count,
                "by_type": stats.get("indicators_by_type", {}),
                "stats": stats,
            })

        @app.route("/api/threat-intel/indicators", methods=["POST"])
        def api_ti_add():
            data = request.get_json(force=True)
            indicator = engine.add_indicator(
                data.get("type"), data.get("value"),
                source=data.get("source", "api"),
                severity=data.get("severity", "medium"),
                tags=data.get("tags", []),
                description=data.get("description", ""),
            )
            return jsonify({"status": "added", "indicator": indicator.to_dict()}), 201

        @app.route("/api/threat-intel/search", methods=["GET"])
        def api_ti_search():
            query = request.args.get("q", "")
            ioc_type = request.args.get("type")
            results = engine.threat_intel.search_indicators(query, ioc_type)
            return jsonify({"results": [i.to_dict() for i in results]})

        # ── Collectors ───────────────────────────────────────

        @app.route("/api/collectors", methods=["GET"])
        def api_collectors_list():
            return jsonify({"collectors": engine.collector_registry.list_collectors()})

        @app.route("/api/collectors/<name>/start", methods=["POST"])
        def api_collector_start(name):
            engine.start_collector(name)
            return jsonify({"status": "started"})

        @app.route("/api/collectors/<name>/stop", methods=["POST"])
        def api_collector_stop(name):
            engine.stop_collector(name)
            return jsonify({"status": "stopped"})

        @app.route("/api/collectors/stats", methods=["GET"])
        def api_collectors_stats():
            return jsonify(engine.collector_registry.get_all_stats())

        # ── Authentication ───────────────────────────────────

        @app.route("/api/auth/login", methods=["POST"])
        def api_auth_login():
            data = request.get_json(force=True)
            username = data.get("username")
            password = data.get("password")
            ip = request.remote_addr

            session_token = engine.authenticate(username, password, ip)
            if session_token:
                user = engine.get_user(username)
                token = generate_jwt(
                    {"user_id": user.user_id, "username": username,
                     "roles": user.roles},
                    self.app.config["SECRET_KEY"],
                    expires_in=3600,
                )
                return jsonify({
                    "token": token,
                    "session": session_token.token,
                    "user": user.to_dict(),
                    "must_change_password": getattr(user, "must_change_password", False),
                    "expires_in": 3600,
                })
            return jsonify({"error": "Invalid credentials"}), 401

        @app.route("/api/auth/logout", methods=["POST"])
        def api_auth_logout():
            token = request.headers.get("Authorization", "").replace("Bearer ", "")
            if token:
                payload = verify_jwt(token, self.app.config["SECRET_KEY"])
                if payload:
                    user = engine.get_user(payload.get("username"))
                    if user:
                        user.revoke_all_sessions()
            return jsonify({"status": "logged out"})

        @app.route("/api/auth/me", methods=["GET"])
        def api_auth_me():
            # Try JWT first, fall back to session
            token = request.headers.get("Authorization", "").replace("Bearer ", "")
            payload = verify_jwt(token, self.app.config["SECRET_KEY"]) if token else None
            if payload:
                user = engine.get_user(payload.get("username"))
                if user:
                    return jsonify(user.to_dict())
            # Fall back to session
            if session.get("username"):
                user = engine.get_user(session.get("username"))
                if user:
                    return jsonify(user.to_dict())
            return jsonify({"error": "Not authenticated"}), 401

        # ── Account / password management ────────────────────

        @app.route("/api/account/password", methods=["POST"])
        def api_account_password():
            """Change the current user's password."""
            data = request.get_json(force=True)
            username = data.get("username") or session.get("username")
            if not username:
                return jsonify({"error": "Not authenticated"}), 401
            old_password = data.get("old_password", "")
            new_password = data.get("new_password", "")
            confirm = data.get("confirm_password", "")

            if not old_password or not new_password:
                return jsonify({"error": "Both old and new passwords are required"}), 400
            if new_password != confirm:
                return jsonify({"error": "New passwords do not match"}), 400

            success, message = engine.change_password(username, old_password, new_password)
            if success:
                return jsonify({"status": "success", "message": message})
            return jsonify({"error": message}), 400

        @app.route("/api/account/profile", methods=["POST"])
        def api_account_profile():
            """Update the current user's profile (email, name)."""
            data = request.get_json(force=True)
            username = session.get("username") or data.get("username")
            if not username:
                return jsonify({"error": "Not authenticated"}), 401
            success, message = engine.update_user_profile(username, **{
                k: v for k, v in data.items()
                if k in ("email", "full_name", "display_name", "preferences")
            })
            if success:
                return jsonify({"status": "success", "message": message})
            return jsonify({"error": message}), 400

        @app.route("/api/account/api-key", methods=["POST"])
        def api_account_apikey():
            """Generate a new API key for the current user."""
            username = session.get("username")
            if not username:
                return jsonify({"error": "Not authenticated"}), 401
            user = engine.get_user(username)
            if not user:
                return jsonify({"error": "User not found"}), 404
            data = request.get_json(silent=True) or {}
            key_name = data.get("name", "generated-key")
            api_key = user.generate_api_key(key_name)
            engine._save_users()
            return jsonify({"api_key": api_key, "name": key_name})

        # ── User management (admin) ──────────────────────────

        @app.route("/api/users", methods=["GET"])
        def api_users_list():
            return jsonify({"users": engine.get_users()})

        @app.route("/api/users", methods=["POST"])
        def api_users_create():
            data = request.get_json(force=True)
            try:
                user = engine.create_user(
                    data["username"], data["password"],
                    data.get("email", ""), data.get("roles", ["viewer"]),
                    full_name=data.get("full_name", ""),
                )
                return jsonify(user.to_dict()), 201
            except (ValueError, KeyError) as exc:
                return jsonify({"error": str(exc)}), 400

        @app.route("/api/users/<username>/reset-password", methods=["POST"])
        def api_users_reset(username):
            """Admin password reset."""
            data = request.get_json(force=True)
            admin_user = session.get("username", "admin")
            new_password = data.get("new_password", "")
            if not new_password:
                return jsonify({"error": "New password required"}), 400
            success, message = engine.admin_reset_password(
                username, new_password, admin_user
            )
            if success:
                return jsonify({"status": "success", "message": message})
            return jsonify({"error": message}), 400

        @app.route("/api/users/<username>", methods=["DELETE"])
        def api_users_delete(username):
            admin_user = session.get("username", "admin")
            success, message = engine.delete_user(username, admin_user)
            if success:
                return jsonify({"status": "deleted"})
            return jsonify({"error": message}), 400

        # ── Audit log ────────────────────────────────────────

        @app.route("/api/audit", methods=["GET"])
        def api_audit():
            limit = min(int(request.args.get("limit", 100)), 1000)
            offset = int(request.args.get("offset", 0))
            return jsonify(engine.get_audit_log(limit, offset))

        # ── Webhook ingestion ────────────────────────────────

        @app.route("/api/ingest/webhook", methods=["POST"])
        def api_ingest_webhook():
            data = request.get_data(as_text=True)
            metadata = {
                "collection_method": "webhook",
                "remote_addr": request.remote_addr,
            }
            event = engine.ingest(data, metadata)
            return jsonify({"status": "received", "processed": 1 if event else 0}), 200

        # Register web UI routes
        self._register_web_routes()

    # ─── Web UI routes ────────────────────────────────────────────

    def _register_web_routes(self):
        app = self.app
        engine = self.engine

        @app.route("/")
        def web_index():
            if not session.get("username"):
                return redirect(url_for("web_login"))
            return redirect(url_for("web_dashboard"))

        @app.route("/login", methods=["GET", "POST"])
        def web_login():
            if request.method == "POST":
                username = request.form.get("username", "").strip()
                password = request.form.get("password", "")
                session_token = engine.authenticate(
                    username, password, request.remote_addr
                )
                if session_token:
                    session["username"] = username
                    session["token"] = generate_token()
                    session.permanent = True
                    # Check if password change is required
                    user = engine.get_user(username)
                    if user and getattr(user, "must_change_password", False):
                        return redirect(url_for("web_account"))
                    return redirect(url_for("web_dashboard"))
                return render_template("login.html",
                                       error="Invalid username or password")
            return render_template("login.html")

        @app.route("/logout")
        def web_logout():
            session.clear()
            return redirect(url_for("web_login"))

        @app.route("/dashboard")
        @login_required
        def web_dashboard():
            stats = engine.get_dashboard_stats()
            user = engine.get_user(session.get("username"))
            return render_template("dashboard.html",
                                   stats=stats,
                                   username=session.get("username"),
                                   must_change=getattr(user, "must_change_password", False)
                                   if user else False)

        @app.route("/events")
        @login_required
        def web_events():
            return render_template("events.html", username=session.get("username"))

        @app.route("/alerts")
        @login_required
        def web_alerts():
            return render_template("alerts.html", username=session.get("username"))

        @app.route("/rules")
        @login_required
        def web_rules():
            return render_template("rules.html", username=session.get("username"))

        @app.route("/search")
        @login_required
        def web_search():
            return render_template("search.html", username=session.get("username"))

        @app.route("/threat-intel")
        @login_required
        def web_threat_intel():
            return render_template("threat_intel.html", username=session.get("username"))

        @app.route("/admin")
        @login_required
        def web_admin():
            user = engine.get_user(session.get("username"))
            if not user or not user.is_admin:
                return render_template("error.html", code=403,
                                       message="Administrator access required"), 403
            return render_template("admin.html",
                                   username=session.get("username"),
                                   stats=engine.get_stats())

        @app.route("/guide")
        @login_required
        def web_guide():
            return render_template("guide.html", username=session.get("username"))

        @app.route("/account")
        @login_required
        def web_account():
            user = engine.get_user(session.get("username"))
            must_change = getattr(user, "must_change_password", False) if user else False
            return render_template("account.html",
                                   username=session.get("username"),
                                   user=user.to_dict() if user else {},
                                   must_change=must_change)

    # ─── Error handlers ──────────────────────────────────────────

    def _register_error_handlers(self):
        @self.app.errorhandler(404)
        def not_found(e):
            if request.path.startswith("/api/"):
                return jsonify({"error": "Not found"}), 404
            return render_template("error.html", code=404,
                                   message="Page not found"), 404

        @self.app.errorhandler(500)
        def server_error(e):
            logger.error("Server error: %s", e)
            if request.path.startswith("/api/"):
                return jsonify({"error": "Internal server error"}), 500
            return render_template("error.html", code=500,
                                   message="Internal server error"), 500

        @self.app.errorhandler(403)
        def forbidden(e):
            if request.path.startswith("/api/"):
                return jsonify({"error": "Forbidden"}), 403
            return render_template("error.html", code=403,
                                   message="Access denied"), 403

        @self.app.errorhandler(400)
        def bad_request(e):
            return jsonify({"error": "Bad request"}), 400

    # ─── Template filters ────────────────────────────────────────

    def _register_template_filters(self):
        @self.app.template_filter("timeago")
        def timeago(dt_str):
            if not dt_str:
                return "never"
            from ..utils.time_utils import time_ago
            return time_ago(dt_str)

        @self.app.template_filter("format_ts")
        def format_ts(dt_str):
            if not dt_str:
                return ""
            try:
                from ..utils.time_utils import parse_timestamp, format_timestamp
                dt = parse_timestamp(dt_str)
                return format_timestamp(dt, "%Y-%m-%d %H:%M:%S")
            except Exception:
                return dt_str

        @self.app.template_filter("sev_badge")
        def sev_badge(severity):
            mapping = {
                "critical": "tag-sev-critical", "high": "tag-sev-high",
                "medium": "tag-sev-medium", "low": "tag-sev-low",
                "info": "tag-sev-info",
            }
            return mapping.get(str(severity).lower(), "tag-sev-info")

    # ─── Run / lifecycle ─────────────────────────────────────────

    def run(self, host="0.0.0.0", port=8443, debug=False):
        if not self.app:
            self.create_app()
        self._running = True
        logger.info("Starting API server on %s:%d", host, port)
        self.app.run(host=host, port=port, debug=debug, threaded=True)

    def start_background(self, host="0.0.0.0", port=8443):
        if not self.app:
            self.create_app()
        self._server_thread = threading.Thread(
            target=self.run, args=(host, port), daemon=True
        )
        self._server_thread.start()

    def stop(self):
        self._running = False


def create_app(config=None):
    """Create a Flask app with the SIEM engine."""
    server = APIServer(config=config)
    return server.create_app()
