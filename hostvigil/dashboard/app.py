"""
HostVigil Dashboard - Flask application factory.

Provides both HTML views and JSON API endpoints for network monitoring data.
Binds to 127.0.0.1 only by default (stealth - no network exposure).
"""

import functools
import ipaddress
import json
import math
import os
import re
import shlex
import sqlite3
import sys
import threading
import time
from collections import deque
from contextlib import contextmanager
from pathlib import Path

from flask import Flask, jsonify, redirect, render_template, request, session, url_for

# Module-level stats cache for _get_stats()
_stats_cache = {"data": None, "time": 0}
_stats_lock = threading.Lock()

# Module-level scan log buffer for SSE streaming
_scan_log_buffer = deque(maxlen=200)

# Parses lines written by hostvigil.utils.setup_logging(), e.g.:
# 2026-08-06T17:22:04.009Z myhost hostvigil[72797] WARNING hostvigil.orchestrator message text
_LOG_LINE_RE = re.compile(r"^(?P<time>\S+)Z \S+ hostvigil\[\d+\] (?P<level>[A-Z]+) (?P<name>\S+) (?P<message>.*)$")


def _parse_log_line(line: str):
    """Parse one line of data/logs/hostvigil.log into a {level, message, time} dict."""
    line = line.rstrip("\r\n")
    if not line.strip():
        return None
    m = _LOG_LINE_RE.match(line)
    if m:
        return {
            "level": m.group("level"),
            "message": f"{m.group('name')}: {m.group('message')}",
            "time": m.group("time") + "Z",
        }
    from datetime import datetime, timezone

    return {"level": "INFO", "message": line, "time": datetime.now(timezone.utc).isoformat()}


def _read_log_tail(path, max_lines: int = 500):
    """Read up to the last max_lines lines of the log file without loading it whole."""
    p = Path(path)
    if not p.exists():
        return []
    try:
        with open(p, "rb") as f:
            f.seek(0, os.SEEK_END)
            file_size = f.tell()
            block_size = 8192
            data = b""
            pos = file_size
            while pos > 0 and data.count(b"\n") <= max_lines:
                read_size = min(block_size, pos)
                pos -= read_size
                f.seek(pos)
                data = f.read(read_size) + data
            text = data.decode("utf-8", errors="replace")
            return text.splitlines()[-max_lines:]
    except OSError:
        return []


def _log_tail_start_position(path):
    """Return (byte_offset, inode) at the current end of the log file, for tail -f style streaming."""
    try:
        stat = Path(path).stat()
        return stat.st_size, stat.st_ino
    except OSError:
        return 0, None


def _read_log_new_lines(path, pos: int, inode):
    """Read any complete new lines appended to the log file since (pos, inode).

    Handles log rotation (inode change or truncation) by resetting to the start,
    and never returns a not-yet-newline-terminated partial last line.
    """
    p = Path(path)
    try:
        stat = p.stat()
    except OSError:
        return pos, inode, []
    if (inode is not None and stat.st_ino != inode) or stat.st_size < pos:
        pos = 0
    inode = stat.st_ino
    if stat.st_size <= pos:
        return pos, inode, []
    try:
        with open(p, "rb") as f:
            f.seek(pos)
            chunk = f.read(stat.st_size - pos)
    except OSError:
        return pos, inode, []
    last_newline = chunk.rfind(b"\n")
    if last_newline == -1:
        return pos, inode, []
    complete = chunk[: last_newline + 1]
    new_pos = pos + len(complete)
    lines = [line for line in complete.decode("utf-8", errors="replace").split("\n") if line != ""]
    return new_pos, inode, lines


# Login rate-limiting: track failed attempts per IP
_login_attempts = {}  # {ip: {'count': int, 'locked_until': float, 'last_attempt': float}}
_login_attempts_lock = threading.Lock()


def create_app(config: dict = None):
    """Application factory for the HostVigil dashboard.

    Args:
        config: Optional configuration dictionary. Expected keys:
            - db_path: Path to SQLite database
            - secret_key: Flask secret key
            - refresh_interval: Auto-refresh interval in seconds
    """
    app = Flask(__name__)

    # Default configuration
    app.config.update(
        {
            "DB_PATH": "data/hostvigil.db",
            "LOG_PATH": "data/logs/hostvigil.log",
            "SECRET_KEY": __import__("os").environ.get("SECRET_KEY", __import__("secrets").token_hex(32)),
            "REFRESH_INTERVAL": 30,
            "HOST": "127.0.0.1",
            "PORT": 5000,
        }
    )

    # Ensure orchestrator attribute is always defined
    app.orchestrator = None

    # Secure session cookies
    # Only set Secure flag when NOT on localhost (cookies won't be sent over plain HTTP)
    dashboard_host = app.config.get("HOST", "127.0.0.1")
    use_secure_cookies = os.environ.get("HOSTVIGIL_HTTPS", "0") == "1"
    if dashboard_host not in ("127.0.0.1", "localhost", "::1"):
        use_secure_cookies = True

    from datetime import timedelta

    app.config.update(
        SESSION_COOKIE_SECURE=use_secure_cookies,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    )

    # Override with provided config
    if config:
        if "db_path" in config:
            app.config["DB_PATH"] = config["db_path"]
        if "secret_key" in config:
            app.config["SECRET_KEY"] = config["secret_key"]
        if "refresh_interval" in config:
            app.config["REFRESH_INTERVAL"] = config["refresh_interval"]
        if "host" in config:
            app.config["HOST"] = config["host"]
        if "port" in config:
            app.config["PORT"] = config["port"]
        if "orchestrator" in config:
            app.orchestrator = config["orchestrator"]

    # Security: Use persistent secret key for session persistence across restarts
    if app.config["SECRET_KEY"] == "change-this-in-production":
        try:
            from hostvigil.enterprise import generate_persistent_secret_key

            app.config["SECRET_KEY"] = generate_persistent_secret_key()
            print("[i] Using persistent secret key for session persistence")
        except ImportError:
            import secrets

            app.config["SECRET_KEY"] = secrets.token_hex(32)
            print("[!] WARNING: Using random secret key. Install enterprise module for persistent sessions.")

    # Session timeout
    from datetime import timedelta

    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=4)

    # -------------------------------------------------------------------
    # Database helpers
    # -------------------------------------------------------------------

    # Ensure database and tables exist
    from hostvigil.utils import init_database

    init_database(app.config["DB_PATH"]).close()

    # -------------------------------------------------------------------
    # Create additional tables for dashboard features
    # -------------------------------------------------------------------
    def _init_dashboard_tables():
        """Create tables for schedules, profiles, webhooks, notes, users."""
        from hostvigil.utils import ensure_application_tables

        db_path = Path(app.config["DB_PATH"])
        conn = sqlite3.connect(str(db_path))
        ensure_application_tables(conn)

        # Create default admin user if not exists
        from datetime import datetime, timezone

        from werkzeug.security import generate_password_hash

        cursor = conn.execute("SELECT id FROM users WHERE username = 'admin'")
        if not cursor.fetchone():
            now = datetime.now(timezone.utc).isoformat()
            pw_hash = generate_password_hash("hostvigil")
            conn.execute(
                "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)", ("admin", pw_hash, now)
            )
        conn.commit()
        conn.close()

    _init_dashboard_tables()

    # -------------------------------------------------------------------
    # Error handlers — keep the dashboard thread alive on unexpected
    # failures. Without these, an exception inside a request handler can
    # propagate and kill the dashboard thread while the daemon keeps
    # scanning (silent loss of the web UI).
    # -------------------------------------------------------------------
    @app.errorhandler(404)
    def _handle_404(e):
        return (
            jsonify(
                {
                    "error": "not_found",
                    "message": "The requested resource does not exist.",
                }
            ),
            404,
        )

    @app.errorhandler(500)
    def _handle_500(e):
        app.logger.error("Unhandled dashboard error: %s", e, exc_info=True)
        # Don't leak internal exception details to the client
        return (
            jsonify(
                {
                    "error": "internal_error",
                    "message": "An unexpected error occurred. Check data/logs/hostvigil.log.",
                }
            ),
            500,
        )

    @app.errorhandler(sqlite3.Error)
    def _handle_db_error(e):
        app.logger.error("Database error: %s", e, exc_info=True)
        return (
            jsonify(
                {
                    "error": "database_error",
                    "message": "Database operation failed. Check data/logs/hostvigil.log.",
                }
            ),
            500,
        )

    @app.errorhandler(Exception)
    def _handle_generic(e):
        app.logger.error("Unhandled exception: %s", e, exc_info=True)
        return (
            jsonify(
                {
                    "error": "internal_error",
                    "message": "An unexpected error occurred. Check data/logs/hostvigil.log.",
                }
            ),
            500,
        )

    # -------------------------------------------------------------------
    # Authentication helpers
    # -------------------------------------------------------------------
    def login_required(f):
        """Decorator to require authentication for a route."""

        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get("logged_in"):
                return redirect(url_for("login"))
            # Session timeout: auto-logout after 30 min idle
            last_activity = session.get("last_activity")
            if last_activity and (time.time() - last_activity > 1800):
                session.clear()
                return redirect(url_for("login"))
            session["last_activity"] = time.time()
            return f(*args, **kwargs)

        return decorated_function

    def api_login_required(f):
        """Decorator to require authentication for API endpoints (returns JSON 401)."""

        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get("logged_in"):
                return jsonify({"error": "Authentication required"}), 401
            # Session timeout: auto-logout after 30 min idle
            last_activity = session.get("last_activity")
            if last_activity and (time.time() - last_activity > 1800):
                session.clear()
                return jsonify({"error": "Session expired"}), 401
            session["last_activity"] = time.time()
            return f(*args, **kwargs)

        return decorated_function

    # Scan concurrency: per-type locks allow different operations to run
    # concurrently (e.g. port scan + nuclei at the same time) while preventing
    # duplicate operations of the same type.
    _scan_locks = {}  # {scan_type: threading.Lock()}
    _scan_locks_master = threading.Lock()  # Protects _scan_locks dict creation
    _active_scans = {}  # {scan_type: status_dict}
    _active_scans_lock = threading.Lock()  # Protects _active_scans dict

    # -------------------------------------------------------------------
    # API authentication: require login for all /api/ routes except
    # lightweight polling endpoints (stats, pipeline/live) which are
    # read-only and used by the auto-refresh JS.
    # -------------------------------------------------------------------
    API_PUBLIC_ENDPOINTS = frozenset(
        [
            # Polling endpoints used by dashboard auto-refresh JS (read-only)
            "api_pipeline_live",
            "api_scan_status",
            "api_scan_progress",
            "api_daemon_live_status",
        ]
    )

    @app.before_request
    def _check_session_timeout():
        """Enforce session timeout (30 min inactivity)."""
        if request.endpoint in ("static", "login", None):
            return None
        if not session.get("logged_in"):
            return None
        last_activity = session.get("last_activity", 0)
        if last_activity and (time.time() - last_activity > 1800):
            session.clear()
            if request.path.startswith("/api/"):
                return jsonify({"error": "Session expired"}), 401
            return redirect(url_for("login"))
        session["last_activity"] = time.time()

    @app.before_request
    def _require_api_auth():
        """Enforce authentication on all API endpoints."""
        if request.path.startswith("/api/"):
            # Allow public read-only polling endpoints
            if request.endpoint in API_PUBLIC_ENDPOINTS:
                return None
            # Allow login-related paths
            if request.path == "/api/login":
                return None
            # Require authentication for everything else
            if not session.get("logged_in"):
                return jsonify({"error": "Authentication required"}), 401
        return None

    @contextmanager
    def get_db():
        """Context manager for database connections."""
        db_path = Path(app.config["DB_PATH"])
        conn = sqlite3.connect(str(db_path), timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
        finally:
            conn.close()

    def query_db(sql: str, params: tuple = (), one: bool = False):
        """Execute a query and return results as list of dicts."""
        with get_db() as conn:
            cursor = conn.execute(sql, params)
            rows = cursor.fetchall()
            if one:
                return dict(rows[0]) if rows else None
            return [dict(row) for row in rows]

    # -------------------------------------------------------------------
    # Security headers
    # -------------------------------------------------------------------

    @app.after_request
    def add_security_headers(response):
        """Add security headers to all responses."""
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' cdn.cloudflare.com cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' cdn.cloudflare.com cdnjs.cloudflare.com; font-src 'self' cdn.cloudflare.com cdnjs.cloudflare.com data:; img-src 'self' data: blob:"
        )
        return response

    # -------------------------------------------------------------------
    # Context processor - inject common data into all templates
    # -------------------------------------------------------------------

    @app.context_processor
    def inject_globals():
        return {
            "refresh_interval": app.config["REFRESH_INTERVAL"],
        }

    # -------------------------------------------------------------------
    # Authentication Routes
    # -------------------------------------------------------------------

    @app.route("/login", methods=["GET", "POST"])
    def login():
        """Login page and form handler."""
        if request.method == "POST":
            from werkzeug.security import check_password_hash

            ip = request.remote_addr or "unknown"

            now = time.time()

            with _login_attempts_lock:
                # Clean up old rate-limit entries (older than 5 minutes since last attempt)
                stale = [k for k, v in _login_attempts.items() if now - v.get("last_attempt", 0) > 300]
                for k in stale:
                    _login_attempts.pop(k, None)

                # Check if IP is locked out
                attempt = _login_attempts.get(ip)
                if attempt and attempt.get("locked_until", 0) > now:
                    remaining = int(attempt["locked_until"] - now)
                    return render_template(
                        "login.html", error=f"Too many failed attempts. Try again in {remaining} seconds."
                    )

            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            user = query_db("SELECT * FROM users WHERE username = ?", (username,), one=True)
            if user and check_password_hash(user["password_hash"], password):
                # Successful login: clear rate-limit record
                with _login_attempts_lock:
                    _login_attempts.pop(ip, None)
                # Prevent session fixation - regenerate session
                session.clear()
                session["logged_in"] = True
                session["username"] = username
                session["auth_time"] = time.time()
                session["last_activity"] = time.time()
                session.permanent = True
                return redirect(url_for("index"))

            # Failed login: increment attempt count
            with _login_attempts_lock:
                if ip not in _login_attempts:
                    _login_attempts[ip] = {"count": 0, "locked_until": 0, "last_attempt": 0}
                _login_attempts[ip]["count"] += 1
                _login_attempts[ip]["last_attempt"] = now
                if _login_attempts[ip]["count"] >= 5:
                    _login_attempts[ip]["locked_until"] = now + 60

            return render_template("login.html", error="Invalid username or password")
        return render_template("login.html", error=None)

    @app.route("/logout")
    def logout():
        """Log out and clear session."""
        session.clear()
        return redirect(url_for("login"))

    # -------------------------------------------------------------------
    # HTML View Routes
    # -------------------------------------------------------------------

    @app.route("/health")
    def health():
        """Health check endpoint for monitoring."""
        from datetime import datetime

        return jsonify({"status": "healthy", "version": "1.0.0", "timestamp": datetime.utcnow().isoformat()})

    @app.route("/")
    @login_required
    def index():
        """Main dashboard - network overview with stats and charts."""
        stats = _get_stats()
        return render_template("index.html", stats=stats)

    @app.route("/hosts")
    @login_required
    def hosts():
        """Host inventory - JS-powered table fetches from /api/hosts."""
        return render_template("hosts.html")

    @app.route("/vulnerabilities")
    @login_required
    def vulnerabilities():
        """Vulnerability findings from nuclei scans."""
        severity_filter = request.args.get("severity", "").lower()

        sql = """
            SELECT
                v.id,
                v.name,
                v.severity,
                v.template_id,
                v.description,
                v.matched_at,
                v.evidence,
                v.is_verified,
                h.ip,
                h.hostname,
                p.port,
                p.protocol,
                p.service
            FROM vulnerabilities v
            JOIN hosts h ON h.id = v.host_id
            LEFT JOIN ports p ON p.id = v.port_id
        """
        params = ()

        if severity_filter and severity_filter in ("critical", "high", "medium", "low", "info"):
            sql += " WHERE LOWER(v.severity) = ?"
            params = (severity_filter,)

        sql += " ORDER BY CASE LOWER(v.severity) "
        sql += "   WHEN 'critical' THEN 1 "
        sql += "   WHEN 'high' THEN 2 "
        sql += "   WHEN 'medium' THEN 3 "
        sql += "   WHEN 'low' THEN 4 "
        sql += "   WHEN 'info' THEN 5 "
        sql += "   ELSE 6 END, v.matched_at DESC"

        vuln_data = query_db(sql, params)
        return render_template(
            "vulnerabilities.html",
            vulnerabilities=vuln_data,
            current_filter=severity_filter,
        )

    @app.route("/anomalies")
    @login_required
    def anomalies():
        """ML-detected anomalies view."""
        show_reviewed = request.args.get("show_reviewed", "0") == "1"

        sql = """
            SELECT
                a.id,
                a.anomaly_type,
                a.score,
                a.description,
                a.detected_at,
                a.is_reviewed,
                h.ip,
                h.hostname
            FROM anomalies a
            JOIN hosts h ON h.id = a.host_id
        """

        if not show_reviewed:
            sql += " WHERE a.is_reviewed = 0"

        sql += " ORDER BY a.score DESC, a.detected_at DESC"

        anomaly_data = query_db(sql)
        return render_template(
            "anomalies.html",
            anomalies=anomaly_data,
            show_reviewed=show_reviewed,
        )

    @app.route("/scan-controls")
    @login_required
    def scan_controls():
        """Scan controls - trigger scans and DNS discovery from the dashboard."""
        return render_template("scan_controls.html")

    @app.route("/live-status")
    @login_required
    def live_status():
        """Live daemon pipeline status - real-time view of background scanning."""
        return render_template("live_status.html")

    @app.route("/logs")
    @login_required
    def logs_page():
        """Live log viewer - real-time streaming log output."""
        return render_template("logs.html")

    @app.route("/api/logs/history")
    @login_required
    def api_logs_history():
        """Return the tail of the actual hostvigil.log file (for initial page load)."""
        lines = _read_log_tail(app.config["LOG_PATH"], max_lines=500)
        return jsonify([_parse_log_line(line) for line in lines])

    @app.route("/api/logs/stream")
    @login_required
    def api_logs_stream():
        """SSE endpoint for tailing the real hostvigil.log file live (syslog-style)."""
        import time as _time

        log_path = app.config["LOG_PATH"]

        def generate():
            pos, inode = _log_tail_start_position(log_path)
            max_iter = 600  # 10 minute timeout
            for _ in range(max_iter):
                pos, inode, new_lines = _read_log_new_lines(log_path, pos, inode)
                for line in new_lines:
                    parsed = _parse_log_line(line)
                    if parsed:
                        yield f"data: {json.dumps(parsed)}\n\n"
                _time.sleep(1)
            yield "event: timeout\ndata: {}\n\n"

        from flask import Response

        return Response(
            generate(), mimetype="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
        )

    @app.route("/redteam")
    @login_required
    def redteam():
        """Red team view - exploitable targets grouped by attack vector."""
        from hostvigil.attack_paths import AttackPathEngine

        # Get verified and high/critical vulns with exploit potential
        exploitable = query_db("""
            SELECT
                v.id,
                v.name,
                v.severity,
                v.template_id,
                v.description,
                v.matched_at,
                v.evidence,
                v.is_verified,
                h.ip,
                h.hostname,
                p.port,
                p.protocol,
                p.service
            FROM vulnerabilities v
            JOIN hosts h ON h.id = v.host_id
            LEFT JOIN ports p ON p.id = v.port_id
            WHERE LOWER(v.severity) IN ('critical', 'high')
            ORDER BY CASE LOWER(v.severity)
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                ELSE 3 END, v.matched_at DESC
        """)

        service_primitives = query_db("""
            SELECT
                se.id,
                se.ip,
                se.port,
                se.service_type,
                se.risk_level,
                se.title,
                se.finding_type,
                se.discovered_at,
                h.hostname,
                se.enum_data
            FROM service_enumeration se
            JOIN hosts h ON h.id = se.host_id
            ORDER BY CASE LOWER(COALESCE(se.risk_level, se.severity, 'info'))
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                ELSE 5 END,
                se.discovered_at DESC
        """)

        # Categorize by attack vector based on template_id and name patterns
        categories = _categorize_exploits(exploitable)

        primitive_categories = _categorize_primitives(service_primitives)
        attack_analysis = AttackPathEngine(app.config["DB_PATH"]).analyze()

        return render_template(
            "redteam.html",
            crown_jewels=attack_analysis.get("crown_jewels", []),
            credential_clusters=attack_analysis.get("credential_clusters", []),
            categories=categories,
            primitive_categories=primitive_categories,
            best_footholds=attack_analysis.get("best_footholds", []),
            pivot_paths=attack_analysis.get("pivot_paths", []),
        )

    # -------------------------------------------------------------------
    # API Endpoints (JSON)
    # -------------------------------------------------------------------

    @app.route("/api/stats")
    def api_stats():
        """API: Get network overview statistics."""
        return jsonify(_get_stats())

    @app.route("/api/hosts")
    def api_hosts():
        """API: Server-side paginated hosts with search, filtering, and sorting.

        Query Parameters:
            page (int): Page number, default 1.
            per_page (int): Results per page, default 50, max 200.
            q (str): Search query (searches ip, hostname, mac, discovery_method).
            subnet (str): Filter by /16 subnet prefix (e.g. '10.82.0.0/16').
            sort (str): Sort column (ip, hostname, port_count, anomaly_count,
                        first_seen, last_seen). Default 'last_seen'.
            order (str): Sort direction (asc, desc). Default 'desc'.
            active_only (str): 'true' (default) or 'false'.

        Returns:
            JSON with hosts list, pagination metadata, and top /16 subnets.
        """
        import ipaddress as _ipaddress
        import math

        # Parse parameters
        page = max(1, request.args.get("page", 1, type=int))
        per_page = min(200, max(1, request.args.get("per_page", 50, type=int)))
        q = request.args.get("q", "").strip()
        subnet_filter = request.args.get("subnet", "").strip()
        sort = request.args.get("sort", "last_seen")
        order = request.args.get("order", "desc")
        active_only = request.args.get("active_only", "true").lower() != "false"

        # Validate sort/order
        allowed_sorts = {"ip", "hostname", "port_count", "anomaly_count", "first_seen", "last_seen"}
        if sort not in allowed_sorts:
            sort = "last_seen"
        if order not in ("asc", "desc"):
            order = "desc"

        # Build the query with subqueries for port_count and anomaly_count
        base_sql = """
            SELECT
                h.id,
                h.ip,
                h.hostname,
                h.mac,
                h.os_fingerprint AS os,
                h.is_active,
                h.discovery_method,
                h.first_seen,
                h.last_seen,
                COALESCE(pc.port_count, 0) AS port_count,
                COALESCE(ac.anomaly_count, 0) AS anomaly_count
            FROM hosts h
            LEFT JOIN (
                SELECT host_id, COUNT(*) AS port_count
                FROM ports WHERE state='open' AND is_active=1
                GROUP BY host_id
            ) pc ON pc.host_id = h.id
            LEFT JOIN (
                SELECT host_id, COUNT(*) AS anomaly_count
                FROM anomalies WHERE is_reviewed=0
                GROUP BY host_id
            ) ac ON ac.host_id = h.id
        """

        where_clauses = []
        params = []

        if active_only:
            where_clauses.append("h.is_active = 1")

        if q:
            where_clauses.append("(h.ip LIKE ? OR h.hostname LIKE ? OR h.mac LIKE ? OR h.discovery_method LIKE ?)")
            like_q = f"%{q}%"
            params.extend([like_q, like_q, like_q, like_q])

        if subnet_filter:
            # Extract the network prefix from the subnet (e.g. '10.82.0.0/16' -> '10.82.')
            try:
                net = _ipaddress.ip_network(subnet_filter, strict=False)
                prefix_len = net.prefixlen
                # For /16, take first 2 octets; for /24, take first 3; for /8, take first 1
                octets_needed = prefix_len // 8
                if octets_needed > 0:
                    prefix = ".".join(str(net.network_address).split(".")[:octets_needed]) + "."
                    where_clauses.append("h.ip LIKE ?")
                    params.append(f"{prefix}%")
            except (ValueError, TypeError):
                pass  # Invalid subnet format, ignore filter

        where_sql = ""
        if where_clauses:
            where_sql = " WHERE " + " AND ".join(where_clauses)

        # Sort mapping - whitelist to prevent SQL injection
        sort_map = {
            "ip": "h.ip",
            "hostname": "h.hostname",
            "port_count": "port_count",
            "anomaly_count": "anomaly_count",
            "first_seen": "h.first_seen",
            "last_seen": "h.last_seen",
        }
        sort_col = sort_map.get(sort, "h.last_seen")
        # Whitelist order parameter to prevent SQL injection
        order = "ASC" if order.upper() != "DESC" else "DESC"
        order_sql = " ORDER BY {} {}".format(sort_col, order)

        # Count total matching rows
        count_sql = f"SELECT COUNT(*) AS total FROM hosts h{where_sql}"
        total_row = query_db(count_sql, tuple(params), one=True)
        total = total_row["total"] if total_row else 0
        total_pages = math.ceil(total / per_page) if total > 0 else 0

        # Fetch paginated results
        offset = (page - 1) * per_page
        paginated_sql = base_sql + where_sql + order_sql + " LIMIT ? OFFSET ?"
        hosts_data = query_db(paginated_sql, tuple(params) + (per_page, offset))

        # Build subnet summary (top 20 /16 subnets by host count)
        subnet_sql = """
            SELECT
                SUBSTR(ip, 1, INSTR(ip, '.') + INSTR(SUBSTR(ip, INSTR(ip, '.') + 1), '.')) AS prefix,
                COUNT(*) AS count
            FROM hosts
        """
        if active_only:
            subnet_sql += " WHERE is_active = 1"
        subnet_sql += " GROUP BY prefix ORDER BY count DESC LIMIT 20"

        subnet_rows = query_db(subnet_sql)
        subnets = []
        for row in subnet_rows:
            prefix = row.get("prefix", "")
            if prefix:
                # Convert prefix like '10.82.' to '10.82.0.0/16'
                parts = prefix.rstrip(".").split(".")
                while len(parts) < 4:
                    parts.append("0")
                subnet_cidr = ".".join(parts[:4]) + "/16"
                subnets.append({"subnet": subnet_cidr, "count": row["count"]})

        return jsonify(
            {
                "hosts": hosts_data,
                "pagination": {
                    "page": page,
                    "per_page": per_page,
                    "total": total,
                    "total_pages": total_pages,
                },
                "subnets": subnets,
            }
        )

    @app.route("/api/vulnerabilities")
    def api_vulnerabilities():
        """API: Server-side paginated vulnerabilities with search and severity filter.

        Query Parameters:
            page (int): Page number, default 1.
            per_page (int): Results per page, default 50, max 200.
            search (str): Search query (searches name, description, ip, hostname).
            severity (str): Filter by severity (critical, high, medium, low, info).

        Returns:
            JSON with vulnerabilities list and pagination metadata.
        """
        page = max(1, request.args.get("page", 1, type=int))
        per_page = min(200, max(1, request.args.get("per_page", 50, type=int)))
        search = request.args.get("search", "").strip()
        severity_filter = request.args.get("severity", "").lower()

        base_sql = """
            SELECT
                v.id,
                v.name,
                v.severity,
                v.template_id,
                v.description,
                v.matched_at,
                v.evidence,
                v.is_verified,
                h.ip,
                h.hostname,
                p.port,
                p.protocol,
                p.service
            FROM vulnerabilities v
            JOIN hosts h ON h.id = v.host_id
            LEFT JOIN ports p ON p.id = v.port_id
        """

        where_clauses = []
        params = []

        if severity_filter and severity_filter in ("critical", "high", "medium", "low", "info"):
            where_clauses.append("LOWER(v.severity) = ?")
            params.append(severity_filter)

        if search:
            where_clauses.append("(v.name LIKE ? OR v.description LIKE ? OR h.ip LIKE ? OR h.hostname LIKE ?)")
            like_q = f"%{search}%"
            params.extend([like_q, like_q, like_q, like_q])

        where_sql = ""
        if where_clauses:
            where_sql = " WHERE " + " AND ".join(where_clauses)

        order_sql = " ORDER BY CASE LOWER(v.severity) "
        order_sql += "   WHEN 'critical' THEN 1 WHEN 'high' THEN 2 "
        order_sql += "   WHEN 'medium' THEN 3 WHEN 'low' THEN 4 "
        order_sql += "   WHEN 'info' THEN 5 ELSE 6 END"

        # Count total matching rows
        count_sql = (
            """
            SELECT COUNT(*) AS total
            FROM vulnerabilities v
            JOIN hosts h ON h.id = v.host_id
            LEFT JOIN ports p ON p.id = v.port_id
        """
            + where_sql
        )
        total_row = query_db(count_sql, tuple(params), one=True)
        total = total_row["total"] if total_row else 0
        total_pages = math.ceil(total / per_page) if total > 0 else 0

        # Fetch paginated results
        offset = (page - 1) * per_page
        paginated_sql = base_sql + where_sql + order_sql + " LIMIT ? OFFSET ?"
        vuln_data = query_db(paginated_sql, tuple(params) + (per_page, offset))

        return jsonify(
            {
                "vulnerabilities": vuln_data,
                "pagination": {
                    "total": total,
                    "page": page,
                    "per_page": per_page,
                    "pages": total_pages,
                },
            }
        )

    @app.route("/api/anomalies")
    def api_anomalies():
        """API: Server-side paginated anomalies with search and score filter.

        Query Parameters:
            page (int): Page number, default 1.
            per_page (int): Results per page, default 50, max 200.
            search (str): Search query (searches anomaly_type, description, ip, hostname).
            min_score (float): Minimum anomaly score filter.
            show_reviewed (str): '1' to include reviewed anomalies, default '0'.

        Returns:
            JSON with anomalies list and pagination metadata.
        """
        page = max(1, request.args.get("page", 1, type=int))
        per_page = min(200, max(1, request.args.get("per_page", 50, type=int)))
        search = request.args.get("search", "").strip()
        min_score = request.args.get("min_score", None, type=float)
        show_reviewed = request.args.get("show_reviewed", "0") == "1"

        base_sql = """
            SELECT
                a.id,
                a.anomaly_type,
                a.score,
                a.description,
                a.detected_at,
                a.is_reviewed,
                h.ip,
                h.hostname
            FROM anomalies a
            JOIN hosts h ON h.id = a.host_id
        """

        where_clauses = []
        params = []

        if not show_reviewed:
            where_clauses.append("a.is_reviewed = 0")

        if search:
            where_clauses.append("(a.anomaly_type LIKE ? OR a.description LIKE ? OR h.ip LIKE ? OR h.hostname LIKE ?)")
            like_q = f"%{search}%"
            params.extend([like_q, like_q, like_q, like_q])

        if min_score is not None:
            where_clauses.append("a.score >= ?")
            params.append(min_score)

        where_sql = ""
        if where_clauses:
            where_sql = " WHERE " + " AND ".join(where_clauses)

        order_sql = " ORDER BY a.score DESC, a.detected_at DESC"

        # Count total matching rows
        count_sql = (
            """
            SELECT COUNT(*) AS total
            FROM anomalies a
            JOIN hosts h ON h.id = a.host_id
        """
            + where_sql
        )
        total_row = query_db(count_sql, tuple(params), one=True)
        total = total_row["total"] if total_row else 0
        total_pages = math.ceil(total / per_page) if total > 0 else 0

        # Fetch paginated results
        offset = (page - 1) * per_page
        paginated_sql = base_sql + where_sql + order_sql + " LIMIT ? OFFSET ?"
        anomaly_data = query_db(paginated_sql, tuple(params) + (per_page, offset))

        return jsonify(
            {
                "anomalies": anomaly_data,
                "pagination": {
                    "total": total,
                    "page": page,
                    "per_page": per_page,
                    "pages": total_pages,
                },
            }
        )

    @app.route("/api/redteam")
    def api_redteam():
        """API: Get exploitable targets grouped by attack vector."""
        from hostvigil.attack_paths import AttackPathEngine

        exploitable = query_db("""
            SELECT
                v.id,
                v.name,
                v.severity,
                v.template_id,
                v.description,
                v.matched_at,
                v.evidence,
                v.is_verified,
                h.ip,
                h.hostname,
                p.port,
                p.protocol,
                p.service
            FROM vulnerabilities v
            JOIN hosts h ON h.id = v.host_id
            LEFT JOIN ports p ON p.id = v.port_id
            WHERE LOWER(v.severity) IN ('critical', 'high')
            ORDER BY v.matched_at DESC
        """)
        service_primitives = query_db("""
            SELECT
                se.id,
                se.ip,
                se.port,
                se.service_type,
                se.risk_level,
                se.title,
                se.finding_type,
                se.discovered_at,
                h.hostname,
                se.enum_data
            FROM service_enumeration se
            JOIN hosts h ON h.id = se.host_id
            ORDER BY CASE LOWER(COALESCE(se.risk_level, se.severity, 'info'))
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                ELSE 5 END,
                se.discovered_at DESC
        """)
        categories = _categorize_exploits(exploitable)
        primitive_categories = _categorize_primitives(service_primitives)
        attack_analysis = AttackPathEngine(app.config["DB_PATH"]).analyze()
        return jsonify(
            {
                "categories": categories,
                "primitive_categories": primitive_categories,
                "best_footholds": attack_analysis.get("best_footholds", []),
                "crown_jewels": attack_analysis.get("crown_jewels", []),
                "credential_clusters": attack_analysis.get("credential_clusters", []),
                "pivot_paths": attack_analysis.get("pivot_paths", []),
                "risk_score": attack_analysis.get("risk_score", 0),
                "summary": attack_analysis.get("summary", ""),
            }
        )

    # -------------------------------------------------------------------
    # Scan Trigger API Endpoints
    # -------------------------------------------------------------------

    @app.route("/api/scan/trigger", methods=["POST"])
    @api_login_required
    def api_trigger_scan():
        """Trigger a scan from the dashboard. Runs in background thread.

        Each scan type gets its own lock, so you can run port scan + nuclei
        concurrently. Duplicate operations of the same type are rejected.
        All dashboard-triggered scans run independently of the daemon pipeline.
        """
        scan_type = request.json.get("scan_type", "full") if request.is_json else "full"
        valid_types = [
            "discover",
            "scan",
            "udpscan",
            "fingerprint",
            "tls",
            "enumerate",
            "servicescan",
            "analyze",
            "nuclei",
            "full",
        ]

        if scan_type not in valid_types:
            return jsonify({"error": f"Invalid scan type. Choose from: {valid_types}"}), 400

        # Get or create a per-type lock
        with _scan_locks_master:
            if scan_type not in _scan_locks:
                _scan_locks[scan_type] = threading.Lock()
            type_lock = _scan_locks[scan_type]

        # Prevent duplicate operations of the same type only
        if not type_lock.acquire(blocking=False):
            return jsonify({"error": f"A '{scan_type}' scan is already in progress", "status": "busy"}), 409

        def _run_scan():
            status_entry = {"type": scan_type, "status": "running", "started": _now_iso()}
            with _active_scans_lock:
                _active_scans[scan_type] = status_entry
            _append_scan_log("info", f"Started {scan_type} scan")
            app._scan_running = True
            app._scan_status = status_entry
            try:
                # Always create a fresh orchestrator for dashboard-triggered scans.
                # This ensures scans run immediately and independently of the daemon
                # pipeline cycle (which may be mid-discovery or blocked on slow techniques).
                # SQLite WAL mode supports concurrent access safely.
                from hostvigil.orchestrator import HostVigilOrchestrator

                orch = HostVigilOrchestrator()

                if scan_type == "discover":
                    result = orch.run_discovery()
                elif scan_type == "scan":
                    result = orch.run_scan()
                elif scan_type == "udpscan":
                    result = orch.run_udp_scan()
                elif scan_type == "fingerprint":
                    result = orch.run_os_fingerprint()
                elif scan_type == "tls":
                    result = orch.run_tls_inspection()
                elif scan_type == "enumerate":
                    result = orch.run_service_enum()
                elif scan_type == "servicescan":
                    result = orch.run_service_scan()
                elif scan_type == "analyze":
                    result = orch.run_analysis()
                elif scan_type == "nuclei":
                    result = orch.run_nuclei()
                elif scan_type == "full":
                    result = orch.run_once()
                else:
                    result = {"error": "unknown scan type"}

                completed_status = {
                    "type": scan_type,
                    "status": "completed",
                    "started": status_entry["started"],
                    "completed": _now_iso(),
                    "result": result,
                }
                with _active_scans_lock:
                    _active_scans[scan_type] = completed_status
                app._scan_status = completed_status
                _append_scan_log("info", f"Completed {scan_type}")
            except Exception as e:
                error_status = {
                    "type": scan_type,
                    "status": "error",
                    "started": status_entry["started"],
                    "error": str(e),
                }
                with _active_scans_lock:
                    _active_scans[scan_type] = error_status
                app._scan_status = error_status
                _append_scan_log("error", f"Error in {scan_type}: {e}")
            finally:
                with _active_scans_lock:
                    app._scan_running = len([s for s in _active_scans.values() if s.get("status") == "running"]) > 0
                type_lock.release()

        try:
            thread = threading.Thread(target=_run_scan, daemon=True, name=f"scan-{scan_type}")
            thread.start()
        except Exception:
            type_lock.release()
            return jsonify({"error": "Failed to start scan thread"}), 500

        return jsonify(
            {
                "status": "started",
                "scan_type": scan_type,
                "message": f"{scan_type} scan triggered successfully (runs independently of daemon)",
            }
        )

    @app.route("/api/scan/status")
    def api_scan_status():
        """Get current background scan status (all active scans)."""
        with _active_scans_lock:
            scans_snapshot = dict(_active_scans)
        running_scans = {k: v for k, v in scans_snapshot.items() if v.get("status") == "running"}
        return jsonify(
            {
                "running": len(running_scans) > 0,
                "active_scans": scans_snapshot,
                "running_types": list(running_scans.keys()),
                # Legacy field for backward compatibility with existing JS
                "scan": getattr(app, "_scan_status", None),
            }
        )

    @app.route("/api/scan/logs")
    def api_scan_logs():
        """SSE endpoint for streaming scan log lines."""
        import time as _time

        def generate():
            last_idx = 0
            max_iter = 300
            for _ in range(max_iter):
                logs = list(_scan_log_buffer)
                if len(logs) > last_idx:
                    for log in logs[last_idx:]:
                        yield f"data: {json.dumps(log)}\n\n"
                    last_idx = len(logs)
                _time.sleep(1)
            yield "event: timeout\ndata: {}\n\n"

        from flask import Response

        return Response(
            generate(), mimetype="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
        )

    @app.route("/api/scan/logs/history")
    @login_required
    def api_scan_logs_history():
        """Return current log buffer contents as JSON array (for initial page load)."""
        return jsonify(list(_scan_log_buffer))

    # -------------------------------------------------------------------
    # Host-level Scan Trigger API
    # -------------------------------------------------------------------

    @app.route("/api/hosts/<ip>/scan", methods=["POST"])
    @api_login_required
    def api_host_scan(ip):
        """Trigger a scan against a single host IP.

        Body (JSON):
            scan_type (str): One of 'scan', 'nuclei', 'fingerprint', 'tls', 'enumerate'.
                             Default 'scan'.

        Runs the operation in a background thread targeting only the specified IP.
        """
        import ipaddress as _ipaddress

        # Validate IP format
        try:
            _ipaddress.ip_address(ip)
        except ValueError:
            return jsonify({"error": f"Invalid IP address: {ip}"}), 400

        scan_type = "scan"
        if request.is_json and request.json:
            scan_type = request.json.get("scan_type", "scan")

        valid_types = ["scan", "nuclei", "fingerprint", "tls", "enumerate", "servicescan"]
        if scan_type not in valid_types:
            return jsonify({"error": f"Invalid scan_type. Choose from: {valid_types}"}), 400

        # Check host exists in DB
        host = query_db("SELECT id, ip FROM hosts WHERE ip = ?", (ip,), one=True)
        if not host:
            return jsonify({"error": f"Host {ip} not found in database. Run discovery first."}), 404

        # Track with a unique key per host+type
        scan_key = f"host_{ip}_{scan_type}"

        # Check if already running for this host (thread-safe)
        with _active_scans_lock:
            if scan_key in _active_scans and _active_scans[scan_key].get("status") == "running":
                return jsonify({"error": f"A '{scan_type}' scan is already running for {ip}", "status": "busy"}), 409

        def _run_host_scan():
            status_entry = {
                "type": scan_type,
                "target": ip,
                "status": "running",
                "started": _now_iso(),
            }
            with _active_scans_lock:
                _active_scans[scan_key] = status_entry

            try:
                from hostvigil.orchestrator import HostVigilOrchestrator

                orch = HostVigilOrchestrator()

                if scan_type == "scan":
                    # TCP port scan against single host
                    from hostvigil.scanner.stealth_scanner import StealthScanner

                    scanner = StealthScanner(orch.config.hostvigil, orch.db_path)
                    result = scanner.scan_hosts([ip])
                elif scan_type == "fingerprint":
                    from hostvigil.scanner.os_fingerprint import OSFingerprinter

                    fp = OSFingerprinter({**orch.config.stealth}, orch.db_path)
                    result = fp.fingerprint_host(ip)
                elif scan_type == "tls":
                    from hostvigil.scanner.tls_inspector import TLSInspector

                    inspector = TLSInspector({**orch.config.stealth}, orch.db_path)
                    # Get TLS-capable ports for this host
                    tls_ports = query_db(
                        "SELECT port FROM ports WHERE host_id = ? AND state='open' AND port IN (443,636,993,995,465,8443,5986,2376,9443) AND is_active=1",
                        (host["id"],),
                    )
                    targets = [(ip, row["port"]) for row in tls_ports]
                    if targets:
                        result = inspector.inspect_targets(targets)
                    else:
                        result = {"message": "No TLS ports found for this host"}
                elif scan_type == "enumerate":
                    from hostvigil.scanner.service_enum import ServiceEnumerator

                    enumerator = ServiceEnumerator({**orch.config.stealth}, orch.db_path)
                    result = enumerator.enumerate_host(ip)
                elif scan_type == "servicescan":
                    from hostvigil.scanner.nmap_service_scan import NmapServiceScanner

                    svc_cfg = {**orch.config.stealth, **orch.config.get("service_scan", default={})}
                    svc_scanner = NmapServiceScanner(svc_cfg, orch.db_path)
                    result = svc_scanner.scan_host(ip)
                elif scan_type == "nuclei":
                    from hostvigil.nuclei.nuclei_runner import NucleiRunner

                    runner = NucleiRunner(orch.config.nuclei, orch.db_path)
                    # Build target URLs from open ports
                    open_ports = query_db(
                        "SELECT port, service FROM ports WHERE host_id = ? AND state='open' AND is_active=1",
                        (host["id"],),
                    )
                    targets = []
                    for row in open_ports:
                        port = row["port"]
                        service = (row.get("service") or "").lower()
                        if port in (443, 8443, 9443) or "https" in service:
                            targets.append(f"https://{ip}:{port}")
                        else:
                            targets.append(f"http://{ip}:{port}")
                    if targets:
                        result = runner.run_scan(targets=targets)
                    else:
                        result = {"message": "No open ports found for nuclei scan. Run TCP Scan first."}
                else:
                    result = {"error": "Unknown scan type"}

                with _active_scans_lock:
                    _active_scans[scan_key] = {
                        "type": scan_type,
                        "target": ip,
                        "status": "completed",
                        "started": status_entry["started"],
                        "completed": _now_iso(),
                        "result": result,
                    }
            except Exception as e:
                with _active_scans_lock:
                    _active_scans[scan_key] = {
                        "type": scan_type,
                        "target": ip,
                        "status": "error",
                        "started": status_entry["started"],
                        "error": str(e),
                    }

        thread = threading.Thread(target=_run_host_scan, daemon=True, name=f"host-scan-{ip}-{scan_type}")
        thread.start()

        return jsonify(
            {
                "status": "started",
                "scan_type": scan_type,
                "target": ip,
                "message": f"{scan_type} scan triggered for {ip}",
            }
        )

    @app.route("/api/scan/progress")
    def api_scan_progress():
        """API: Real-time progress of all active scans and daemon pipeline status.

        Returns daemon status, dashboard-triggered scan progress, and
        prerequisite readiness for each scan type.
        """
        # --- Daemon status ---
        daemon_info = {"running": False, "current_phase": None, "cycle": 0}
        orch = getattr(app, "orchestrator", None)
        if orch:
            daemon_info = {
                "running": getattr(orch, "running", False),
                "current_phase": getattr(orch.status, "current_phase", None) if hasattr(orch, "status") else None,
                "cycle": (getattr(orch.status, "total_runs", 0) if hasattr(orch, "status") else 0) + 1,
            }

        # --- Dashboard scans progress ---
        dashboard_scans = {}
        scan_types_tracked = ["discover", "scan", "udpscan", "fingerprint", "tls", "enumerate", "analyze", "nuclei"]
        with _active_scans_lock:
            scans_snapshot = dict(_active_scans)
        for stype in scan_types_tracked:
            if stype in scans_snapshot:
                entry = scans_snapshot[stype]
                dashboard_scans[stype] = {
                    "status": entry.get("status", "idle"),
                    "started": entry.get("started"),
                    "completed": entry.get("completed"),
                    "progress": entry.get("progress"),
                    "error": entry.get("error"),
                }
            else:
                dashboard_scans[stype] = {"status": "idle"}

        # --- Prerequisites: what's ready to scan ---
        def _format_count(count):
            """Format large numbers with comma separator."""
            return f"{count:,}"

        # scan: all active hosts
        scan_count_row = query_db("SELECT COUNT(*) AS cnt FROM hosts WHERE is_active=1", one=True)
        scan_count = scan_count_row["cnt"] if scan_count_row else 0

        # nuclei: hosts with open ports
        nuclei_count_row = query_db(
            """
            SELECT COUNT(DISTINCT h.id) AS cnt
            FROM ports p JOIN hosts h ON p.host_id = h.id
            WHERE p.state='open' AND p.is_active=1 AND h.is_active=1
        """,
            one=True,
        )
        nuclei_count = nuclei_count_row["cnt"] if nuclei_count_row else 0

        # tls: hosts with TLS-capable ports open
        tls_count_row = query_db(
            """
            SELECT COUNT(DISTINCT host_id) AS cnt
            FROM ports
            WHERE state='open' AND port IN (443,636,993,995,465,8443,5986,2376,9443) AND is_active=1
        """,
            one=True,
        )
        tls_count = tls_count_row["cnt"] if tls_count_row else 0

        # enumerate: same as nuclei (needs open ports)
        enumerate_count = nuclei_count

        # fingerprint: same as scan (all active hosts)
        fingerprint_count = scan_count

        # analyze: same as scan (all active hosts)
        analyze_count = scan_count

        prerequisites = {
            "scan": {
                "ready": scan_count > 0,
                "target_count": scan_count,
                "message": f"{_format_count(scan_count)} hosts available"
                if scan_count > 0
                else "No hosts discovered yet. Run Discovery first.",
            },
            "nuclei": {
                "ready": nuclei_count > 0,
                "target_count": nuclei_count,
                "message": f"{_format_count(nuclei_count)} hosts with open ports"
                if nuclei_count > 0
                else "No open ports found. Run TCP Scan first.",
            },
            "fingerprint": {
                "ready": fingerprint_count > 0,
                "target_count": fingerprint_count,
                "message": f"{_format_count(fingerprint_count)} hosts available"
                if fingerprint_count > 0
                else "No hosts discovered yet. Run Discovery first.",
            },
            "tls": {
                "ready": tls_count > 0,
                "target_count": tls_count,
                "message": f"{_format_count(tls_count)} hosts with TLS ports"
                if tls_count > 0
                else "No TLS ports found. Run TCP Scan first.",
            },
            "enumerate": {
                "ready": enumerate_count > 0,
                "target_count": enumerate_count,
                "message": f"{_format_count(enumerate_count)} hosts with services"
                if enumerate_count > 0
                else "No services found. Run TCP Scan first.",
            },
            "analyze": {
                "ready": analyze_count > 0,
                "target_count": analyze_count,
                "message": "Ready" if analyze_count > 0 else "No hosts discovered yet. Run Discovery first.",
            },
        }

        return jsonify(
            {
                "daemon": daemon_info,
                "dashboard_scans": dashboard_scans,
                "prerequisites": prerequisites,
            }
        )

    @app.route("/api/pipeline/status")
    def api_pipeline_status():
        """Get live pipeline status including current phase and last scan details."""
        # Query the scans table for last scan info
        last_scan = query_db("SELECT * FROM scans ORDER BY start_time DESC LIMIT 1", one=True)
        recent_scans = query_db("SELECT * FROM scans ORDER BY start_time DESC LIMIT 10")
        stats = _get_stats()

        # Live orchestrator state (available in daemon mode)
        daemon_status = None
        if hasattr(app, "orchestrator") and app.orchestrator:
            daemon_status = app.orchestrator.get_status()

        return jsonify(
            {
                "last_scan": last_scan,
                "recent_scans": recent_scans,
                "stats": stats,
                "running": getattr(app, "_scan_running", False),
                "current_scan": getattr(app, "_scan_status", None),
                "daemon": daemon_status,
            }
        )

    @app.route("/api/pipeline/live")
    def api_pipeline_live():
        """Lightweight endpoint for polling live updates (stats + daemon state)."""
        stats = _get_stats()
        last_scan = query_db("SELECT * FROM scans ORDER BY start_time DESC LIMIT 1", one=True)
        # Detect running: either dashboard-triggered scan OR daemon cycle in progress
        is_running = getattr(app, "_scan_running", False)
        current_phase = None
        daemon_state = None
        total_runs = 0
        total_errors = 0
        hosts_discovered = 0
        ports_found = 0
        last_run_start = None
        last_run_end = None
        last_run_result = None

        if hasattr(app, "orchestrator") and app.orchestrator:
            orch = app.orchestrator
            # Thread-safe: to_dict() acquires the lock internally
            status_dict = orch.status.to_dict()
            daemon_state = status_dict["state"]
            current_phase = status_dict["current_phase"]
            total_runs = status_dict["total_runs"]
            total_errors = status_dict["total_errors"]
            hosts_discovered = status_dict["hosts_discovered"]
            ports_found = status_dict["ports_found"]
            last_run_start = status_dict["last_run_start"]
            last_run_end = status_dict["last_run_end"]
            last_run_result = status_dict["last_run_result"]
            if daemon_state == "running" and current_phase:
                is_running = True

        if not is_running and last_scan and not last_scan.get("end_time"):
            is_running = True

        daemon_info = None
        if daemon_state:
            daemon_info = {
                "state": daemon_state,
                "current_phase": current_phase,
                "total_runs": total_runs,
                "total_errors": total_errors,
                "hosts_discovered": hosts_discovered,
                "ports_found": ports_found,
                "last_run_start": last_run_start,
                "last_run_end": last_run_end,
                "last_run_result": last_run_result,
            }
            # FIX #26: Include in_progress_since when a phase is active
            if current_phase is not None:
                daemon_info["in_progress_since"] = last_run_start

        return jsonify(
            {
                "stats": stats,
                "last_scan": last_scan,
                "running": is_running,
                "last_scan_time": last_scan.get("end_time") if last_scan else None,
                "daemon": daemon_info,
            }
        )

    @app.route("/api/daemon/live-status")
    def api_daemon_live_status():
        """Lightweight live daemon status for the Live Status page.

        Returns only in-memory orchestrator state — zero DB queries.
        Safe to poll at 5s intervals even with 200k+ hosts.
        """
        orch = getattr(app, "orchestrator", None)
        if not orch:
            return jsonify(
                {
                    "daemon_running": False,
                    "state": "not_available",
                    "message": "Dashboard running without daemon (standalone mode)",
                }
            )
        return jsonify(orch.get_live_status())

    @app.route("/api/anomalies/<int:anomaly_id>/feedback", methods=["POST"])
    def api_anomaly_feedback(anomaly_id):
        """Record operator feedback on an anomaly (true positive or false positive)."""
        from hostvigil.ml_engine.enrichment import MLEnrichmentEngine

        if not request.is_json:
            return jsonify({"error": "JSON body required"}), 400

        is_tp = request.json.get("is_true_positive", True)
        notes = request.json.get("notes", "")

        config = {"model_path": "data/models/"}
        engine = MLEnrichmentEngine(config, app.config["DB_PATH"])
        result = engine.record_feedback(anomaly_id, is_tp, notes)

        return jsonify(result)

    @app.route("/api/ml/stats")
    def api_ml_stats():
        """Get ML enrichment engine statistics."""
        from hostvigil.ml_engine.enrichment import MLEnrichmentEngine

        config = {"model_path": "data/models/"}
        engine = MLEnrichmentEngine(config, app.config["DB_PATH"])
        return jsonify(engine.get_enrichment_stats())

    # -------------------------------------------------------------------
    # Host Tagging API Endpoints
    # -------------------------------------------------------------------

    @app.route("/api/hosts/<int:host_id>/tags", methods=["GET"])
    def api_get_host_tags(host_id):
        """API: Get all tags for a host."""
        tags = query_db("SELECT tag, added_at FROM host_tags WHERE host_id = ?", (host_id,))
        return jsonify({"host_id": host_id, "tags": tags})

    @app.route("/api/hosts/<int:host_id>/tags", methods=["POST"])
    def api_add_host_tag(host_id):
        """API: Add a tag to a host."""
        if not request.is_json:
            return jsonify({"error": "JSON required"}), 400
        tag = request.json.get("tag", "").strip()
        if not tag:
            return jsonify({"error": "tag is required"}), 400
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc).isoformat()
        try:
            with get_db() as conn:
                conn.execute(
                    "INSERT OR IGNORE INTO host_tags (host_id, tag, added_at) VALUES (?, ?, ?)", (host_id, tag, now)
                )
                conn.commit()
            return jsonify({"status": "added", "host_id": host_id, "tag": tag})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/hosts/<int:host_id>/tags/<tag>", methods=["DELETE"])
    def api_remove_host_tag(host_id, tag):
        """API: Remove a tag from a host."""
        with get_db() as conn:
            conn.execute("DELETE FROM host_tags WHERE host_id = ? AND tag = ?", (host_id, tag))
            conn.commit()
        return jsonify({"status": "removed", "host_id": host_id, "tag": tag})

    # -------------------------------------------------------------------
    # Scan Diff API Endpoint
    # -------------------------------------------------------------------

    @app.route("/api/diff")
    def api_scan_diff():
        """API: Get network changes over a time window."""
        from hostvigil.scanner.scan_diff import ScanDiff

        hours = request.args.get("hours", 24, type=int)
        diff = ScanDiff(app.config["DB_PATH"])
        return jsonify(diff.get_diff(hours))

    @app.route("/api/discover/dns", methods=["POST"])
    def api_discover_dns():
        """Discover hosts using a custom DNS server for zone transfer or reverse lookups."""
        import threading

        if not request.is_json:
            return jsonify({"error": "JSON body required"}), 400

        dns_server = request.json.get("dns_server", "").strip()
        target_range = request.json.get("target_range", "").strip()
        domain = request.json.get("domain", "").strip()

        if not dns_server:
            return jsonify({"error": "dns_server is required"}), 400

        # Validate dns_server is a valid IP address (prevent SSRF via hostname)
        import ipaddress as _ipaddress

        try:
            _ipaddress.ip_address(dns_server)
        except ValueError:
            return jsonify({"error": "dns_server must be a valid IP address"}), 400

        # Validate domain doesn't contain shell-unsafe characters
        if domain and not all(c.isalnum() or c in ".-" for c in domain):
            return jsonify({"error": "Invalid domain format"}), 400

        # Use per-type lock system instead of global app._scan_running
        with _scan_locks_master:
            if "dns_discover" not in _scan_locks:
                _scan_locks["dns_discover"] = threading.Lock()
            dns_lock = _scan_locks["dns_discover"]
        if not dns_lock.acquire(blocking=False):
            return jsonify({"error": "DNS discovery already running"}), 409

        def _run_dns_discovery():
            import socket

            status_entry = {"type": "dns_discovery", "status": "running", "started": _now_iso()}
            with _active_scans_lock:
                _active_scans["dns_discover"] = status_entry
            app._scan_status = status_entry
            discovered = []

            try:
                db_path = app.config["DB_PATH"]

                # If target_range provided, do reverse DNS lookups using the custom DNS server
                if target_range:
                    import ipaddress
                    import random
                    import time

                    try:
                        network = ipaddress.ip_network(target_range, strict=False)
                    except ValueError:
                        app._scan_status = {
                            "type": "dns_discovery",
                            "status": "error",
                            "error": "Invalid target_range CIDR",
                        }
                        return

                    hosts_list = list(network.hosts())
                    random.shuffle(hosts_list)  # Stealth: randomize order

                    for ip in hosts_list:
                        ip_str = str(ip)
                        try:
                            # Build reverse DNS query using the custom DNS server
                            import struct

                            # Craft DNS PTR query
                            rev_name = ".".join(reversed(ip_str.split("."))) + ".in-addr.arpa"
                            query_id = random.randint(0, 65535)

                            # Build DNS packet
                            packet = struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
                            # Encode domain name
                            for label in rev_name.split("."):
                                packet += struct.pack("B", len(label)) + label.encode()
                            packet += b"\x00"
                            packet += struct.pack(">HH", 12, 1)  # PTR, IN

                            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                            sock.settimeout(3.0)
                            sock.sendto(packet, (dns_server, 53))

                            response = sock.recv(1024)
                            sock.close()

                            # Parse response - check if we got an answer
                            if len(response) > 12:
                                answer_count = struct.unpack(">H", response[6:8])[0]
                                if answer_count > 0:
                                    # Extract hostname from response (simplified parsing)
                                    hostname = _parse_dns_ptr_response(response)
                                    if hostname:
                                        discovered.append({"ip": ip_str, "hostname": hostname})
                                        _store_dns_host(db_path, ip_str, hostname)

                        except (socket.timeout, OSError):
                            pass

                        # Stealth delay between queries
                        time.sleep(random.uniform(0.5, 2.0))

                # If domain provided, attempt zone transfer (AXFR)
                if domain:
                    import time

                    try:
                        axfr_results = _attempt_zone_transfer(dns_server, domain)
                        for entry in axfr_results:
                            discovered.append(entry)
                            _store_dns_host(db_path, entry["ip"], entry.get("hostname", ""))
                    except Exception:
                        pass

                completed_status = {
                    "type": "dns_discovery",
                    "status": "completed",
                    "started": status_entry["started"],
                    "completed": _now_iso(),
                    "hosts_found": len(discovered),
                    "results": discovered[:100],  # Limit response size
                }
                app._scan_status = completed_status
            except Exception as e:
                app._scan_status = {"type": "dns_discovery", "status": "error", "error": str(e)}
            finally:
                with _active_scans_lock:
                    _active_scans.pop("dns_discover", None)
                dns_lock.release()

        thread = threading.Thread(target=_run_dns_discovery, daemon=True)
        thread.start()

        return jsonify(
            {
                "status": "started",
                "message": f"DNS discovery started using server {dns_server}",
                "dns_server": dns_server,
                "target_range": target_range,
                "domain": domain,
            }
        )

    def _now_iso() -> str:
        """Get current UTC time as ISO string."""
        from datetime import datetime, timezone

        return datetime.now(timezone.utc).isoformat()

    def _append_scan_log(level, message):
        """Append a log entry to the scan log buffer for SSE streaming."""
        _scan_log_buffer.append({"level": level, "message": message, "time": _now_iso()})

    def _store_dns_host(db_path: str, ip: str, hostname: str):
        """Store a DNS-discovered host in the database."""
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc).isoformat()
        conn = None
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM hosts WHERE ip = ?", (ip,))
            row = cursor.fetchone()
            if row:
                cursor.execute(
                    "UPDATE hosts SET hostname = ?, last_seen = ?, is_active = 1 WHERE id = ?", (hostname, now, row[0])
                )
            else:
                cursor.execute(
                    "INSERT INTO hosts (ip, hostname, first_seen, last_seen, discovery_method, is_active) "
                    "VALUES (?, ?, ?, ?, 'dns_custom', 1)",
                    (ip, hostname, now, now),
                )
            conn.commit()
        except Exception as e:
            import logging

            logging.getLogger("hostvigil.dashboard").warning(f"Failed to store DNS host {ip}: {e}")
        finally:
            if conn:
                conn.close()

    def _parse_dns_ptr_response(response: bytes) -> str:
        """Parse a DNS PTR response to extract the hostname."""
        try:
            # Skip header (12 bytes) and question section
            offset = 12
            # Skip question name
            while offset < len(response) and response[offset] != 0:
                if response[offset] & 0xC0 == 0xC0:
                    offset += 2
                    break
                offset += response[offset] + 1
            else:
                offset += 1
            offset += 4  # Skip QTYPE + QCLASS

            # Parse answer section
            if offset >= len(response):
                return ""

            # Skip answer name (may be pointer)
            if response[offset] & 0xC0 == 0xC0:
                offset += 2
            else:
                while offset < len(response) and response[offset] != 0:
                    offset += response[offset] + 1
                offset += 1

            if offset + 10 > len(response):
                return ""

            import struct

            rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", response[offset : offset + 10])
            offset += 10

            if rtype != 12:  # Not PTR
                return ""

            # Read the PTR name
            hostname_parts = []
            end = offset + rdlength
            while offset < end and offset < len(response) and response[offset] != 0:
                if response[offset] & 0xC0 == 0xC0:
                    # Pointer - follow it
                    ptr_offset = struct.unpack(">H", response[offset : offset + 2])[0] & 0x3FFF
                    # Read name at pointer
                    while ptr_offset < len(response) and response[ptr_offset] != 0:
                        label_len = response[ptr_offset]
                        if label_len & 0xC0 == 0xC0:
                            break
                        hostname_parts.append(
                            response[ptr_offset + 1 : ptr_offset + 1 + label_len].decode("ascii", errors="ignore")
                        )
                        ptr_offset += label_len + 1
                    break
                else:
                    label_len = response[offset]
                    hostname_parts.append(
                        response[offset + 1 : offset + 1 + label_len].decode("ascii", errors="ignore")
                    )
                    offset += label_len + 1

            return ".".join(hostname_parts) if hostname_parts else ""
        except Exception:
            return ""

    def _attempt_zone_transfer(dns_server: str, domain: str) -> list:
        """Attempt DNS zone transfer (AXFR) - often blocked but worth trying."""
        import socket
        import struct

        results = []
        try:
            # Build AXFR query
            query_id = 0x1234
            packet = struct.pack(">HHHHHH", query_id, 0x0000, 1, 0, 0, 0)
            for label in domain.split("."):
                packet += struct.pack("B", len(label)) + label.encode()
            packet += b"\x00"
            packet += struct.pack(">HH", 252, 1)  # AXFR, IN

            # TCP connection for zone transfer
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            sock.connect((dns_server, 53))

            # Send with length prefix (TCP DNS)
            length_prefix = struct.pack(">H", len(packet))
            sock.sendall(length_prefix + packet)

            # Read response
            resp_len_data = sock.recv(2)
            if len(resp_len_data) == 2:
                resp_len = struct.unpack(">H", resp_len_data)[0]
                response = b""
                while len(response) < resp_len:
                    chunk = sock.recv(resp_len - len(response))
                    if not chunk:
                        break
                    response += chunk

                # Parse A records from zone transfer response
                # (simplified - real AXFR parsing is complex)
                if len(response) > 12:
                    answer_count = struct.unpack(">H", response[6:8])[0]
                    if answer_count > 0:
                        # Zone transfer was successful (rare but valuable)
                        pass  # Full AXFR parsing would go here

            sock.close()
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass

        return results

    # -------------------------------------------------------------------
    # Network Graph Endpoints
    # -------------------------------------------------------------------

    @app.route("/network-graph")
    @login_required
    def network_graph():
        return render_template("network_graph.html")

    @app.route("/api/graph/data")
    def api_graph_data():
        """API: Build clustered network graph data.

        With large networks (200k+ hosts), loading all nodes kills the browser.
        This endpoint returns subnet-level clusters by default, and individual
        hosts when a specific subnet is requested via ?subnet= parameter.

        Query params:
            subnet: (optional) Expand a specific subnet, e.g. '10.0.1.0/24'
            limit:  (optional) Max hosts to return when expanding (default 500)
        """
        expand_subnet = request.args.get("subnet")
        try:
            host_limit = min(int(request.args.get("limit", 500)), 2000)
        except (ValueError, TypeError):
            host_limit = 500

        if expand_subnet:
            # --- Expand a single subnet: return individual hosts ---
            try:
                net = ipaddress.ip_network(expand_subnet, strict=False)
                prefix = ".".join(str(net.network_address).split(".")[:3]) + "."
            except ValueError:
                return jsonify({"error": "Invalid subnet"}), 400
            hosts = query_db(
                """
                SELECT h.id, h.ip, h.hostname, h.os_fingerprint,
                       COUNT(DISTINCT p.id) as port_count,
                       COUNT(DISTINCT v.id) as vuln_count,
                       MAX(CASE WHEN LOWER(v.severity) = 'critical' THEN 4
                                WHEN LOWER(v.severity) = 'high' THEN 3
                                WHEN LOWER(v.severity) = 'medium' THEN 2
                                ELSE 1 END) as max_severity
                FROM hosts h
                LEFT JOIN ports p ON p.host_id = h.id AND p.is_active = 1
                LEFT JOIN vulnerabilities v ON v.host_id = h.id
                WHERE h.is_active = 1 AND h.ip LIKE ?
                GROUP BY h.id
                LIMIT ?
            """,
                (prefix + "%", host_limit),
            )

            nodes = []
            edges = []
            for host in hosts:
                ip = host["ip"]
                severity = host.get("max_severity", 0) or 0
                color = "#1cbb8c"
                if severity >= 4:
                    color = "#dc3545"
                elif severity >= 3:
                    color = "#ff6d00"
                elif severity >= 2:
                    color = "#fcb92c"

                nodes.append(
                    {
                        "id": f"host_{host['id']}",
                        "label": host.get("hostname") or ip,
                        "title": f"{ip}\nPorts: {host['port_count']}\nVulns: {host['vuln_count']}\nOS: {host.get('os_fingerprint') or 'unknown'}",
                        "color": color,
                        "size": max(10, min(40, 10 + host["port_count"] * 2)),
                        "ip": ip,
                        "subnet": expand_subnet,
                        "port_count": host["port_count"],
                        "vuln_count": host["vuln_count"],
                        "is_cluster": False,
                    }
                )

            # Chain edges within the expanded subnet
            for i in range(len(nodes) - 1):
                edges.append(
                    {
                        "id": i,
                        "from": nodes[i]["id"],
                        "to": nodes[i + 1]["id"],
                        "color": {"color": "#2d3748", "opacity": 0.3},
                    }
                )

            truncated = len(hosts) >= host_limit
            return jsonify(
                {
                    "nodes": nodes,
                    "edges": edges,
                    "subnets": [expand_subnet],
                    "expanded_subnet": expand_subnet,
                    "truncated": truncated,
                    "total_in_subnet": len(hosts),
                }
            )

        # --- Default: return subnet-level clusters ---
        # Get per-host data and aggregate by /24 subnet in Python.
        # LIMIT 600000 as a safety cap — at 500k hosts this uses ~150MB peak RAM
        # which is acceptable for enterprise deployments. The aggregation loop is O(n).
        import math

        raw_hosts = query_db("""
            SELECT h.ip,
                   MAX(CASE WHEN LOWER(v.severity) = 'critical' THEN 4
                            WHEN LOWER(v.severity) = 'high' THEN 3
                            WHEN LOWER(v.severity) = 'medium' THEN 2
                            ELSE 1 END) as max_severity,
                   COUNT(DISTINCT p.id) as port_count,
                   COUNT(DISTINCT v.id) as vuln_count
            FROM hosts h
            LEFT JOIN ports p ON p.host_id = h.id AND p.is_active = 1
            LEFT JOIN vulnerabilities v ON v.host_id = h.id
            WHERE h.is_active = 1
            GROUP BY h.ip
            LIMIT 600000
        """)

        # Aggregate by /24 subnet in Python (reliable across all SQLite versions)
        subnets = {}
        for host in raw_hosts:
            ip = host["ip"]
            parts = ip.split(".")
            if len(parts) == 4:
                prefix = ".".join(parts[:3])
            else:
                continue  # skip IPv6 or malformed for now
            if prefix not in subnets:
                subnets[prefix] = {"host_count": 0, "total_ports": 0, "total_vulns": 0, "max_severity": 0}
            s = subnets[prefix]
            s["host_count"] += 1
            s["total_ports"] += host.get("port_count", 0) or 0
            s["total_vulns"] += host.get("vuln_count", 0) or 0
            sev = host.get("max_severity", 0) or 0
            if sev > s["max_severity"]:
                s["max_severity"] = sev

        nodes = []
        edges = []
        subnet_list = sorted(subnets.keys())

        for prefix in subnet_list:
            s = subnets[prefix]
            subnet_cidr = prefix + ".0/24"
            severity = s["max_severity"]
            if severity >= 4:
                color = "#dc3545"
            elif severity >= 3:
                color = "#ff6d00"
            elif severity >= 2:
                color = "#fcb92c"
            else:
                color = "#1cbb8c"

            # Scale node size by host count (log scale for large subnets)
            size = max(15, min(60, 15 + int(math.log2(max(1, s["host_count"]))) * 5))

            nodes.append(
                {
                    "id": f"subnet_{prefix}",
                    "label": f"{subnet_cidr}\n({s['host_count']} hosts)",
                    "title": f"Subnet: {subnet_cidr}\nHosts: {s['host_count']}\nOpen Ports: {s['total_ports']}\nVulnerabilities: {s['total_vulns']}",
                    "color": color,
                    "size": size,
                    "ip": subnet_cidr,
                    "subnet": subnet_cidr,
                    "port_count": s["total_ports"],
                    "vuln_count": s["total_vulns"],
                    "host_count": s["host_count"],
                    "is_cluster": True,
                }
            )

        # Connect subnets that share a /16 (same first two octets)
        supernets = {}
        for prefix in subnet_list:
            parts = prefix.split(".")
            supernet = ".".join(parts[:2])
            if supernet not in supernets:
                supernets[supernet] = []
            supernets[supernet].append(f"subnet_{prefix}")

        edge_id = 0
        for _supernet, subnet_ids in supernets.items():
            # Chain subnets within same /16 — limit edges to avoid clutter
            for i in range(min(len(subnet_ids) - 1, 30)):
                edges.append(
                    {
                        "id": edge_id,
                        "from": subnet_ids[i],
                        "to": subnet_ids[i + 1],
                        "color": {"color": "#2d3748", "opacity": 0.2},
                    }
                )
                edge_id += 1

        return jsonify(
            {
                "nodes": nodes,
                "edges": edges,
                "subnets": [p + ".0/24" for p in subnet_list],
                "total_hosts": sum(s["host_count"] for s in subnets.values()),
                "clustered": True,
            }
        )

    # -------------------------------------------------------------------
    # Attack Paths Endpoints
    # -------------------------------------------------------------------

    @app.route("/attack-paths")
    @login_required
    def attack_paths():
        """Attack path visualization - lateral movement and priv esc chains."""
        return render_template("attack_paths.html")

    @app.route("/api/attack-paths")
    def api_attack_paths():
        """API: Analyze and return attack paths from scan findings."""
        from hostvigil.attack_paths import AttackPathEngine

        engine = AttackPathEngine(app.config["DB_PATH"])
        result = engine.analyze()
        return jsonify(result)

    # -------------------------------------------------------------------
    # Feature: Host Detail Page (Feature 1)
    # -------------------------------------------------------------------

    @app.route("/host/<ip>")
    @app.route("/hosts/<ip>")
    @login_required
    def host_detail(ip):
        """Host detail page - all info for a single IP."""
        host = query_db("SELECT * FROM hosts WHERE ip = ?", (ip,), one=True)

        # Fallback: if ip is actually a numeric DB id (legacy links), look up by id
        if not host and ip.isdigit():
            host = query_db("SELECT * FROM hosts WHERE id = ?", (int(ip),), one=True)

        if not host:
            return render_template(
                "host_detail.html",
                host={
                    "ip": ip,
                    "hostname": None,
                    "mac": None,
                    "os_fingerprint": None,
                    "is_active": False,
                    "discovery_method": None,
                    "first_seen": None,
                    "last_seen": None,
                },
                ports=[],
                vulns=[],
                tls=[],
                anomalies=[],
            )

        host_id = host["id"]
        ports = query_db(
            "SELECT * FROM ports WHERE host_id = ? AND state = 'open' AND is_active = 1 ORDER BY port", (host_id,)
        )
        vulns = query_db(
            """
            SELECT v.*, p.port, p.protocol FROM vulnerabilities v
            LEFT JOIN ports p ON p.id = v.port_id
            WHERE v.host_id = ? ORDER BY CASE LOWER(v.severity)
                WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                WHEN 'medium' THEN 3 ELSE 4 END
        """,
            (host_id,),
        )
        tls = []
        try:
            tls = query_db("SELECT * FROM tls_certificates WHERE host_id = ?", (host_id,))
        except Exception:
            pass  # Table may not exist if TLS inspection hasn't run
        anomalies = query_db("SELECT * FROM anomalies WHERE host_id = ? ORDER BY score DESC", (host_id,))

        # Additional data for enriched detail view
        services = []
        try:
            services = query_db(
                "SELECT * FROM service_enumeration WHERE host_id = ? ORDER BY severity DESC, enumerated_at DESC",
                (host_id,),
            )
        except Exception:
            pass

        credentials = []
        try:
            credentials = query_db(
                "SELECT * FROM credential_results WHERE host_id = ? ORDER BY tested_at DESC",
                (host_id,),
            )
        except Exception:
            pass

        tags = []
        try:
            tags = query_db("SELECT tag, added_at FROM host_tags WHERE host_id = ?", (host_id,))
        except Exception:
            pass

        banner_changes = []
        try:
            banner_changes = query_db(
                "SELECT * FROM banner_changes WHERE host_id = ? ORDER BY detected_at DESC LIMIT 20",
                (host_id,),
            )
        except Exception:
            pass

        return render_template(
            "host_detail.html",
            host=host,
            ports=ports,
            vulns=vulns,
            tls=tls,
            anomalies=anomalies,
            services=services,
            credentials=credentials,
            tags=tags,
            banner_changes=banner_changes,
        )

    # -------------------------------------------------------------------
    # Feature: Session Notes (Feature 6)
    # -------------------------------------------------------------------

    @app.route("/notes", methods=["GET", "POST"])
    @login_required
    def notes():
        """Session notes - create and view engagement notes."""
        from datetime import datetime, timezone

        if request.method == "POST":
            title = request.form.get("title", "").strip()
            content = request.form.get("content", "").strip()
            if title and content:
                now = datetime.now(timezone.utc).isoformat()
                with get_db() as conn:
                    conn.execute(
                        "INSERT INTO notes (title, content, created_at) VALUES (?, ?, ?)", (title, content, now)
                    )
                    conn.commit()
            return redirect(url_for("notes"))

        all_notes = query_db("SELECT * FROM notes ORDER BY created_at DESC")
        return render_template("notes.html", notes=all_notes)

    # -------------------------------------------------------------------
    # Feature: Diff View (Feature 9)
    # -------------------------------------------------------------------

    @app.route("/diff")
    @login_required
    def diff_view():
        """Network diff view - what changed in the last N hours."""
        from datetime import datetime, timedelta, timezone

        hours = request.args.get("hours", 24, type=int)
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

        new_hosts = query_db("SELECT * FROM hosts WHERE first_seen >= ? ORDER BY first_seen DESC", (cutoff,))
        new_ports = query_db(
            """
            SELECT p.*, h.ip FROM ports p
            JOIN hosts h ON h.id = p.host_id
            WHERE p.first_seen >= ? ORDER BY p.first_seen DESC
        """,
            (cutoff,),
        )
        new_vulns = query_db(
            """
            SELECT v.*, h.ip, p.port FROM vulnerabilities v
            JOIN hosts h ON h.id = v.host_id
            LEFT JOIN ports p ON p.id = v.port_id
            WHERE v.matched_at >= ? ORDER BY v.matched_at DESC
        """,
            (cutoff,),
        )

        return render_template("diff.html", new_hosts=new_hosts, new_ports=new_ports, new_vulns=new_vulns, hours=hours)

    # -------------------------------------------------------------------
    # Feature: Scan Scheduling API (Feature 3)
    # -------------------------------------------------------------------

    @app.route("/api/schedule", methods=["GET"])
    def api_get_schedules():
        """API: Get all scan schedules."""
        schedules = query_db("SELECT * FROM schedules ORDER BY created_at DESC")
        return jsonify({"schedules": schedules})

    @app.route("/api/schedule", methods=["POST"])
    def api_add_schedule():
        """API: Add a new scan schedule."""
        from datetime import datetime, timezone

        if not request.is_json:
            return jsonify({"error": "JSON required"}), 400
        scan_type = request.json.get("scan_type", "").strip()
        cron_expr = request.json.get("cron_expr", "").strip()
        enabled = request.json.get("enabled", True)
        if not scan_type or not cron_expr:
            return jsonify({"error": "scan_type and cron_expr are required"}), 400
        now = datetime.now(timezone.utc).isoformat()
        with get_db() as conn:
            conn.execute(
                "INSERT INTO schedules (scan_type, cron_expr, enabled, created_at) VALUES (?, ?, ?, ?)",
                (scan_type, cron_expr, 1 if enabled else 0, now),
            )
            conn.commit()
        return jsonify({"status": "created", "scan_type": scan_type, "cron_expr": cron_expr})

    @app.route("/api/schedule/<int:schedule_id>", methods=["DELETE"])
    def api_delete_schedule(schedule_id):
        """API: Delete a scan schedule."""
        with get_db() as conn:
            conn.execute("DELETE FROM schedules WHERE id = ?", (schedule_id,))
            conn.commit()
        return jsonify({"status": "deleted", "id": schedule_id})

    @app.route("/api/schedule/<int:schedule_id>/toggle", methods=["POST"])
    def api_toggle_schedule(schedule_id):
        """API: Toggle a schedule's enabled/disabled state."""
        schedule = query_db("SELECT * FROM schedules WHERE id = ?", (schedule_id,), one=True)
        if not schedule:
            return jsonify({"error": "Schedule not found"}), 404
        new_state = 0 if schedule["enabled"] else 1
        with get_db() as conn:
            conn.execute("UPDATE schedules SET enabled = ? WHERE id = ?", (new_state, schedule_id))
            conn.commit()
        return jsonify({"status": "toggled", "id": schedule_id, "enabled": bool(new_state)})

    # -------------------------------------------------------------------
    # Feature: Engagement Profiles API (Feature 4)
    # -------------------------------------------------------------------

    @app.route("/api/profiles", methods=["GET"])
    def api_get_profiles():
        """API: Get all engagement profiles."""
        profiles = query_db("SELECT * FROM profiles ORDER BY created_at DESC")
        return jsonify({"profiles": profiles})

    @app.route("/api/profiles", methods=["POST"])
    def api_add_profile():
        """API: Create a new engagement profile."""
        from datetime import datetime, timezone

        if not request.is_json:
            return jsonify({"error": "JSON required"}), 400
        name = request.json.get("name", "").strip()
        if not name:
            return jsonify({"error": "name is required"}), 400
        target_ranges = request.json.get("target_ranges", "")
        scan_type = request.json.get("scan_type", "full")
        notes = request.json.get("notes", "")
        now = datetime.now(timezone.utc).isoformat()
        with get_db() as conn:
            conn.execute(
                "INSERT INTO profiles (name, target_ranges, scan_type, notes, created_at) VALUES (?, ?, ?, ?, ?)",
                (name, target_ranges, scan_type, notes, now),
            )
            conn.commit()
        return jsonify({"status": "created", "name": name})

    @app.route("/api/profiles/<int:profile_id>", methods=["DELETE"])
    def api_delete_profile(profile_id):
        """API: Delete an engagement profile."""
        with get_db() as conn:
            conn.execute("DELETE FROM profiles WHERE id = ?", (profile_id,))
            conn.commit()
        return jsonify({"status": "deleted", "id": profile_id})

    # -------------------------------------------------------------------
    # Feature: Webhook Configuration API (Feature 5)
    # -------------------------------------------------------------------

    @app.route("/api/webhooks", methods=["GET"])
    def api_get_webhooks():
        """API: Get all configured webhooks."""
        webhooks = query_db("SELECT * FROM webhooks ORDER BY created_at DESC")
        return jsonify({"webhooks": webhooks})

    @app.route("/api/webhooks", methods=["POST"])
    def api_add_webhook():
        """API: Add a webhook notification endpoint."""
        from datetime import datetime, timezone

        if not request.is_json:
            return jsonify({"error": "JSON required"}), 400
        name = request.json.get("name", "").strip()
        url = request.json.get("url", "").strip()
        events = request.json.get("events", "all")
        if not name or not url:
            return jsonify({"error": "name and url are required"}), 400
        now = datetime.now(timezone.utc).isoformat()
        with get_db() as conn:
            conn.execute(
                "INSERT INTO webhooks (name, url, events, created_at) VALUES (?, ?, ?, ?)", (name, url, events, now)
            )
            conn.commit()
        return jsonify({"status": "created", "name": name})

    # -------------------------------------------------------------------
    # Feature: Rate Limit Visualization API (Feature 7)
    # -------------------------------------------------------------------

    @app.route("/api/rate-stats")
    def api_rate_stats():
        """API: Get current scan rate/throttle statistics (placeholder)."""
        return jsonify(
            {
                "probes_per_minute": 4.2,
                "avg_delay_seconds": 27.5,
                "backoff_count": 0,
                "decoys_sent": 12,
                "current_jitter": 0.3,
                "rst_detected": 0,
                "throttle_active": False,
                "scan_window_active": True,
            }
        )

    # -------------------------------------------------------------------
    # Helper Functions
    # -------------------------------------------------------------------

    def _get_stats() -> dict:
        """Gather network overview statistics (cached for 10 seconds)."""
        now = time.time()
        with _stats_lock:
            if _stats_cache["data"] is not None and (now - _stats_cache["time"]) < 10:
                return _stats_cache["data"]

        total_hosts = query_db("SELECT COUNT(*) as count FROM hosts WHERE is_active = 1", one=True)
        total_ports = query_db("SELECT COUNT(*) as count FROM ports WHERE is_active = 1", one=True)
        vuln_by_severity = query_db("""
            SELECT LOWER(severity) as severity, COUNT(*) as count
            FROM vulnerabilities
            GROUP BY LOWER(severity)
        """)
        active_anomalies = query_db(
            "SELECT COUNT(*) as count FROM anomalies WHERE is_reviewed = 0",
            one=True,
        )
        recent_scans = query_db("SELECT * FROM scans ORDER BY start_time DESC LIMIT 5")

        # Severity breakdown dict
        severity_counts = {row["severity"]: row["count"] for row in vuln_by_severity}

        result = {
            "total_hosts": total_hosts["count"] if total_hosts else 0,
            "total_ports": total_ports["count"] if total_ports else 0,
            "vulnerabilities": {
                "critical": severity_counts.get("critical", 0),
                "high": severity_counts.get("high", 0),
                "medium": severity_counts.get("medium", 0),
                "low": severity_counts.get("low", 0),
                "info": severity_counts.get("info", 0),
                "total": sum(severity_counts.values()),
            },
            "active_anomalies": active_anomalies["count"] if active_anomalies else 0,
            "recent_scans": recent_scans,
        }

        with _stats_lock:
            _stats_cache["data"] = result
            _stats_cache["time"] = now
        return result

    def _categorize_exploits(vulns: list) -> dict:
        """Categorize vulnerabilities by attack vector for red team view."""
        categories = {
            "rce": {"label": "Remote Code Execution", "icon": "💀", "items": []},
            "auth_bypass": {"label": "Authentication Bypass", "icon": "🔓", "items": []},
            "default_creds": {"label": "Default Credentials", "icon": "🔑", "items": []},
            "sqli": {"label": "SQL Injection", "icon": "💉", "items": []},
            "ssrf": {"label": "SSRF / Path Traversal", "icon": "🌐", "items": []},
            "file_inclusion": {"label": "File Inclusion / Upload", "icon": "📁", "items": []},
            "info_disclosure": {"label": "Information Disclosure", "icon": "📋", "items": []},
            "other": {"label": "Other Critical", "icon": "⚡", "items": []},
        }

        for vuln in vulns:
            name_lower = (vuln.get("name") or "").lower()
            template_lower = (vuln.get("template_id") or "").lower()
            combined = f"{name_lower} {template_lower}"

            if any(kw in combined for kw in ["rce", "remote-code", "command-injection", "exec", "deserialization"]):
                categories["rce"]["items"].append(vuln)
            elif any(kw in combined for kw in ["auth-bypass", "authentication-bypass", "unauth", "broken-auth"]):
                categories["auth_bypass"]["items"].append(vuln)
            elif any(kw in combined for kw in ["default-login", "default-cred", "default-password", "weak-password"]):
                categories["default_creds"]["items"].append(vuln)
            elif any(kw in combined for kw in ["sqli", "sql-injection", "sql_injection"]):
                categories["sqli"]["items"].append(vuln)
            elif any(kw in combined for kw in ["ssrf", "path-traversal", "lfi", "directory-traversal"]):
                categories["ssrf"]["items"].append(vuln)
            elif any(kw in combined for kw in ["file-inclusion", "file-upload", "arbitrary-file", "rfi"]):
                categories["file_inclusion"]["items"].append(vuln)
            elif any(kw in combined for kw in ["disclosure", "exposed", "leaked", "sensitive"]):
                categories["info_disclosure"]["items"].append(vuln)
            else:
                categories["other"]["items"].append(vuln)

        # Remove empty categories
        return {k: v for k, v in categories.items() if v["items"]}

    def _categorize_primitives(primitives: list) -> dict:
        """Categorize service enumeration results by red-team primitive."""
        categories = {
            "host_takeover": {"label": "Host Takeover", "icon": "💥", "items": []},
            "relay_risk": {"label": "Relay Risk", "icon": "🔁", "items": []},
            "pivot_node": {"label": "Pivot Node", "icon": "🧭", "items": []},
            "domain_enum": {"label": "Domain Enumeration", "icon": "🗂️", "items": []},
            "lateral_movement": {"label": "Lateral Movement", "icon": "↔️", "items": []},
            "data_exposure": {"label": "Data Exposure", "icon": "🗃️", "items": []},
            "admin_plane": {"label": "Admin Plane", "icon": "⚙️", "items": []},
            "other": {"label": "Other Primitives", "icon": "⚡", "items": []},
        }

        for primitive in primitives:
            enum_data = primitive.get("enum_data")
            if isinstance(enum_data, str):
                try:
                    enum_data = json.loads(enum_data)
                except Exception:
                    enum_data = {}
            attack_tags = set((enum_data or {}).get("attack_tags", []))
            if not attack_tags:
                risk = (primitive.get("risk_level") or "").lower()
                if risk == "critical":
                    attack_tags.update(["host-takeover", "pivot-node"])
                elif risk == "high":
                    attack_tags.update(["pivot-node", "lateral-movement"])

            if "host-takeover" in attack_tags:
                categories["host_takeover"]["items"].append(primitive)
            elif "relay-risk" in attack_tags:
                categories["relay_risk"]["items"].append(primitive)
            elif "pivot-node" in attack_tags:
                categories["pivot_node"]["items"].append(primitive)
            elif "domain-enum" in attack_tags or "credential-harvest" in attack_tags:
                categories["domain_enum"]["items"].append(primitive)
            elif "lateral-movement" in attack_tags:
                categories["lateral_movement"]["items"].append(primitive)
            elif "data-exposure" in attack_tags:
                categories["data_exposure"]["items"].append(primitive)
            elif "admin-plane" in attack_tags:
                categories["admin_plane"]["items"].append(primitive)
            else:
                categories["other"]["items"].append(primitive)

        return {k: v for k, v in categories.items() if v["items"]}

    # ===================================================================
    # ADVANCED FEATURES
    # ===================================================================

    # --- Target Tagging (already exists via /api/hosts/<id>/tags) ---
    # Enhanced: filter hosts by tag
    @app.route("/api/hosts/by-tag/<tag>")
    def api_hosts_by_tag(tag):
        """Get all hosts with a specific tag."""
        hosts = query_db(
            """
            SELECT h.ip, h.hostname, h.mac, h.os_fingerprint, h.is_active,
                   h.first_seen, h.last_seen, h.discovery_method
            FROM hosts h
            JOIN host_tags ht ON ht.host_id = h.id
            WHERE ht.tag = ?
            ORDER BY h.ip
        """,
            (tag,),
        )
        return jsonify({"tag": tag, "hosts": hosts, "count": len(hosts)})

    @app.route("/api/tags")
    def api_all_tags():
        """Get all unique tags with host counts."""
        tags = query_db("""
            SELECT tag, COUNT(*) as count FROM host_tags GROUP BY tag ORDER BY count DESC
        """)
        return jsonify(tags)

    # --- Findings Deduplication ---
    @app.route("/api/vulns/grouped")
    def api_vulns_grouped():
        """Group same vulnerability across multiple hosts."""
        grouped = query_db("""
            SELECT v.name, v.severity, v.template_id, COUNT(DISTINCT v.host_id) as host_count,
                   GROUP_CONCAT(DISTINCT h.ip) as affected_hosts
            FROM vulnerabilities v
            JOIN hosts h ON h.id = v.host_id
            GROUP BY v.name, v.severity
            ORDER BY host_count DESC,
                     CASE LOWER(v.severity) WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                     WHEN 'medium' THEN 2 ELSE 3 END
        """)
        return jsonify(grouped)

    # --- Conditional Nuclei Rules ---
    @app.route("/api/nuclei-rules", methods=["GET", "POST"])
    def api_nuclei_rules():
        """Manage conditional nuclei auto-trigger rules."""
        if request.method == "POST":
            data = request.get_json()
            if not data or not data.get("condition") or not data.get("template"):
                return jsonify({"error": "condition and template required"}), 400
            with get_db() as conn:
                conn.execute(
                    """
                    INSERT INTO nuclei_rules (condition_type, condition_value, template_id, enabled, created_at)
                    VALUES (?, ?, ?, 1, datetime('now'))
                """,
                    (data["condition"], data.get("condition_value", ""), data["template"]),
                )
                conn.commit()
            return jsonify({"status": "created"})
        rules = query_db("SELECT * FROM nuclei_rules ORDER BY created_at DESC")
        return jsonify(rules)

    # --- Banner Change Alerting ---
    @app.route("/api/banner-changes")
    def api_banner_changes():
        """Get recent banner changes detected."""
        changes = query_db("""
            SELECT bc.id, h.ip, h.hostname, bc.port, bc.old_banner, bc.new_banner,
                   bc.detected_at
            FROM banner_changes bc
            JOIN hosts h ON h.id = bc.host_id
            ORDER BY bc.detected_at DESC
            LIMIT 100
        """)
        return jsonify(changes)

    # --- MITRE ATT&CK Heatmap ---
    @app.route("/mitre")
    @login_required
    def mitre_heatmap():
        """MITRE ATT&CK heatmap page."""
        return render_template("mitre.html")

    @app.route("/api/mitre/coverage")
    def api_mitre_coverage():
        """Get MITRE technique coverage from findings."""
        coverage = query_db("""
            SELECT technique_id, technique_name, tactic, COUNT(*) as evidence_count,
                   MAX(confidence) as max_confidence
            FROM mitre_mappings
            GROUP BY technique_id
            ORDER BY tactic, technique_id
        """)

        # Group flat rows into the tactics structure the template expects.
        tactics = {}
        for row in coverage:
            tac = tactics.setdefault(row["tactic"], {"name": row["tactic"], "techniques": []})
            tac["techniques"].append({
                "id": row["technique_id"],
                "name": row["technique_name"],
                "hits": row["evidence_count"] or 1,
            })
        return jsonify({"tactics": list(tactics.values()), "techniques": coverage})

    # --- Risk Score Timeline ---
    @app.route("/api/risk-timeline")
    def api_risk_timeline():
        """Get risk score history over time."""
        timeline = query_db("""
            SELECT score, factors, recorded_at
            FROM risk_timeline
            ORDER BY recorded_at ASC
        """)
        return jsonify(timeline)

    # --- Traffic Budgeting ---
    @app.route("/api/traffic-budget", methods=["GET", "POST"])
    def api_traffic_budget():
        """Get/set daily packet budget."""
        if request.method == "POST":
            data = request.get_json()
            budget = data.get("daily_budget", 10000)
            with get_db() as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO traffic_budget (id, daily_budget, packets_today, reset_at)
                    VALUES (1, ?, 0, datetime('now'))
                """,
                    (budget,),
                )
                conn.commit()
            return jsonify({"status": "updated", "daily_budget": budget})
        budget = query_db("SELECT * FROM traffic_budget WHERE id = 1", one=True)
        if not budget:
            budget = {"daily_budget": 10000, "packets_today": 0, "reset_at": None}
        return jsonify(budget)

    # --- Scan Persona Rotation ---
    @app.route("/api/personas", methods=["GET", "POST"])
    def api_personas():
        """Manage scan personas (timing/TTL/port profiles)."""
        if request.method == "POST":
            data = request.get_json()
            with get_db() as conn:
                conn.execute(
                    """
                    INSERT INTO scan_personas (name, config, created_at)
                    VALUES (?, ?, datetime('now'))
                """,
                    (data.get("name", "default"), json.dumps(data.get("config", {}))),
                )
                conn.commit()
            return jsonify({"status": "created"})
        personas = query_db("SELECT * FROM scan_personas ORDER BY created_at DESC")
        return jsonify(personas)

    # --- Credential Correlation Matrix ---
    @app.route("/api/credentials")
    def api_credentials():
        """Get credential correlation matrix."""
        try:
            creds = query_db("""
                SELECT c.id, h.ip, h.hostname, c.port, c.service, c.username,
                       c.credential_hash, c.success, c.tested_at
                FROM credential_results c
                JOIN hosts h ON h.id = c.host_id
                WHERE c.success = 1
                ORDER BY c.username, h.ip
            """)
        except sqlite3.OperationalError:
            creds = []
        return jsonify(creds)

    # --- Honey Token Detection ---
    @app.route("/api/honeytokens")
    def api_honeytokens():
        """Get detected honeypots/canary tokens."""
        tokens = query_db("""
            SELECT ht.id, h.ip, h.hostname, ht.detection_type, ht.confidence,
                   ht.evidence, ht.detected_at
            FROM honeytokens ht
            JOIN hosts h ON h.id = ht.host_id
            ORDER BY ht.confidence DESC
        """)
        return jsonify(tokens)

    # --- Executive Summary ---
    @app.route("/api/executive-summary")
    def api_executive_summary():
        """Generate executive summary of the engagement."""
        stats = _get_stats()
        vulns = stats.get("vulnerabilities", {})

        summary = {
            "engagement_duration": query_db(
                "SELECT MIN(first_seen) as start, MAX(last_seen) as end FROM hosts", one=True
            ),
            "hosts_discovered": stats.get("total_hosts", 0),
            "ports_found": stats.get("total_ports", 0),
            "critical_vulns": vulns.get("critical", 0),
            "high_vulns": vulns.get("high", 0),
            "total_vulns": vulns.get("total", 0),
            "anomalies": stats.get("active_anomalies", 0),
            "attack_paths": len(
                query_db("SELECT DISTINCT technique_id FROM mitre_mappings WHERE tactic = 'initial-access'")
            ),
            "narrative": _generate_narrative(stats),
        }
        return jsonify(summary)

    def _generate_narrative(stats):
        """Auto-generate attack narrative text."""
        vulns = stats.get("vulnerabilities", {})
        hosts = stats.get("total_hosts", 0)
        critical = vulns.get("critical", 0)
        high = vulns.get("high", 0)

        if critical + high == 0:
            return f"Reconnaissance of {hosts} hosts completed. No critical or high severity vulnerabilities identified. The network posture appears strong."

        narrative = f"During this engagement, {hosts} hosts were discovered through stealth reconnaissance. "
        if critical > 0:
            narrative += (
                f"{critical} critical vulnerabilities were identified that could allow immediate system compromise. "
            )
        if high > 0:
            narrative += f"{high} high-severity issues provide potential attack paths. "
        narrative += "Detailed findings and recommended remediations are documented in the full report."
        return narrative

    # --- Attack Narrative Generation ---
    @app.route("/api/attack-narrative")
    def api_attack_narrative():
        """Generate attack narrative from findings chain."""
        # Build narrative from scan history + findings
        scans = query_db("SELECT * FROM scans ORDER BY start_time ASC LIMIT 20")
        vulns = query_db("""
            SELECT v.*, h.ip, h.hostname FROM vulnerabilities v
            JOIN hosts h ON h.id = v.host_id
            WHERE v.severity IN ('critical', 'high')
            ORDER BY v.matched_at ASC
        """)

        narrative_steps = []
        for scan in scans:
            narrative_steps.append(
                {
                    "phase": scan.get("scan_type", "unknown"),
                    "time": scan.get("start_time"),
                    "result": f"Discovered {scan.get('hosts_found', 0)} hosts, {scan.get('ports_found', 0)} ports",
                }
            )
        for vuln in vulns:
            narrative_steps.append(
                {
                    "phase": "exploitation",
                    "time": vuln.get("matched_at"),
                    "result": f"{(vuln.get('severity') or 'info').upper()}: {vuln.get('name', '?')} on {vuln.get('ip', '?')}",
                }
            )

        return jsonify({"steps": narrative_steps, "summary": _generate_narrative(_get_stats())})

    # --- Passive DNS Correlation ---
    @app.route("/api/passive-dns", methods=["GET", "POST"])
    def api_passive_dns():
        """Store/retrieve passive DNS data."""
        if request.method == "POST":
            data = request.get_json()
            with get_db() as conn:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO passive_dns (ip, domain, record_type, first_seen, last_seen, source)
                    VALUES (?, ?, ?, datetime('now'), datetime('now'), ?)
                """,
                    (data.get("ip"), data.get("domain"), data.get("type", "A"), data.get("source", "manual")),
                )
                conn.commit()
            return jsonify({"status": "added"})
        dns_records = query_db("""
            SELECT pd.*, h.hostname as current_hostname
            FROM passive_dns pd
            LEFT JOIN hosts h ON h.ip = pd.ip
            ORDER BY pd.last_seen DESC
            LIMIT 500
        """)
        return jsonify(dns_records)

    # --- Engagement Comparison ---
    @app.route("/api/compare", methods=["POST"])
    def api_compare_engagement():
        """Compare current findings against imported previous engagement."""
        data = request.get_json()
        previous = data.get("previous", {})

        current_hosts = set(r["ip"] for r in query_db("SELECT ip FROM hosts"))
        prev_hosts = set(previous.get("hosts", []))

        current_vulns = query_db("""
            SELECT name, severity, template_id, host_id, port
            FROM vulnerabilities
        """)
        prev_vulns = previous.get("vulnerabilities", [])
        current_vuln_keys = {
            (
                v.get("template_id") or "",
                v.get("name") or "",
                str(v.get("host_id") or ""),
                str(v.get("port") or ""),
            )
            for v in current_vulns
        }
        prev_vuln_keys = {
            (
                v.get("template_id") or "",
                v.get("name") or "",
                str(v.get("host_id") or ""),
                str(v.get("port") or ""),
            )
            for v in prev_vulns
        }

        comparison = {
            "new_hosts": list(current_hosts - prev_hosts),
            "removed_hosts": list(prev_hosts - current_hosts),
            "common_hosts": len(current_hosts & prev_hosts),
            "new_vulns": [
                v
                for v in current_vulns
                if (
                    (v.get("template_id") or ""),
                    (v.get("name") or ""),
                    str(v.get("host_id") or ""),
                    str(v.get("port") or ""),
                )
                not in prev_vuln_keys
            ],
            "resolved_vulns": [
                v
                for v in prev_vulns
                if (
                    (v.get("template_id") or ""),
                    (v.get("name") or ""),
                    str(v.get("host_id") or ""),
                    str(v.get("port") or ""),
                )
                not in current_vuln_keys
            ],
            "current_total": len(current_hosts),
            "previous_total": len(prev_hosts),
        }
        return jsonify(comparison)

    # --- Kill Chain Builder ---
    @app.route("/api/kill-chain", methods=["GET", "POST"])
    def api_kill_chain():
        """Build/retrieve kill chain evidence."""
        if request.method == "POST":
            data = request.get_json()
            with get_db() as conn:
                conn.execute(
                    """
                    INSERT INTO kill_chain (step_order, title, description, evidence, mitre_id, created_at)
                    VALUES (?, ?, ?, ?, ?, datetime('now'))
                """,
                    (
                        data.get("order", 0),
                        data.get("title", ""),
                        data.get("description", ""),
                        data.get("evidence", ""),
                        data.get("mitre_id", ""),
                    ),
                )
                conn.commit()
            return jsonify({"status": "added"})
        chain = query_db("SELECT * FROM kill_chain ORDER BY step_order ASC")
        return jsonify(chain)

    # --- Live Terminal (WebSocket-like via polling) ---
    @app.route("/api/terminal", methods=["POST"])
    @api_login_required
    def api_terminal():
        """Execute a HostVigil CLI command and return output."""
        data = request.get_json()
        cmd = data.get("command", "").strip()

        # Strict allowlist of safe commands and exact argument schema.
        # This blocks malformed flag/value pairs while still allowing common uses.
        def _is_safe_output_path(value: str) -> bool:
            p = Path(value)
            if p.is_absolute():
                return False
            if ".." in p.parts:
                return False
            return True

        command_specs = {
            "status": {
                "flags_no_value": {"--json"},
                "flags_with_value": {},
                "allow_positional": False,
            },
            "diff": {
                "flags_no_value": set(),
                "flags_with_value": {"--hours": "int"},
                "allow_positional": False,
            },
            "export": {
                "flags_no_value": set(),
                "flags_with_value": {
                    "--format": {"json", "csv", "report", "ips", "targets", "urls", "c2"},
                    "--output": "path",
                    "-o": "path",
                },
                "allow_positional": False,
            },
        }

        try:
            parts = shlex.split(cmd)
        except ValueError as e:
            return jsonify({"error": f"Invalid command syntax: {e}"}), 400

        if not parts:
            return jsonify({"error": "No command provided"}), 400

        cmd_base = parts[0]
        if cmd_base not in command_specs:
            return jsonify({"error": f"Command not allowed. Permitted: {list(command_specs.keys())}"}), 403

        spec = command_specs[cmd_base]
        i = 1
        while i < len(parts):
            token = parts[i]
            if token in spec["flags_no_value"]:
                i += 1
                continue

            if token in spec["flags_with_value"]:
                i += 1
                if i >= len(parts):
                    return jsonify({"error": f"Missing value for {token}"}), 400
                value = parts[i]
                rule = spec["flags_with_value"][token]
                if rule == "int":
                    if not value.isdigit():
                        return jsonify({"error": f"Invalid value for {token}: {value}"}), 400
                elif rule == "path":
                    if not _is_safe_output_path(value):
                        return jsonify({"error": f"Unsafe output path: {value}"}), 400
                elif isinstance(rule, set):
                    if value not in rule:
                        return jsonify({"error": f"Invalid value for {token}: {value}"}), 400
                i += 1
                continue

            if token.startswith("-"):
                return jsonify({"error": f"Argument not allowed: {token}"}), 403
            if not spec["allow_positional"]:
                return jsonify({"error": f"Positional argument not allowed: {token}"}), 403
            i += 1

        import subprocess

        try:
            # Use list form and current interpreter to prevent shell injection and venv drift.
            result = subprocess.run(
                [sys.executable, "run.py"] + parts,
                capture_output=True,
                text=True,
                timeout=30,
                cwd=str(Path(app.config["DB_PATH"]).parent.parent),
            )
            return jsonify({"stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode})
        except subprocess.TimeoutExpired:
            return jsonify({"error": "Command timed out (30s)"}), 408
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # --- Collaborative Mode ---
    @app.route("/api/operators", methods=["GET", "POST"])
    def api_operators():
        """Track active operators."""
        if request.method == "POST":
            data = request.get_json()
            with get_db() as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO operators (username, last_active, current_page)
                    VALUES (?, datetime('now'), ?)
                """,
                    (session.get("username", "anonymous"), data.get("page", "/")),
                )
                conn.commit()
            return jsonify({"status": "updated"})
        # Return operators active in last 5 minutes
        operators = query_db("""
            SELECT username, last_active, current_page FROM operators
            WHERE last_active > datetime('now', '-5 minutes')
        """)
        return jsonify(operators)

    # --- Egress Testing ---
    @app.route("/api/egress")
    def api_egress():
        """Get egress test results (passive detection)."""
        results = query_db("""
            SELECT * FROM egress_results ORDER BY tested_at DESC LIMIT 100
        """)
        return jsonify(results)

    # --- MITRE Heatmap page ---
    # (template created separately)

    # ===================================================================
    # Additional DB Tables for Advanced Features
    # ===================================================================
    def _init_advanced_tables():
        """Create tables for all advanced features."""
        from hostvigil.utils import ensure_application_tables

        db_path = Path(app.config["DB_PATH"])
        conn = sqlite3.connect(str(db_path))
        ensure_application_tables(conn)
        conn.commit()
        conn.close()

    _init_advanced_tables()

    from hostvigil.dashboard.exports import create_export_blueprint

    app.register_blueprint(
        create_export_blueprint(
            db_path_getter=lambda: app.config["DB_PATH"],
            query_db=query_db,
            get_stats=_get_stats,
            now_iso=_now_iso,
        )
    )

    # -------------------------------------------------------------------
    # Command Center & UI Routes
    # -------------------------------------------------------------------

    @app.route("/command-center")
    @login_required
    def command_center():
        """Modern command center UI with real-time updates."""
        return render_template("command_center.html")

    @app.route("/ad-discovery")
    @login_required
    def ad_discovery():
        """Active Directory discovery UI."""
        return render_template("ad_discovery.html")

    @app.route("/credentials")
    @login_required
    def credentials():
        """Credential checker UI."""
        return render_template("credentials.html")

    @app.route("/settings")
    @login_required
    def settings():
        """Configuration settings UI."""
        return render_template("settings.html")

    # -------------------------------------------------------------------
    # AD Discovery API Routes
    # -------------------------------------------------------------------

    @app.route("/api/ad/discover", methods=["POST"])
    @api_login_required
    def api_ad_discover():
        """Run Active Directory discovery."""
        from hostvigil.discovery.ad_discovery import ADDiscoverer

        data = request.json or {}
        dc = data.get("dc", "")
        domain = data.get("domain", "")
        username = data.get("username", "")
        password = data.get("password", "")

        try:
            ad = ADDiscoverer()

            # Connect
            if username and password and domain:
                if not ad.connect_with_creds(dc, username, password, domain):
                    return jsonify({"error": "Failed to connect with provided credentials"}), 400
            else:
                if not ad.connect_anonymous(dc):
                    return jsonify({"error": "Failed to connect anonymously"}), 400

            # Get data
            computers = ad.get_all_computers()
            servers = ad.get_all_servers()
            dcs = ad.get_domain_controllers()
            ous = ad.get_ou_structure()

            # Store in database
            with get_db() as conn:
                for host in computers:
                    conn.execute(
                        "INSERT OR REPLACE INTO hosts (ip, hostname, os_type, status, last_seen) VALUES (?, ?, ?, ?, datetime('now'))",
                        (host.get("ip", ""), host.get("hostname", ""), "windows", "active"),
                    )
                conn.commit()

            return jsonify({"computers": computers, "servers": servers, "domain_controllers": dcs, "ous": ous})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # -------------------------------------------------------------------
    # Credential Checker API Routes
    # -------------------------------------------------------------------

    _CREDENTIAL_CHECK_ID = 1  # Single concurrent credential check at a time (see type_lock below)

    @app.route("/api/credentials/check", methods=["POST"])
    @api_login_required
    def api_credentials_check():
        """Launch a real credential spray against discovered services in a background thread."""
        from hostvigil.scanner.credential_spray import StealthCredentialSpray

        scan_key = "credential_check"
        with _scan_locks_master:
            if scan_key not in _scan_locks:
                _scan_locks[scan_key] = threading.Lock()
            type_lock = _scan_locks[scan_key]

        if not type_lock.acquire(blocking=False):
            return jsonify({"error": "A credential check is already in progress", "status": "busy"}), 409

        status_entry = {
            "type": scan_key,
            "status": "running",
            "started": _now_iso(),
            "progress": 0,
            "successes": 0,
            "results": [],
        }
        with _active_scans_lock:
            _active_scans[scan_key] = status_entry

        def _on_progress(done, total, results_so_far):
            successes = [r for r in results_so_far if r.get("success")]
            with _active_scans_lock:
                _active_scans[scan_key] = {
                    **_active_scans[scan_key],
                    "progress": int(done * 100 / total) if total else 100,
                    "successes": len(successes),
                    "results": results_so_far,
                }

        def _run_check():
            _append_scan_log("info", "Started credential check")
            try:
                spray = StealthCredentialSpray({}, app.config["DB_PATH"])
                results = spray.spray_all(progress_callback=_on_progress)
                successes = [r for r in results if r.get("success")]
                completed_status = {
                    "type": scan_key,
                    "status": "completed",
                    "started": status_entry["started"],
                    "completed": _now_iso(),
                    "progress": 100,
                    "successes": len(successes),
                    "results": results,
                }
                with _active_scans_lock:
                    _active_scans[scan_key] = completed_status
                _append_scan_log("info", f"Completed credential check: {len(successes)} valid credential(s) found")
            except Exception as e:
                with _active_scans_lock:
                    _active_scans[scan_key] = {
                        **_active_scans.get(scan_key, {}),
                        "status": "error",
                        "error": str(e),
                    }
                _append_scan_log("error", f"Error in credential check: {e}")
            finally:
                type_lock.release()

        try:
            thread = threading.Thread(target=_run_check, daemon=True, name="scan-credential_check")
            thread.start()
        except Exception:
            type_lock.release()
            return jsonify({"error": "Failed to start credential check thread"}), 500

        return jsonify({"status": "started", "check_id": _CREDENTIAL_CHECK_ID})

    @app.route("/api/credentials/status/<int:check_id>")
    @api_login_required
    def api_credentials_status(check_id):
        """Get real credential check progress/results from the background job."""
        with _active_scans_lock:
            status = dict(_active_scans.get("credential_check", {}))
        if not status:
            return jsonify({"progress": 0, "successes": 0, "results": [], "status": "idle"})
        return jsonify(
            {
                "progress": status.get("progress", 0),
                "successes": status.get("successes", 0),
                "results": status.get("results", []),
                "status": status.get("status", "running"),
                "error": status.get("error"),
            }
        )

    # -------------------------------------------------------------------
    # Custom Credential Management API
    # -------------------------------------------------------------------

    @app.route("/api/credentials/custom")
    @api_login_required
    def api_custom_credentials_list():
        """List all custom credential pairs."""
        with get_db() as conn:
            rows = conn.execute(
                "SELECT id, username, password, label, added_at FROM custom_credentials ORDER BY added_at DESC"
            ).fetchall()
            return jsonify([dict(r) for r in rows])

    @app.route("/api/credentials/custom", methods=["POST"])
    @api_login_required
    def api_custom_credentials_add():
        """Add a new custom credential pair."""
        data = request.json or {}
        username = (data.get("username") or "").strip()
        password = data.get("password", "")
        label = (data.get("label") or "").strip() or None

        if not username:
            return jsonify({"error": "Username is required"}), 400

        with get_db() as conn:
            try:
                conn.execute(
                    "INSERT INTO custom_credentials (username, password, label, added_at) VALUES (?, ?, ?, ?)",
                    (username, password, label, _now_iso()),
                )
                conn.commit()
                return jsonify({"status": "ok", "message": f"Credential added: {username}"})
            except sqlite3.IntegrityError:
                return jsonify({"error": "This username/password pair already exists"}), 409

    @app.route("/api/credentials/custom/<int:cred_id>", methods=["DELETE"])
    @api_login_required
    def api_custom_credentials_delete(cred_id):
        """Delete a custom credential pair."""
        with get_db() as conn:
            cursor = conn.execute("DELETE FROM custom_credentials WHERE id = ?", (cred_id,))
            conn.commit()
            if cursor.rowcount == 0:
                return jsonify({"error": "Credential not found"}), 404
            return jsonify({"status": "ok", "message": "Credential deleted"})

    # -------------------------------------------------------------------
    # Targets API Routes
    # -------------------------------------------------------------------

    @app.route("/api/targets/add", methods=["POST"])
    @api_login_required
    def api_targets_add():
        """Add new targets."""
        data = request.json or {}
        ranges = data.get("ranges") or data.get("ips") or []

        try:
            from pathlib import Path

            import yaml

            config_path = Path("config.yaml")
            if not config_path.exists():
                return jsonify(
                    {"status": "error", "error": "config.yaml not found — create it before adding targets"}
                ), 400

            with open(config_path) as f:
                doc = yaml.safe_load(f) or {}

            if not isinstance(doc.get("hostvigil"), dict):
                return (
                    jsonify({"status": "error", "error": "config.yaml is missing the 'hostvigil' section"}),
                    400,
                )

            cfg = doc["hostvigil"]
            discovery = cfg.get("discovery")
            if not isinstance(discovery, dict):
                discovery = {}
                cfg["discovery"] = discovery

            # Add ranges to config
            current_ranges = discovery.get("target_ranges") if isinstance(discovery.get("target_ranges"), list) else []
            added = []
            for r in ranges:
                r = str(r).strip()
                if r and r not in current_ranges:
                    current_ranges.append(r)
                    added.append(r)
            discovery["target_ranges"] = current_ranges

            with open(config_path, "w") as f:
                # Preserve any non-hostvigil top-level keys; the config file's
                # top level is the 'hostvigil' dict itself.
                yaml.dump(doc, f, default_flow_style=False, sort_keys=False)
            return jsonify({"status": "saved", "ranges": current_ranges, "added": added})
        except Exception as e:
            return jsonify({"status": "error", "error": str(e)}), 500

    # -------------------------------------------------------------------
    # Services API Routes
    # -------------------------------------------------------------------

    @app.route("/api/services/summary")
    @api_login_required
    def api_services_summary():
        """Get services summary."""
        try:
            with get_db() as conn:
                services = conn.execute(
                    "SELECT service_name as service, COUNT(*) as count FROM service_fingerprints GROUP BY service_name ORDER BY count DESC"
                ).fetchall()
            return jsonify({"services": [{"service": s["service"], "count": s["count"]} for s in services]})
        except Exception as e:
            return jsonify({"status": "error", "error": str(e)}), 500

    @app.route("/api/settings/profiles")
    @api_login_required
    def api_get_config_profiles():
        """Get available configuration profiles."""
        try:
            from hostvigil.config import PRECONFIGURED_PROFILES

            profiles = {}
            for key, profile in PRECONFIGURED_PROFILES.items():
                profiles[key] = {
                    "name": profile["name"],
                    "description": profile["description"],
                    "icon": profile.get("icon", "bi-gear"),
                }
            return jsonify(profiles)
        except Exception:
            # Fallback profiles if import fails
            return jsonify(
                {
                    "basic": {
                        "name": "Basic (Small Network)",
                        "description": "Fast scanning for < 500 hosts",
                        "icon": "bi-house-door",
                    },
                    "sme": {
                        "name": "SME (Medium Network)",
                        "description": "Balanced for 500-5K hosts",
                        "icon": "bi-buildings",
                    },
                    "enterprise": {
                        "name": "Enterprise (Large Network)",
                        "description": "Maximum stealth for 5K-200K+ hosts",
                        "icon": "bi-globe-americas",
                    },
                }
            )

    @app.route("/api/settings/profile/<profile_id>")
    @api_login_required
    def api_get_config_profile(profile_id):
        """Get specific profile configuration."""
        try:
            from hostvigil.config import PRECONFIGURED_PROFILES

            if profile_id in PRECONFIGURED_PROFILES:
                return jsonify(PRECONFIGURED_PROFILES[profile_id]["config"])
            return jsonify({"error": "Profile not found"}), 404
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/settings", methods=["GET"])
    @api_login_required
    def api_get_settings():
        """Get current configuration."""
        try:
            from pathlib import Path

            from hostvigil.config import get_config

            config_path = Path("config.yaml")
            if config_path.exists():
                config = get_config(str(config_path))
                # Config object stores data in _data dict
                if hasattr(config, "_data"):
                    return jsonify(config._data)
                return jsonify({})
            return jsonify(
                {
                    "target_ranges": ["192.168.1.0/24"],
                    "discovery": {"techniques": ["arp_sweep", "icmp_sweep", "dns_reverse_walk"]},
                    "scanner": {"mode": "two_phase", "naabu": {"rate": 5000, "threads": 50}},
                    "stealth": {"profile": "shadow"},
                    "nuclei": {"auto_run": True, "severity_filter": ["critical", "high"]},
                    "pipeline": {"mode": "wave", "wave_size": 100},
                    "logging": {"level": "WARNING", "file_path": "data/ops.log"},
                }
            )
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/settings", methods=["POST"])
    @api_login_required
    def api_save_settings():
        """Save configuration."""
        from pathlib import Path

        import yaml

        data = request.json or {}
        config = data.get("config", {})
        try:
            config_path = Path("config.yaml")
            if config_path.exists():
                import shutil

                shutil.copy(str(config_path), str(config_path) + ".backup")
            with open(config_path, "w") as f:
                if "hostvigil" in config:
                    yaml_data = config
                else:
                    yaml_data = {"hostvigil": config}
                yaml.dump(yaml_data, f, default_flow_style=False, sort_keys=False)
            return jsonify({"status": "saved"})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    return app


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def run_dashboard(config: dict = None):
    """Run the dashboard server."""
    app = create_app(config)
    host = app.config.get("HOST", "127.0.0.1")
    port = app.config.get("PORT", 5000)
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    run_dashboard()
