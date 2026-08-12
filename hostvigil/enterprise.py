"""
HostVigil Enterprise Extensions

Additional features for large-scale deployments:
- API key authentication
- Rate limiting
- Persistent secret key generation
- Request logging
"""

import hashlib
import logging
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from typing import Dict, List, Optional

from flask import g, jsonify, request

logger = logging.getLogger("hostvigil.enterprise")

# ============================================================================
# Persistent Secret Key Generation
# ============================================================================


def generate_persistent_secret_key(secret_file: str = "data/.secret_key") -> str:
    """
    Generate and persist a secret key across restarts.

    This fixes the session invalidation issue where random keys
    break user sessions on every restart.

    Args:
        secret_file: Path to store the secret key

    Returns:
        32-byte hex secret key
    """
    path = Path(secret_file)

    # Ensure directory exists
    path.parent.mkdir(parents=True, exist_ok=True)

    if path.exists():
        try:
            key = path.read_text().strip()
            # Validate that the key is hex-only and long enough
            if len(key) >= 32 and all(c in "0123456789abcdef" for c in key):
                logger.debug("Loaded existing secret key")
                return key
            else:
                logger.warning("Existing secret key is invalid or corrupted, regenerating")
        except Exception as e:
            logger.warning(f"Failed to read secret key: {e}")

    # Generate new key
    new_key = secrets.token_hex(32)

    try:
        path.write_text(new_key)
        path.chmod(0o600)  # Restrict permissions
        logger.info("Generated new persistent secret key")
    except Exception as e:
        logger.warning(f"Failed to persist secret key: {e}")

    return new_key


# ============================================================================
# Simple Rate Limiter (In-Memory)
# ============================================================================


class RateLimiter:
    """
    Simple in-memory rate limiter for API endpoints.

    For production, use Redis or database-backed limiter.
    """

    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: Dict[str, List[float]] = {}
        self._lock = threading.Lock()

    def is_allowed(self, identifier: str) -> bool:
        """Check if request is allowed for given identifier (IP or user)."""
        now = time.time()
        window_start = now - self.window_seconds

        with self._lock:
            # Cleanup old requests
            if identifier in self._requests:
                self._requests[identifier] = [ts for ts in self._requests[identifier] if ts > window_start]
            else:
                self._requests[identifier] = []

            # Check if under limit
            if len(self._requests[identifier]) < self.max_requests:
                self._requests[identifier].append(now)
                return True

            return False

    def get_remaining(self, identifier: str) -> int:
        """Get remaining requests allowed in current window."""
        now = time.time()
        window_start = now - self.window_seconds

        with self._lock:
            if identifier not in self._requests:
                return self.max_requests

            current = len([ts for ts in self._requests[identifier] if ts > window_start])
            return max(0, self.max_requests - current)


# Global rate limiter instance
_api_rate_limiter = RateLimiter(max_requests=100, window_seconds=60)


def rate_limit(max_requests: int = 100, window_seconds: int = 60):
    """
    Decorator to rate limit API endpoints.

    Usage:
        @app.route('/api/data')
        @rate_limit(max_requests=50, window_seconds=60)
        def get_data():
            ...
    """

    def decorator(f):
        # Create a per-route RateLimiter using the provided parameters
        limiter = RateLimiter(max_requests=max_requests, window_seconds=window_seconds)

        @wraps(f)
        def wrapped(*args, **kwargs):
            # Get client identifier (IP or API key)
            identifier = request.headers.get("X-API-Key")
            if not identifier:
                identifier = request.remote_addr or "unknown"

            if not limiter.is_allowed(identifier):
                remaining = limiter.get_remaining(identifier)
                response = jsonify({"error": "Rate limit exceeded", "retry_after": window_seconds})
                response.headers["X-RateLimit-Limit"] = str(max_requests)
                response.headers["X-RateLimit-Remaining"] = str(remaining)
                response.headers["Retry-After"] = str(window_seconds)
                return response, 429

            response = f(*args, **kwargs)

            # Add rate limit headers to successful responses
            if hasattr(response, "headers"):
                remaining = limiter.get_remaining(identifier)
                response.headers["X-RateLimit-Limit"] = str(max_requests)
                response.headers["X-RateLimit-Remaining"] = str(remaining)

            return response

        return wrapped

    return decorator


# ============================================================================
# API Key Authentication
# ============================================================================


class APIKeyManager:
    """Manage API keys for programmatic access."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._cache: Dict[str, dict] = {}
        self._cache_expiry: Dict[str, float] = {}
        self._cache_ttl = 300  # 5 minutes
        self._lock = threading.Lock()

    def _get_conn(self):
        """Get database connection."""
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        return conn

    def ensure_table(self):
        """Create API keys table if not exists."""
        conn = self._get_conn()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS api_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key_hash TEXT UNIQUE NOT NULL,
                    name TEXT NOT NULL,
                    created_by TEXT,
                    created_at TEXT NOT NULL,
                    last_used_at TEXT,
                    expires_at TEXT,
                    is_active INTEGER DEFAULT 1,
                    permissions TEXT DEFAULT 'read'
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash)")
            conn.commit()
        finally:
            conn.close()

    def _hash_key(self, key: str) -> str:
        """Hash API key for storage."""
        return hashlib.sha256(key.encode()).hexdigest()

    def create_key(
        self, name: str, created_by: str = "admin", expires_days: int = None, permissions: str = "read"
    ) -> str:
        """
        Create new API key.

        Returns:
            The raw API key (only shown once)
        """
        # Generate key
        raw_key = secrets.token_urlsafe(32)
        key_hash = self._hash_key(raw_key)

        now = datetime.now(timezone.utc).isoformat()
        expires_at = None
        if expires_days:
            from datetime import timedelta

            expires_at = (datetime.now(timezone.utc) + timedelta(days=expires_days)).isoformat()

        conn = self._get_conn()
        try:
            conn.execute(
                """
                INSERT INTO api_keys (key_hash, name, created_by, created_at, expires_at, permissions)
                VALUES (?, ?, ?, ?, ?, ?)
            """,
                (key_hash, name, created_by, now, expires_at, permissions),
            )
            conn.commit()
            logger.info(f"Created API key: {name} (created by {created_by})")
        finally:
            conn.close()

        return raw_key

    def validate_key(self, raw_key: str) -> Optional[dict]:
        """Validate API key and return key info if valid."""
        key_hash = self._hash_key(raw_key)
        now = time.time()

        # Check cache first
        with self._lock:
            if key_hash in self._cache:
                if now < self._cache_expiry.get(key_hash, 0):
                    return self._cache[key_hash]
                else:
                    del self._cache[key_hash]
                    del self._cache_expiry[key_hash]

        # Query database
        conn = self._get_conn()
        try:
            cursor = conn.execute(
                """
                SELECT id, key_hash, name, created_by, created_at,
                       last_used_at, expires_at, is_active, permissions
                FROM api_keys
                WHERE key_hash = ?
            """,
                (key_hash,),
            )
            row = cursor.fetchone()

            if not row:
                return None

            # Check if active
            if not row["is_active"]:
                return None

            # Check expiry
            if row["expires_at"]:
                try:
                    expires = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))
                    if datetime.now(timezone.utc) > expires:
                        return None
                except (ValueError, TypeError):
                    pass

            # Update last_used_at
            conn.execute("UPDATE api_keys SET last_used_at = ? WHERE id = ?", (now_iso(), row["id"]))
            conn.commit()

            # Cache result
            result = dict(row)
            with self._lock:
                self._cache[key_hash] = result
                self._cache_expiry[key_hash] = now + self._cache_ttl

            return result

        finally:
            conn.close()

    def list_keys(self) -> list:
        """List all API keys (without exposing the actual keys)."""
        conn = self._get_conn()
        try:
            cursor = conn.execute("""
                SELECT id, name, created_by, created_at, last_used_at,
                       expires_at, is_active, permissions
                FROM api_keys
                ORDER BY created_at DESC
            """)
            return [dict(row) for row in cursor.fetchall()]
        finally:
            conn.close()

    def revoke_key(self, key_id: int) -> bool:
        """Revoke an API key."""
        conn = self._get_conn()
        try:
            conn.execute("UPDATE api_keys SET is_active = 0 WHERE id = ?", (key_id,))
            conn.commit()
            logger.info(f"Revoked API key ID {key_id}")
            return True
        finally:
            conn.close()


# ============================================================================
# Request Logging Middleware
# ============================================================================


class RequestLogger:
    """Log all API requests for audit trail."""

    def __init__(self, app, db_path: str):
        self.app = app
        self.db_path = db_path
        self._enabled = True

    def _get_conn(self):
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        return conn

    def ensure_table(self):
        """Create request log table."""
        conn = self._get_conn()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS api_request_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    method TEXT NOT NULL,
                    endpoint TEXT NOT NULL,
                    remote_addr TEXT,
                    user_agent TEXT,
                    api_key_id INTEGER,
                    username TEXT,
                    status_code INTEGER,
                    response_time_ms INTEGER,
                    request_size INTEGER,
                    response_size INTEGER
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_api_log_timestamp ON api_request_log(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_api_log_endpoint ON api_request_log(endpoint)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_api_log_user ON api_request_log(username)")
            conn.commit()
        finally:
            conn.close()

    def register(self):
        """Register request/response hooks."""
        if not self._enabled:
            return

        self.ensure_table()

        @self.app.before_request
        def before_request():
            g.start_time = time.time()
            g.request_size = request.content_length or 0

        @self.app.after_request
        def after_request(response):
            if not request.path.startswith("/api/"):
                return response

            # Calculate response time
            duration_ms = int((time.time() - getattr(g, "start_time", time.time())) * 1000)
            response_size = response.content_length or 0

            # Get user info
            api_key_id = getattr(g, "api_key_id", None)
            username = getattr(g, "username", None)
            request_size = getattr(g, "request_size", 0)

            # Log asynchronously (don't block response)
            try:
                self._log_request(
                    method=request.method,
                    endpoint=request.path,
                    remote_addr=request.remote_addr,
                    user_agent=request.headers.get("User-Agent", "")[:200],
                    api_key_id=api_key_id,
                    username=username,
                    status_code=response.status_code,
                    response_time_ms=duration_ms,
                    request_size=request_size,
                    response_size=response_size,
                )
            except Exception as e:
                logger.debug(f"Request logging failed: {e}")

            return response

    def _log_request(self, **kwargs):
        """Insert log entry."""
        conn = None
        try:
            conn = self._get_conn()
            conn.execute(
                """
                INSERT INTO api_request_log
                (timestamp, method, endpoint, remote_addr, user_agent,
                 api_key_id, username, status_code, response_time_ms,
                 request_size, response_size)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    now_iso(),
                    kwargs["method"],
                    kwargs["endpoint"],
                    kwargs["remote_addr"],
                    kwargs["user_agent"],
                    kwargs.get("api_key_id"),
                    kwargs.get("username"),
                    kwargs["status_code"],
                    kwargs["response_time_ms"],
                    kwargs.get("request_size", 0),
                    kwargs.get("response_size", 0),
                ),
            )
            conn.commit()
        finally:
            if conn:
                conn.close()


# ============================================================================
# Import helpers
# ============================================================================


def now_iso() -> str:
    """Get current UTC timestamp in ISO format."""
    return datetime.now(timezone.utc).isoformat()
