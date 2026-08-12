"""
Shared utility functions for HostVigil.

Provides:
- Stealth file-only logging (no console output to avoid detection)
- Timestamp helpers
- IP address validation
- SQLite database initialization
- BatchDBWriter for high-throughput DB writes
"""

import ipaddress
import logging
import logging.handlers
import os
import queue
import socket
import sqlite3
import threading
import time as _time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

# ---------------------------------------------------------------------------
# Logging Setup (Stealth - file only, no console handlers)
# ---------------------------------------------------------------------------


def setup_logging(
    log_dir: str | Path = "data/logs",
    log_level: int = logging.INFO,
    log_filename: str = "hostvigil.log",
) -> logging.Logger:
    """Configure stealth file-only logging.

    No console output is produced to minimize detection footprint.
    """
    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("hostvigil")
    logger.setLevel(log_level)

    # Remove any existing handlers to prevent console leakage
    logger.handlers.clear()
    logger.propagate = False

    # Rotating file handler — 50 MB × 5 backups, stealth mode
    file_handler = logging.handlers.RotatingFileHandler(
        log_path / log_filename,
        maxBytes=50 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setLevel(log_level)

    hostname = socket.gethostname()
    pid = os.getpid()

    formatter = logging.Formatter(
        fmt=f"%(asctime)sZ {hostname} hostvigil[{pid}] %(levelname)s %(name)s %(message)s",
    )
    formatter.default_time_format = "%Y-%m-%dT%H:%M:%S"
    formatter.default_msec_format = "%s.%03d"
    formatter.converter = _time.gmtime
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger


def get_logger(name: str = "hostvigil") -> logging.Logger:
    """Get a child logger under the hostvigil namespace."""
    return logging.getLogger(f"hostvigil.{name}")


# ---------------------------------------------------------------------------
# Batch Database Writer — thread-safe, queue-backed, single connection
# ---------------------------------------------------------------------------


class BatchDBWriter:
    """High-throughput SQLite writer using a dedicated writer thread.

    Producers enqueue (sql, params) tuples; the writer thread drains the queue
    in configurable batches, using a single persistent connection.  This
    eliminates the per-row connect/commit/close overhead that previously
    caused O(n) file-descriptor and WAL-lock contention with 200k+ hosts.

    Usage::

        writer = BatchDBWriter("data/hostvigil.db")
        writer.start()
        writer.enqueue("INSERT INTO ports ...", (host_id, port, ...))
        # ... many more enqueue calls from concurrent threads ...
        writer.flush()   # drain remaining items
        writer.stop()
    """

    def __init__(self, db_path: str, batch_interval: float = 1.0, max_batch: int = 500):
        self._queue: queue.Queue = queue.Queue()
        self._db_path = db_path
        self._batch_interval = batch_interval
        self._max_batch = max_batch
        self._conn: sqlite3.Connection | None = None
        self._thread: threading.Thread | None = None
        self._shutdown = threading.Event()
        self._lock = threading.Lock()
        self._total_written = 0
        self._total_errors = 0

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._shutdown.clear()
        self._conn = sqlite3.connect(self._db_path, timeout=30)
        self._conn.execute("PRAGMA busy_timeout=30000")
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._thread = threading.Thread(target=self._writer_loop, name="hv-db-writer", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._shutdown.set()
        if self._thread:
            self._thread.join(timeout=30)
            self._thread = None
        if self._conn:
            self._conn.close()
            self._conn = None

    def enqueue(self, sql: str, params: tuple = ()) -> None:
        self._queue.put((sql, params))

    def flush(self) -> None:
        """Drain pending writes. No-op if the writer was never started."""
        if self._thread is None or not self._thread.is_alive():
            return
        self._drain_batch()

    @property
    def stats(self) -> dict:
        return {
            "queued": self._queue.qsize(),
            "total_written": self._total_written,
            "total_errors": self._total_errors,
        }

    def _writer_loop(self) -> None:
        while not self._shutdown.is_set():
            self._drain_batch()
            self._shutdown.wait(timeout=self._batch_interval)

    def _drain_batch(self) -> None:
        batch: list[tuple[str, tuple]] = []
        try:
            while len(batch) < self._max_batch:
                batch.append(self._queue.get_nowait())
        except queue.Empty:
            pass

        if not batch:
            return

        with self._lock:
            try:
                for sql, params in batch:
                    self._conn.execute(sql, params)
                self._conn.commit()
                self._total_written += len(batch)
            except sqlite3.Error:
                self._total_errors += len(batch)
                try:
                    self._conn.rollback()
                except sqlite3.Error:
                    pass


def wal_checkpoint(db_path: str) -> None:
    """Truncate the WAL file to reclaim disk space after a daemon cycle."""
    try:
        conn = sqlite3.connect(db_path, timeout=10)
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.close()
    except sqlite3.Error:
        pass


# ---------------------------------------------------------------------------
# Timestamp Helpers
# ---------------------------------------------------------------------------


def now_utc() -> datetime:
    """Return the current UTC timestamp."""
    return datetime.now(timezone.utc)


def now_iso() -> str:
    """Return the current UTC time as an ISO 8601 string."""
    return now_utc().isoformat()


def timestamp_to_iso(dt: datetime) -> str:
    """Convert a datetime object to ISO 8601 string."""
    return dt.isoformat()


def iso_to_timestamp(iso_str: str) -> datetime:
    """Parse an ISO 8601 string to a datetime object."""
    return datetime.fromisoformat(iso_str)


def elapsed_seconds(start: datetime, end: datetime | None = None) -> float:
    """Calculate elapsed seconds between two timestamps."""
    if end is None:
        end = now_utc()
    return (end - start).total_seconds()


# ---------------------------------------------------------------------------
# IP Address Validation
# ---------------------------------------------------------------------------


def is_valid_ip(address: str) -> bool:
    """Validate an IPv4 address."""
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def is_valid_network(cidr: str) -> bool:
    """Validate a CIDR network notation."""
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


def is_private_ip(address: str) -> bool:
    """Check if an IP address is in a private range."""
    try:
        return ipaddress.ip_address(address).is_private
    except ValueError:
        return False


def expand_network(cidr: str, max_hosts: int = 65536) -> list[str]:
    """Expand a CIDR network to a list of host IP strings.

    Limited to max_hosts (default 65536) to prevent memory exhaustion
    on very large networks like /8. Returns empty list if network exceeds limit.
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        if network.num_addresses - 2 > max_hosts:  # subtract network + broadcast
            return []
        return [str(host) for host in network.hosts()]
    except ValueError:
        return []


# ---------------------------------------------------------------------------
# Database Initialization
# ---------------------------------------------------------------------------

_DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL UNIQUE,
    mac TEXT,
    hostname TEXT,
    os_fingerprint TEXT,
    os_confidence REAL DEFAULT 0.0,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    discovery_method TEXT,
    discovery_source TEXT DEFAULT 'active',
    priority_score REAL DEFAULT 0.0,
    is_active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'tcp',
    state TEXT NOT NULL DEFAULT 'open',
    service TEXT,
    banner TEXT,
    product TEXT,
    version TEXT,
    cpe TEXT,
    extra_info TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1,
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE,
    UNIQUE(host_id, port, protocol)
);

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_type TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT,
    hosts_found INTEGER DEFAULT 0,
    ports_found INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    port_id INTEGER,
    template_id TEXT,
    name TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT,
    matched_at TEXT NOT NULL,
    evidence TEXT,
    is_verified INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE,
    FOREIGN KEY (port_id) REFERENCES ports(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS anomalies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    anomaly_type TEXT NOT NULL,
    score REAL NOT NULL,
    description TEXT,
    detected_at TEXT NOT NULL,
    is_reviewed INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS tls_certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER,
    ip TEXT,
    port INTEGER NOT NULL DEFAULT 443,
    subject TEXT,
    issuer TEXT,
    serial_number TEXT,
    not_before TEXT,
    not_after TEXT,
    is_expired INTEGER DEFAULT 0,
    is_self_signed INTEGER DEFAULT 0,
    signature_algorithm TEXT,
    key_type TEXT,
    key_size INTEGER,
    key_bits INTEGER,
    san_names TEXT,
    san_domains TEXT,
    protocol_version TEXT,
    cipher_suite TEXT,
    cipher_bits INTEGER,
    weaknesses TEXT,
    fingerprint_sha256 TEXT,
    cert_fingerprint_sha256 TEXT,
    weak_cipher INTEGER DEFAULT 0,
    inspected_at TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS service_enumeration (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER,
    ip TEXT,
    port INTEGER,
    service_type TEXT,
    finding_type TEXT,
    severity TEXT DEFAULT 'info',
    risk_level TEXT,
    title TEXT,
    details TEXT,
    findings TEXT,
    enum_data TEXT,
    discovered_at TEXT,
    enumerated_at TEXT,
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ml_training_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    trained_at TEXT NOT NULL,
    samples_count INTEGER NOT NULL,
    model_version TEXT NOT NULL,
    accuracy_score REAL
);

CREATE TABLE IF NOT EXISTS host_tags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    tag TEXT NOT NULL,
    added_at TEXT NOT NULL,
    FOREIGN KEY (host_id) REFERENCES hosts(id),
    UNIQUE(host_id, tag)
);

CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip);
CREATE INDEX IF NOT EXISTS idx_hosts_active ON hosts(is_active);
CREATE INDEX IF NOT EXISTS idx_ports_host ON ports(host_id);
CREATE INDEX IF NOT EXISTS idx_ports_active ON ports(is_active);
CREATE INDEX IF NOT EXISTS idx_ports_state_active ON ports(state, is_active);
CREATE INDEX IF NOT EXISTS idx_ports_host_state_active ON ports(host_id, state, is_active);
CREATE INDEX IF NOT EXISTS idx_vulns_host ON vulnerabilities(host_id);
CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vulns_host_severity ON vulnerabilities(host_id, severity);
CREATE INDEX IF NOT EXISTS idx_anomalies_host ON anomalies(host_id);
CREATE INDEX IF NOT EXISTS idx_anomalies_score ON anomalies(score);
CREATE INDEX IF NOT EXISTS idx_anomalies_reviewed_score ON anomalies(is_reviewed, score);
CREATE INDEX IF NOT EXISTS idx_host_tags_host ON host_tags(host_id);
CREATE INDEX IF NOT EXISTS idx_host_tags_tag ON host_tags(tag);
"""

_APP_FEATURE_SCHEMA = """
CREATE TABLE IF NOT EXISTS schedules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_type TEXT NOT NULL,
    cron_expr TEXT NOT NULL,
    enabled INTEGER DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    target_ranges TEXT,
    scan_type TEXT DEFAULT 'full',
    notes TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS webhooks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    events TEXT DEFAULT 'all',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alert_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    title TEXT NOT NULL,
    message TEXT,
    severity TEXT NOT NULL DEFAULT 'info',
    webhook_count INTEGER DEFAULT 0,
    sent_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ad_objects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    object_type TEXT NOT NULL,
    name TEXT NOT NULL,
    dn TEXT,
    attributes_json TEXT,
    discovered_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ml_feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    anomaly_id INTEGER,
    host_id INTEGER,
    anomaly_type TEXT,
    score REAL,
    features TEXT,
    is_true_positive INTEGER NOT NULL,
    feedback_at TEXT NOT NULL,
    operator_notes TEXT,
    FOREIGN KEY (anomaly_id) REFERENCES anomalies(id) ON DELETE SET NULL,
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ml_temporal_baseline (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hour_of_week INTEGER NOT NULL,
    feature_name TEXT NOT NULL,
    mean_value REAL,
    std_value REAL,
    sample_count INTEGER DEFAULT 0,
    updated_at TEXT NOT NULL,
    UNIQUE(hour_of_week, feature_name)
);

CREATE TABLE IF NOT EXISTS ml_network_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_at TEXT NOT NULL,
    total_hosts INTEGER,
    total_ports INTEGER,
    port_distribution TEXT,
    service_distribution TEXT,
    new_hosts_since_last INTEGER DEFAULT 0,
    lost_hosts_since_last INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS ml_service_correlations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    service_a TEXT NOT NULL,
    service_b TEXT NOT NULL,
    co_occurrence_count INTEGER DEFAULT 0,
    total_hosts_with_a INTEGER DEFAULT 0,
    total_hosts_with_b INTEGER DEFAULT 0,
    correlation_score REAL DEFAULT 0.0,
    updated_at TEXT NOT NULL,
    UNIQUE(service_a, service_b)
);

CREATE TABLE IF NOT EXISTS nuclei_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    condition_type TEXT NOT NULL,
    condition_value TEXT,
    template_id TEXT NOT NULL,
    enabled INTEGER DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS banner_changes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    port INTEGER NOT NULL,
    old_banner TEXT,
    new_banner TEXT,
    detected_at TEXT NOT NULL,
    FOREIGN KEY (host_id) REFERENCES hosts(id)
);

CREATE TABLE IF NOT EXISTS mitre_mappings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    technique_id TEXT NOT NULL,
    technique_name TEXT NOT NULL,
    tactic TEXT NOT NULL,
    confidence REAL DEFAULT 0.5,
    evidence TEXT,
    host_id INTEGER,
    created_at TEXT NOT NULL,
    FOREIGN KEY (host_id) REFERENCES hosts(id)
);

CREATE TABLE IF NOT EXISTS risk_timeline (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    score REAL NOT NULL,
    factors TEXT,
    recorded_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS traffic_budget (
    id INTEGER PRIMARY KEY DEFAULT 1,
    daily_budget INTEGER DEFAULT 10000,
    packets_today INTEGER DEFAULT 0,
    reset_at TEXT
);

CREATE TABLE IF NOT EXISTS scan_personas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    config TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS honeytokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    detection_type TEXT NOT NULL,
    confidence REAL DEFAULT 0.5,
    evidence TEXT,
    detected_at TEXT NOT NULL,
    FOREIGN KEY (host_id) REFERENCES hosts(id)
);

CREATE TABLE IF NOT EXISTS passive_dns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    domain TEXT NOT NULL,
    record_type TEXT DEFAULT 'A',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    source TEXT DEFAULT 'manual',
    UNIQUE(ip, domain, record_type)
);

CREATE TABLE IF NOT EXISTS kill_chain (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    step_order INTEGER NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    evidence TEXT,
    mitre_id TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS operators (
    username TEXT PRIMARY KEY,
    last_active TEXT NOT NULL,
    current_page TEXT
);

CREATE TABLE IF NOT EXISTS egress_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_ip TEXT,
    dest_port INTEGER,
    protocol TEXT DEFAULT 'tcp',
    success INTEGER DEFAULT 0,
    method TEXT,
    tested_at TEXT NOT NULL
);

-- Enterprise scanning support tables
CREATE TABLE IF NOT EXISTS scan_checkpoints (
    scan_id TEXT PRIMARY KEY,
    total_targets INTEGER NOT NULL,
    completed_targets INTEGER NOT NULL,
    current_batch_start INTEGER NOT NULL,
    started_at TEXT NOT NULL,
    last_checkpoint TEXT NOT NULL,
    state TEXT DEFAULT 'running'
);

CREATE TABLE IF NOT EXISTS service_fingerprints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    ports_hash TEXT NOT NULL,
    banner_hash TEXT,
    service_name TEXT,
    service_version TEXT,
    discovered_at TEXT NOT NULL,
    UNIQUE(target, ports_hash)
);

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
);

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
);

CREATE INDEX IF NOT EXISTS idx_scan_checkpoints_state ON scan_checkpoints(state);
CREATE INDEX IF NOT EXISTS idx_service_fingerprints_target ON service_fingerprints(target);
CREATE INDEX IF NOT EXISTS idx_service_fingerprints_ports ON service_fingerprints(ports_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_log_timestamp ON api_request_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_api_log_endpoint ON api_request_log(endpoint);

CREATE INDEX IF NOT EXISTS idx_alert_history_type ON alert_history(event_type, sent_at);
CREATE INDEX IF NOT EXISTS idx_ad_objects_domain ON ad_objects(domain);
CREATE INDEX IF NOT EXISTS idx_ad_objects_type ON ad_objects(domain, object_type);
CREATE INDEX IF NOT EXISTS idx_ml_feedback_anomaly ON ml_feedback(anomaly_id);
CREATE INDEX IF NOT EXISTS idx_ml_feedback_host ON ml_feedback(host_id);

CREATE TABLE IF NOT EXISTS custom_credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    label TEXT,
    added_at TEXT NOT NULL,
    UNIQUE(username, password)
);
"""


# ---------------------------------------------------------------------------
# Schema Migrations
# ---------------------------------------------------------------------------

MigrationFn = Callable[[sqlite3.Connection], None]


def _column_exists(conn: sqlite3.Connection, table: str, column: str) -> bool:
    """Return True if a column exists on a table."""
    # Use bracket-quoted identifier to prevent SQL injection via table names
    rows = conn.execute(f"PRAGMA table_info([{table}])").fetchall()
    return any(r[1] == column for r in rows)


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    """Return True if a table exists."""
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table,),
    ).fetchone()
    return row is not None


def _ensure_schema_migrations_table(conn: sqlite3.Connection) -> None:
    """Create the migration tracking table if needed."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version TEXT PRIMARY KEY,
            description TEXT NOT NULL,
            applied_at TEXT NOT NULL
        )
        """
    )


def _migration_0001_baseline(_conn: sqlite3.Connection) -> None:
    """Baseline marker migration.

    The main schema is still created via _DB_SCHEMA for backward compatibility.
    This migration anchors future incremental migrations.
    """
    return


def _migration_0002_tls_compat(conn: sqlite3.Connection) -> None:
    """Ensure TLS compatibility columns and backfills exist."""
    if not _table_exists(conn, "tls_certificates"):
        return

    for col_def in (
        "ip TEXT",
        "signature_algorithm TEXT",
        "key_size INTEGER",
        "key_bits INTEGER",
        "san_names TEXT",
        "san_domains TEXT",
        "cipher_bits INTEGER",
        "weaknesses TEXT",
        "fingerprint_sha256 TEXT",
        "cert_fingerprint_sha256 TEXT",
    ):
        col_name = col_def.split()[0]
        if not _column_exists(conn, "tls_certificates", col_name):
            conn.execute(f"ALTER TABLE tls_certificates ADD COLUMN {col_def}")

    if _column_exists(conn, "tls_certificates", "fingerprint_sha256") and _column_exists(
        conn, "tls_certificates", "cert_fingerprint_sha256"
    ):
        conn.execute(
            "UPDATE tls_certificates SET cert_fingerprint_sha256 = fingerprint_sha256 "
            "WHERE (cert_fingerprint_sha256 IS NULL OR cert_fingerprint_sha256 = '') "
            "AND fingerprint_sha256 IS NOT NULL AND fingerprint_sha256 != ''"
        )
        conn.execute(
            "UPDATE tls_certificates SET fingerprint_sha256 = cert_fingerprint_sha256 "
            "WHERE (fingerprint_sha256 IS NULL OR fingerprint_sha256 = '') "
            "AND cert_fingerprint_sha256 IS NOT NULL AND cert_fingerprint_sha256 != ''"
        )

    if _column_exists(conn, "tls_certificates", "key_bits") and _column_exists(conn, "tls_certificates", "key_size"):
        conn.execute(
            "UPDATE tls_certificates SET key_size = key_bits "
            "WHERE (key_size IS NULL OR key_size = 0) AND key_bits IS NOT NULL AND key_bits > 0"
        )
        conn.execute(
            "UPDATE tls_certificates SET key_bits = key_size "
            "WHERE (key_bits IS NULL OR key_bits = 0) AND key_size IS NOT NULL AND key_size > 0"
        )

    if _column_exists(conn, "tls_certificates", "san_domains") and _column_exists(
        conn, "tls_certificates", "san_names"
    ):
        conn.execute(
            "UPDATE tls_certificates SET san_names = san_domains "
            "WHERE (san_names IS NULL OR san_names = '') AND san_domains IS NOT NULL AND san_domains != ''"
        )
        conn.execute(
            "UPDATE tls_certificates SET san_domains = san_names "
            "WHERE (san_domains IS NULL OR san_domains = '') AND san_names IS NOT NULL AND san_names != ''"
        )


def _migration_0003_service_enum_compat(conn: sqlite3.Connection) -> None:
    """Ensure service_enumeration includes modern and legacy-compatible columns."""
    if not _table_exists(conn, "service_enumeration"):
        conn.execute(
            """
            CREATE TABLE service_enumeration (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER,
                ip TEXT,
                port INTEGER,
                service_type TEXT,
                finding_type TEXT,
                severity TEXT DEFAULT 'info',
                risk_level TEXT,
                title TEXT,
                details TEXT,
                findings TEXT,
                enum_data TEXT,
                discovered_at TEXT,
                enumerated_at TEXT,
                FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
            )
            """
        )

    for col_def in (
        "ip TEXT",
        "finding_type TEXT",
        "severity TEXT DEFAULT 'info'",
        "risk_level TEXT",
        "title TEXT",
        "details TEXT",
        "findings TEXT",
        "enum_data TEXT",
        "discovered_at TEXT",
        "enumerated_at TEXT",
    ):
        col_name = col_def.split()[0]
        if not _column_exists(conn, "service_enumeration", col_name):
            conn.execute(f"ALTER TABLE service_enumeration ADD COLUMN {col_def}")


def _migration_0004_credential_results_compat(conn: sqlite3.Connection) -> None:
    """Ensure credential_results canonical schema exists and backfill old names."""
    if not _table_exists(conn, "credential_results"):
        conn.execute(
            """
            CREATE TABLE credential_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER NOT NULL,
                port INTEGER,
                service TEXT,
                username TEXT,
                credential_hash TEXT,
                success INTEGER DEFAULT 0,
                tested_at TEXT NOT NULL,
                FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
            )
            """
        )

    for col_def in (
        "host_id INTEGER",
        "port INTEGER",
        "service TEXT",
        "username TEXT",
        "credential_hash TEXT",
        "success INTEGER DEFAULT 0",
        "tested_at TEXT",
    ):
        col_name = col_def.split()[0]
        if not _column_exists(conn, "credential_results", col_name):
            conn.execute(f"ALTER TABLE credential_results ADD COLUMN {col_def}")

    if _column_exists(conn, "credential_results", "password_hash") and _column_exists(
        conn, "credential_results", "credential_hash"
    ):
        conn.execute(
            "UPDATE credential_results SET credential_hash = password_hash "
            "WHERE (credential_hash IS NULL OR credential_hash = '') AND password_hash IS NOT NULL"
        )
    if _column_exists(conn, "credential_results", "attempted_at") and _column_exists(
        conn, "credential_results", "tested_at"
    ):
        conn.execute(
            "UPDATE credential_results SET tested_at = attempted_at "
            "WHERE (tested_at IS NULL OR tested_at = '') AND attempted_at IS NOT NULL"
        )


def _migration_0005_ports_service_version(conn: sqlite3.Connection) -> None:
    """Add nmap -sV service/version detection columns to the ports table.

    These enrich the existing ``service``/``banner`` columns with structured
    product, version, CPE, and extra-info fields parsed from ``nmap -sV`` XML.
    """
    if not _table_exists(conn, "ports"):
        return
    for col_def in (
        "product TEXT",
        "version TEXT",
        "cpe TEXT",
        "extra_info TEXT",
    ):
        col_name = col_def.split()[0]
        if not _column_exists(conn, "ports", col_name):
            conn.execute(f"ALTER TABLE ports ADD COLUMN {col_def}")


def _migration_0006_custom_credentials(conn: sqlite3.Connection) -> None:
    """Add custom_credentials table for user-managed credential pairs."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS custom_credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            label TEXT,
            added_at TEXT NOT NULL,
            UNIQUE(username, password)
        )
    """)


def _migration_0007_enterprise_features(conn: sqlite3.Connection) -> None:
    """Add priority_score, discovery_source to hosts; attack_chains table."""
    for col, col_def in (
        ("priority_score", "REAL DEFAULT 0.0"),
        ("discovery_source", "TEXT DEFAULT 'active'"),
    ):
        try:
            conn.execute(f"ALTER TABLE hosts ADD COLUMN {col} {col_def}")
        except sqlite3.OperationalError:
            pass

    conn.execute("""
        CREATE TABLE IF NOT EXISTS attack_chains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            chain_name TEXT NOT NULL,
            source_host_id INTEGER,
            target_host_id INTEGER,
            technique_chain TEXT,
            severity TEXT DEFAULT 'medium',
            confidence_score REAL DEFAULT 0.0,
            supporting_evidence TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (source_host_id) REFERENCES hosts(id) ON DELETE SET NULL,
            FOREIGN KEY (target_host_id) REFERENCES hosts(id) ON DELETE SET NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_attack_chains_severity ON attack_chains(severity)")


_MIGRATIONS: list[tuple[str, str, MigrationFn]] = [
    ("0001", "baseline schema marker", _migration_0001_baseline),
    ("0002", "tls compatibility columns/backfills", _migration_0002_tls_compat),
    ("0003", "service enumeration compatibility", _migration_0003_service_enum_compat),
    ("0004", "credential results compatibility", _migration_0004_credential_results_compat),
    ("0005", "ports service/version detection columns", _migration_0005_ports_service_version),
    ("0006", "custom credentials table", _migration_0006_custom_credentials),
    (
        "0007",
        "enterprise features (priority_score, discovery_source, attack_chains)",
        _migration_0007_enterprise_features,
    ),
]


def run_database_migrations(conn: sqlite3.Connection) -> list[str]:
    """Run pending database migrations in order.

    Returns a list of migration versions applied in this invocation.
    Each migration is committed individually so a failure in one migration
    does not roll back previously successful ones.
    """
    _ensure_schema_migrations_table(conn)
    conn.commit()  # Ensure the migrations table itself is committed
    applied_rows = conn.execute("SELECT version FROM schema_migrations").fetchall()
    applied = {r[0] for r in applied_rows}
    newly_applied: list[str] = []

    for version, description, migration_fn in _MIGRATIONS:
        if version in applied:
            continue

        try:
            migration_fn(conn)
            conn.execute(
                "INSERT INTO schema_migrations (version, description, applied_at) VALUES (?, ?, ?)",
                (version, description, now_iso()),
            )
            conn.commit()
            newly_applied.append(version)
        except Exception:
            conn.rollback()
            raise

    return newly_applied


def ensure_application_tables(conn: sqlite3.Connection) -> None:
    """Create feature tables used by dashboard, enrichment, alerting, and AD."""
    conn.executescript(_APP_FEATURE_SCHEMA)


def init_database(db_path: str | Path = "data/hostvigil.db") -> sqlite3.Connection:
    """Initialize the SQLite database with the HostVigil schema.

    Creates the database file and parent directories if they don't exist.
    Returns an open connection with WAL mode and foreign keys enabled.
    """
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(db_path), timeout=30)
    try:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=30000")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.executescript(_DB_SCHEMA)
        ensure_application_tables(conn)
        run_database_migrations(conn)
        conn.commit()
    except Exception:
        conn.close()
        raise

    return conn


_initialized_dbs: set[str] = set()
_initialized_dbs_lock = threading.Lock()


def get_db_connection(db_path: str | Path = "data/hostvigil.db") -> sqlite3.Connection:
    """Get a database connection with row factory enabled."""
    db_path = Path(db_path)
    if not db_path.exists():
        return init_database(db_path)

    conn = sqlite3.connect(str(db_path), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")

    db_key = str(db_path.resolve())
    with _initialized_dbs_lock:
        if db_key not in _initialized_dbs:
            ensure_application_tables(conn)
            run_database_migrations(conn)
            _initialized_dbs.add(db_key)

    return conn


def dict_from_row(row: Any) -> dict[str, Any]:
    """Convert a sqlite3.Row to a dictionary."""
    if row is None:
        return {}
    return dict(row)
