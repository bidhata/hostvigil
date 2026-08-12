"""
HostVigil Export/Import Module

Handles exporting all findings to JSON/CSV and importing previous scan data back in.
Supports merge and replace modes for flexible data management.
"""

import csv
import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("hostvigil.export_import")

VERSION = "1.0.0"
PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _get_default_output_dir() -> Path:
    """Get the default output directory for exports."""
    output_dir = PROJECT_ROOT / "data" / "reports"
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


def _timestamp_filename(prefix: str, ext: str) -> str:
    """Generate a timestamped filename."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return f"{prefix}_{ts}.{ext}"


def _table_exists(conn: sqlite3.Connection, table_name: str) -> bool:
    """Check if a table exists in the database."""
    cursor = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    )
    return cursor.fetchone() is not None


def cleanup_old_reports(max_age_days: int = 14, max_total_mb: int = 500) -> Dict:
    """Remove old generated report/export files from the default reports dir."""
    import time

    report_dir = _get_default_output_dir()
    cutoff = time.time() - (max_age_days * 86400)
    files = [p for p in report_dir.iterdir() if p.is_file() and p.name != ".gitkeep"]
    deleted = []

    for path in files:
        if path.stat().st_mtime < cutoff:
            size = path.stat().st_size
            path.unlink(missing_ok=True)
            deleted.append({"path": str(path), "size_bytes": size, "reason": "age"})

    remaining = [p for p in report_dir.iterdir() if p.is_file() and p.name != ".gitkeep"]
    total_size = sum(p.stat().st_size for p in remaining)
    max_bytes = max_total_mb * 1024 * 1024

    for path in sorted(remaining, key=lambda p: p.stat().st_mtime):
        if total_size <= max_bytes:
            break
        size = path.stat().st_size
        path.unlink(missing_ok=True)
        total_size -= size
        deleted.append({"path": str(path), "size_bytes": size, "reason": "size"})

    return {
        "reports_dir": str(report_dir),
        "deleted_count": len(deleted),
        "deleted": deleted,
        "remaining_count": len([p for p in report_dir.iterdir() if p.is_file() and p.name != ".gitkeep"]),
        "max_age_days": max_age_days,
        "max_total_mb": max_total_mb,
    }


class DataExporter:
    """Export HostVigil findings to JSON, CSV, or Markdown report."""

    def __init__(self, db_path: str):
        self.db_path = db_path

    def _connect(self) -> sqlite3.Connection:
        """Create a database connection with row factory."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _fetch_hosts(self, conn: sqlite3.Connection) -> List[Dict]:
        """Fetch all hosts from the database."""
        if not _table_exists(conn, "hosts"):
            return []
        cursor = conn.execute(
            "SELECT ip, mac, hostname, os_fingerprint, first_seen, last_seen, discovery_method FROM hosts"
        )
        return [dict(row) for row in cursor.fetchall()]

    def _fetch_ports(self, conn: sqlite3.Connection) -> List[Dict]:
        """Fetch all ports with host IP."""
        if not _table_exists(conn, "ports") or not _table_exists(conn, "hosts"):
            return []
        cursor = conn.execute("""
            SELECT h.ip AS host_ip, p.port, p.protocol, p.state, p.service, p.banner,
                   p.first_seen, p.last_seen
            FROM ports p
            JOIN hosts h ON h.id = p.host_id
        """)
        return [dict(row) for row in cursor.fetchall()]

    def _fetch_vulnerabilities(self, conn: sqlite3.Connection) -> List[Dict]:
        """Fetch all vulnerabilities with host IP and port."""
        if not _table_exists(conn, "vulnerabilities") or not _table_exists(conn, "hosts"):
            return []
        cursor = conn.execute("""
            SELECT h.ip AS host_ip, p.port, v.template_id, v.name, v.severity,
                   v.description, v.evidence, v.matched_at
            FROM vulnerabilities v
            JOIN hosts h ON h.id = v.host_id
            LEFT JOIN ports p ON p.id = v.port_id
        """)
        return [dict(row) for row in cursor.fetchall()]

    def _fetch_anomalies(self, conn: sqlite3.Connection) -> List[Dict]:
        """Fetch all anomalies with host IP."""
        if not _table_exists(conn, "anomalies") or not _table_exists(conn, "hosts"):
            return []
        cursor = conn.execute("""
            SELECT h.ip AS host_ip, a.anomaly_type, a.score, a.description,
                   a.detected_at, a.is_reviewed
            FROM anomalies a
            JOIN hosts h ON h.id = a.host_id
        """)
        return [dict(row) for row in cursor.fetchall()]

    def _fetch_tls_certs(self, conn: sqlite3.Connection) -> List[Dict]:
        """Fetch TLS certificates if table exists."""
        if not _table_exists(conn, "tls_certificates") or not _table_exists(conn, "hosts"):
            return []
        cursor = conn.execute("""
            SELECT h.ip AS host_ip, t.port, t.subject, t.issuer, t.not_before,
                   t.not_after, t.serial_number, t.fingerprint_sha256,
                   t.key_type, t.key_bits, t.san_domains
            FROM tls_certificates t
            JOIN hosts h ON h.id = t.host_id
        """)
        return [dict(row) for row in cursor.fetchall()]

    def _fetch_service_enum(self, conn: sqlite3.Connection) -> List[Dict]:
        """Fetch service enumeration findings if table exists."""
        if not _table_exists(conn, "service_enumeration") or not _table_exists(conn, "hosts"):
            return []
        cursor = conn.execute("""
            SELECT h.ip AS host_ip, s.port, s.service_type, s.finding_type,
                   s.severity, s.title, s.details, s.discovered_at
            FROM service_enumeration s
            JOIN hosts h ON h.id = s.host_id
        """)
        return [dict(row) for row in cursor.fetchall()]

    def export_json(self, output_path: str = None) -> str:
        """Export all findings to a single JSON file. Returns filepath."""
        conn = self._connect()
        try:
            hosts = self._fetch_hosts(conn)
            ports = self._fetch_ports(conn)
            vulns = self._fetch_vulnerabilities(conn)
            anomalies = self._fetch_anomalies(conn)
            tls_certs = self._fetch_tls_certs(conn)
            service_enum = self._fetch_service_enum(conn)
        finally:
            conn.close()

        export_data = {
            "hostvigil_export": {
                "version": VERSION,
                "exported_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "summary": {
                    "total_hosts": len(hosts),
                    "total_ports": len(ports),
                    "total_vulnerabilities": len(vulns),
                    "total_anomalies": len(anomalies),
                },
                "hosts": hosts,
                "ports": ports,
                "vulnerabilities": vulns,
                "anomalies": anomalies,
            }
        }

        # Include optional tables if data exists
        if tls_certs:
            export_data["hostvigil_export"]["tls_certificates"] = tls_certs
            export_data["hostvigil_export"]["summary"]["total_tls_certificates"] = len(tls_certs)
        if service_enum:
            export_data["hostvigil_export"]["service_enumeration"] = service_enum
            export_data["hostvigil_export"]["summary"]["total_service_findings"] = len(service_enum)

        if output_path is None:
            output_path = str(_get_default_output_dir() / _timestamp_filename("hostvigil_export", "json"))

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2, default=str)

        logger.info(
            "Exported JSON to %s (%d hosts, %d ports, %d vulns, %d anomalies)",
            output_path,
            len(hosts),
            len(ports),
            len(vulns),
            len(anomalies),
        )
        return output_path

    def export_csv(self, output_dir: str = None) -> List[str]:
        """Export to multiple CSV files (one per table). Returns list of filepaths."""
        if output_dir is None:
            output_dir = str(_get_default_output_dir())

        Path(output_dir).mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        paths = []
        paths.append(self.export_hosts_csv(str(Path(output_dir) / f"hosts_{ts}.csv")))
        paths.append(self.export_ports_csv(str(Path(output_dir) / f"ports_{ts}.csv")))
        paths.append(self.export_vulns_csv(str(Path(output_dir) / f"vulnerabilities_{ts}.csv")))
        paths.append(self.export_anomalies_csv(str(Path(output_dir) / f"anomalies_{ts}.csv")))

        # Optional tables
        conn = self._connect()
        try:
            if _table_exists(conn, "tls_certificates"):
                tls_path = str(Path(output_dir) / f"tls_certificates_{ts}.csv")
                paths.append(self._export_table_csv(conn, "tls_certificates", tls_path))
            if _table_exists(conn, "service_enumeration"):
                svc_path = str(Path(output_dir) / f"service_enumeration_{ts}.csv")
                paths.append(self._export_table_csv(conn, "service_enumeration", svc_path))
        finally:
            conn.close()

        logger.info("Exported %d CSV files to %s", len(paths), output_dir)
        return paths

    def _export_table_csv(self, conn: sqlite3.Connection, table: str, output_path: str) -> str:
        """Generic CSV export for optional tables with host IP join."""
        if table == "tls_certificates":
            rows = self._fetch_tls_certs(conn)
        elif table == "service_enumeration":
            rows = self._fetch_service_enum(conn)
        else:
            return output_path

        if not rows:
            # Write empty CSV with header placeholder
            with open(output_path, "w", newline="", encoding="utf-8") as f:
                f.write("")
            return output_path

        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)

        return output_path

    def export_hosts_csv(self, output_path: str) -> str:
        """Export hosts table to CSV."""
        conn = self._connect()
        try:
            hosts = self._fetch_hosts(conn)
        finally:
            conn.close()

        fieldnames = ["ip", "mac", "hostname", "os_fingerprint", "first_seen", "last_seen", "discovery_method"]

        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for host in hosts:
                writer.writerow({k: host.get(k, "") for k in fieldnames})

        return output_path

    def export_ports_csv(self, output_path: str) -> str:
        """Export ports table to CSV."""
        conn = self._connect()
        try:
            ports = self._fetch_ports(conn)
        finally:
            conn.close()

        fieldnames = ["host_ip", "port", "protocol", "state", "service", "banner", "first_seen", "last_seen"]

        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for port in ports:
                writer.writerow({k: port.get(k, "") for k in fieldnames})

        return output_path

    def export_vulns_csv(self, output_path: str) -> str:
        """Export vulnerabilities to CSV."""
        conn = self._connect()
        try:
            vulns = self._fetch_vulnerabilities(conn)
        finally:
            conn.close()

        fieldnames = ["host_ip", "port", "template_id", "name", "severity", "description", "evidence", "matched_at"]

        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for vuln in vulns:
                writer.writerow({k: vuln.get(k, "") for k in fieldnames})

        return output_path

    def export_anomalies_csv(self, output_path: str) -> str:
        """Export anomalies to CSV."""
        conn = self._connect()
        try:
            anomalies = self._fetch_anomalies(conn)
        finally:
            conn.close()

        fieldnames = ["host_ip", "anomaly_type", "score", "description", "detected_at", "is_reviewed"]

        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for anomaly in anomalies:
                writer.writerow({k: anomaly.get(k, "") for k in fieldnames})

        return output_path

    def generate_report(self, output_path: str = None) -> str:
        """Generate a markdown summary report."""
        conn = self._connect()
        try:
            hosts = self._fetch_hosts(conn)
            ports = self._fetch_ports(conn)
            vulns = self._fetch_vulnerabilities(conn)
            anomalies = self._fetch_anomalies(conn)
        finally:
            conn.close()

        if output_path is None:
            output_path = str(_get_default_output_dir() / _timestamp_filename("hostvigil_report", "md"))

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)

        # Severity breakdown
        severity_counts = {}
        for v in vulns:
            sev = (v.get("severity") or "unknown").lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Top hosts by open ports
        host_port_counts: Dict[str, int] = {}
        for p in ports:
            ip = p.get("host_ip", "unknown")
            host_port_counts[ip] = host_port_counts.get(ip, 0) + 1
        top_hosts = sorted(host_port_counts.items(), key=lambda x: x[1], reverse=True)[:10]

        # Build report
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        lines = [
            "# HostVigil Assessment Report",
            "",
            f"**Generated:** {now}",
            "",
            "---",
            "",
            "## Summary",
            "",
            "| Metric | Count |",
            "|--------|-------|",
            f"| Hosts Discovered | {len(hosts)} |",
            f"| Open Ports | {len(ports)} |",
            f"| Vulnerabilities | {len(vulns)} |",
            f"| Anomalies | {len(anomalies)} |",
            "",
            "## Vulnerability Breakdown",
            "",
            "| Severity | Count |",
            "|----------|-------|",
        ]

        for sev in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(sev, 0)
            if count > 0:
                lines.append(f"| {sev.capitalize()} | {count} |")

        if not severity_counts:
            lines.append("| (none) | 0 |")

        lines.extend(
            [
                "",
                "## Top Hosts by Open Ports",
                "",
                "| Host | Open Ports |",
                "|------|-----------|",
            ]
        )

        for ip, count in top_hosts:
            hostname = ""
            for h in hosts:
                if h.get("ip") == ip:
                    hostname = h.get("hostname") or ""
                    break
            label = f"{ip} ({hostname})" if hostname else ip
            lines.append(f"| {label} | {count} |")

        if not top_hosts:
            lines.append("| (none) | 0 |")

        # Critical/High vulns detail
        critical_high = [v for v in vulns if (v.get("severity") or "").lower() in ("critical", "high")]
        if critical_high:
            lines.extend(
                [
                    "",
                    "## Critical & High Vulnerabilities",
                    "",
                ]
            )
            for v in critical_high[:20]:
                lines.append(
                    f"- **{v.get('name', 'Unknown')}** ({v.get('severity', '?')}) — "
                    f"{v.get('host_ip', '?')}:{v.get('port', '?')} "
                    f"[{v.get('template_id', '')}]"
                )

        # Anomalies summary
        unreviewed = [a for a in anomalies if not a.get("is_reviewed")]
        if unreviewed:
            lines.extend(
                [
                    "",
                    "## Unreviewed Anomalies",
                    "",
                ]
            )
            for a in unreviewed[:15]:
                lines.append(
                    f"- **{a.get('anomaly_type', 'Unknown')}** (score: {a.get('score', 0):.2f}) — "
                    f"{a.get('host_ip', '?')}: {a.get('description', '')}"
                )

        lines.extend(["", "---", "", "*Report generated by HostVigil*", ""])

        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        logger.info("Generated report at %s", output_path)
        return output_path


class DataImporter:
    """Import HostVigil findings from JSON or CSV exports."""

    def __init__(self, db_path: str):
        self.db_path = db_path

    def _connect(self) -> sqlite3.Connection:
        """Create a database connection."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _validate_json(self, data: dict) -> bool:
        """Validate JSON structure before import."""
        if "hostvigil_export" not in data:
            logger.error("Missing 'hostvigil_export' root key")
            return False

        export = data["hostvigil_export"]
        required_keys = ["version", "hosts", "ports", "vulnerabilities", "anomalies"]
        for key in required_keys:
            if key not in export:
                logger.error("Missing required key: %s", key)
                return False

        if not isinstance(export["hosts"], list):
            logger.error("'hosts' must be a list")
            return False
        if not isinstance(export["ports"], list):
            logger.error("'ports' must be a list")
            return False
        if not isinstance(export["vulnerabilities"], list):
            logger.error("'vulnerabilities' must be a list")
            return False
        if not isinstance(export["anomalies"], list):
            logger.error("'anomalies' must be a list")
            return False

        return True

    def _ensure_tables(self, conn: sqlite3.Connection):
        """Ensure required tables exist (create if missing)."""
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL UNIQUE,
                mac TEXT,
                hostname TEXT,
                os_fingerprint TEXT,
                first_seen TEXT,
                last_seen TEXT,
                discovery_method TEXT,
                is_active INTEGER DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT DEFAULT 'tcp',
                state TEXT DEFAULT 'open',
                service TEXT,
                banner TEXT,
                first_seen TEXT,
                last_seen TEXT,
                is_active INTEGER DEFAULT 1,
                FOREIGN KEY (host_id) REFERENCES hosts(id),
                UNIQUE(host_id, port, protocol)
            );
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER NOT NULL,
                port_id INTEGER,
                template_id TEXT,
                name TEXT,
                severity TEXT,
                description TEXT,
                evidence TEXT,
                matched_at TEXT,
                is_verified INTEGER DEFAULT 0,
                FOREIGN KEY (host_id) REFERENCES hosts(id),
                FOREIGN KEY (port_id) REFERENCES ports(id)
            );
            CREATE TABLE IF NOT EXISTS anomalies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER NOT NULL,
                anomaly_type TEXT,
                score REAL,
                description TEXT,
                detected_at TEXT,
                is_reviewed INTEGER DEFAULT 0,
                FOREIGN KEY (host_id) REFERENCES hosts(id)
            );
        """)

    def _get_or_create_host(self, conn: sqlite3.Connection, ip: str) -> Optional[int]:
        """Get host_id by IP, or return None if not found."""
        cursor = conn.execute("SELECT id FROM hosts WHERE ip = ?", (ip,))
        row = cursor.fetchone()
        return row[0] if row else None

    def _merge_host(self, conn: sqlite3.Connection, host_data: dict) -> int:
        """Merge a single host record. Returns host_id."""
        ip = host_data.get("ip", "")
        if not ip:
            raise ValueError("Host record missing 'ip' field")

        existing_id = self._get_or_create_host(conn, ip)

        if existing_id is not None:
            # Update existing: only update fields that are non-empty in import
            updates = []
            params = []
            # Whitelist of allowed column names to prevent SQL injection
            allowed_host_fields = {"mac", "hostname", "os_fingerprint", "discovery_method", "last_seen"}
            for field in ["mac", "hostname", "os_fingerprint", "discovery_method"]:
                val = host_data.get(field)
                if val and field in allowed_host_fields:
                    updates.append("{} = ?".format(field))
                    params.append(val)

            # Always update last_seen if provided
            last_seen = host_data.get("last_seen")
            if last_seen:
                updates.append("last_seen = ?")
                params.append(last_seen)

            if updates:
                params.append(existing_id)
                conn.execute("UPDATE hosts SET {} WHERE id = ?".format(", ".join(updates)), params)

            return existing_id
        else:
            # Insert new host
            cursor = conn.execute(
                "INSERT INTO hosts (ip, mac, hostname, os_fingerprint, first_seen, last_seen, discovery_method, is_active) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, 1)",
                (
                    ip,
                    host_data.get("mac", ""),
                    host_data.get("hostname", ""),
                    host_data.get("os_fingerprint", ""),
                    host_data.get("first_seen", datetime.now(timezone.utc).isoformat()),
                    host_data.get("last_seen", datetime.now(timezone.utc).isoformat()),
                    host_data.get("discovery_method", "import"),
                ),
            )
            return cursor.lastrowid

    def _merge_port(self, conn: sqlite3.Connection, host_id: int, port_data: dict):
        """Merge a single port record."""
        port_num = port_data.get("port")
        protocol = port_data.get("protocol", "tcp")

        if port_num is None:
            return

        # Check if port already exists for this host
        cursor = conn.execute(
            "SELECT id FROM ports WHERE host_id = ? AND port = ? AND protocol = ?",
            (host_id, int(port_num), protocol),
        )
        row = cursor.fetchone()

        if row is not None:
            # Update existing port
            port_id = row[0]
            updates = []
            params = []
            # Whitelist of allowed column names to prevent SQL injection
            allowed_port_fields = {"state", "service", "banner", "last_seen"}
            for field in ["state", "service", "banner"]:
                val = port_data.get(field)
                if val and field in allowed_port_fields:
                    updates.append("{} = ?".format(field))
                    params.append(val)

            last_seen = port_data.get("last_seen")
            if last_seen:
                updates.append("last_seen = ?")
                params.append(last_seen)

            if updates:
                params.append(port_id)
                conn.execute("UPDATE ports SET {} WHERE id = ?".format(", ".join(updates)), params)
        else:
            # Insert new port
            conn.execute(
                "INSERT INTO ports (host_id, port, protocol, state, service, banner, first_seen, last_seen, is_active) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)",
                (
                    host_id,
                    int(port_num),
                    protocol,
                    port_data.get("state", "open"),
                    port_data.get("service", ""),
                    port_data.get("banner", ""),
                    port_data.get("first_seen", datetime.now(timezone.utc).isoformat()),
                    port_data.get("last_seen", datetime.now(timezone.utc).isoformat()),
                ),
            )

    def _get_port_id(self, conn: sqlite3.Connection, host_id: int, port_num, protocol: str = "tcp") -> Optional[int]:
        """Get port_id by host_id, port number, and protocol."""
        if port_num is None:
            return None
        cursor = conn.execute(
            "SELECT id FROM ports WHERE host_id = ? AND port = ? AND protocol = ?",
            (host_id, int(port_num), protocol),
        )
        row = cursor.fetchone()
        return row[0] if row else None

    def _wipe_tables(self, conn: sqlite3.Connection):
        """Wipe all data tables for replace mode."""
        # Whitelist of allowed tables to prevent SQL injection
        allowed_tables = ["anomalies", "vulnerabilities", "ports", "hosts"]
        for table in allowed_tables:
            if _table_exists(conn, table):
                conn.execute("DELETE FROM {}".format(table))

    def import_json(self, input_path: str, mode: str = "merge") -> Dict:
        """Import from JSON export. mode: 'merge' or 'replace'. Returns stats."""
        with open(input_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if not self._validate_json(data):
            return {"error": "Invalid JSON structure", "imported": False}

        export = data["hostvigil_export"]
        stats = {"hosts_imported": 0, "ports_imported": 0, "vulns_imported": 0, "anomalies_imported": 0}

        conn = self._connect()
        try:
            self._ensure_tables(conn)

            if mode == "replace":
                self._wipe_tables(conn)

            # Import hosts
            host_id_map: Dict[str, int] = {}  # ip -> host_id
            for host_data in export.get("hosts", []):
                ip = host_data.get("ip", "")
                if not ip:
                    continue
                host_id = self._merge_host(conn, host_data)
                host_id_map[ip] = host_id
                stats["hosts_imported"] += 1

            # Import ports
            for port_data in export.get("ports", []):
                host_ip = port_data.get("host_ip", "")
                host_id = host_id_map.get(host_ip)
                if host_id is None:
                    host_id = self._get_or_create_host(conn, host_ip)
                if host_id is None:
                    # Auto-create host if not found
                    host_id = self._merge_host(conn, {"ip": host_ip})
                    host_id_map[host_ip] = host_id
                self._merge_port(conn, host_id, port_data)
                stats["ports_imported"] += 1

            # Import vulnerabilities
            for vuln_data in export.get("vulnerabilities", []):
                host_ip = vuln_data.get("host_ip", "")
                host_id = host_id_map.get(host_ip)
                if host_id is None:
                    host_id = self._get_or_create_host(conn, host_ip)
                if host_id is None:
                    continue

                port_num = vuln_data.get("port")
                port_id = self._get_port_id(conn, host_id, port_num) if port_num else None

                # Check for existing vulnerability
                existing = conn.execute(
                    "SELECT id FROM vulnerabilities WHERE host_id=? AND template_id=? AND matched_at=?",
                    (host_id, vuln_data.get("template_id", ""), vuln_data.get("matched_at", "")),
                ).fetchone()
                if existing:
                    stats["vulns_skipped"] = stats.get("vulns_skipped", 0) + 1
                    continue

                conn.execute(
                    "INSERT INTO vulnerabilities (host_id, port_id, template_id, name, severity, description, evidence, matched_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        host_id,
                        port_id,
                        vuln_data.get("template_id", ""),
                        vuln_data.get("name", ""),
                        vuln_data.get("severity", ""),
                        vuln_data.get("description", ""),
                        vuln_data.get("evidence", ""),
                        vuln_data.get("matched_at", ""),
                    ),
                )
                stats["vulns_imported"] += 1

            # Import anomalies
            for anomaly_data in export.get("anomalies", []):
                host_ip = anomaly_data.get("host_ip", "")
                host_id = host_id_map.get(host_ip)
                if host_id is None:
                    host_id = self._get_or_create_host(conn, host_ip)
                if host_id is None:
                    continue

                # Check for existing anomaly
                existing = conn.execute(
                    "SELECT id FROM anomalies WHERE host_id=? AND anomaly_type=? AND detected_at=?",
                    (host_id, anomaly_data.get("anomaly_type", ""), anomaly_data.get("detected_at", "")),
                ).fetchone()
                if existing:
                    stats["anomalies_skipped"] = stats.get("anomalies_skipped", 0) + 1
                    continue

                conn.execute(
                    "INSERT INTO anomalies (host_id, anomaly_type, score, description, detected_at, is_reviewed) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        host_id,
                        anomaly_data.get("anomaly_type", ""),
                        float(anomaly_data.get("score", 0)),
                        anomaly_data.get("description", ""),
                        anomaly_data.get("detected_at", ""),
                        int(anomaly_data.get("is_reviewed", 0)),
                    ),
                )
                stats["anomalies_imported"] += 1

            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error("Import failed: %s", e)
            return {"error": str(e), "imported": False}
        finally:
            conn.close()

        stats["imported"] = True
        stats["mode"] = mode
        logger.info("JSON import complete (%s mode): %s", mode, stats)
        return stats

    def import_hosts_csv(self, input_path: str, mode: str = "merge") -> Dict:
        """Import hosts from CSV."""
        stats = {"hosts_imported": 0, "hosts_skipped": 0}

        conn = self._connect()
        try:
            self._ensure_tables(conn)

            if mode == "replace":
                self._wipe_tables(conn)

            with open(input_path, "r", newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    ip = row.get("ip", "").strip()
                    if not ip:
                        stats["hosts_skipped"] += 1
                        continue
                    self._merge_host(conn, row)
                    stats["hosts_imported"] += 1

            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error("CSV host import failed: %s", e)
            return {"error": str(e), "imported": False}
        finally:
            conn.close()

        stats["imported"] = True
        stats["mode"] = mode
        logger.info("Hosts CSV import complete: %s", stats)
        return stats

    def import_ports_csv(self, input_path: str, mode: str = "merge") -> Dict:
        """Import ports from CSV."""
        stats = {"ports_imported": 0, "ports_skipped": 0}

        conn = self._connect()
        try:
            self._ensure_tables(conn)

            if mode == "replace":
                for table in ["vulnerabilities", "ports"]:
                    if _table_exists(conn, table):
                        conn.execute("DELETE FROM {}".format(table))

            with open(input_path, "r", newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    host_ip = row.get("host_ip", "").strip()
                    port_num = row.get("port", "").strip()
                    if not host_ip or not port_num:
                        stats["ports_skipped"] += 1
                        continue

                    host_id = self._get_or_create_host(conn, host_ip)
                    if host_id is None:
                        host_id = self._merge_host(conn, {"ip": host_ip})

                    row["port"] = int(port_num)
                    self._merge_port(conn, host_id, row)
                    stats["ports_imported"] += 1

            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error("CSV port import failed: %s", e)
            return {"error": str(e), "imported": False}
        finally:
            conn.close()

        stats["imported"] = True
        stats["mode"] = mode
        logger.info("Ports CSV import complete: %s", stats)
        return stats

    def import_vulns_csv(self, input_path: str, mode: str = "merge") -> Dict:
        """Import vulnerabilities from CSV."""
        stats = {"vulns_imported": 0, "vulns_skipped": 0}

        conn = self._connect()
        try:
            self._ensure_tables(conn)

            if mode == "replace":
                if _table_exists(conn, "vulnerabilities"):
                    conn.execute("DELETE FROM vulnerabilities")

            with open(input_path, "r", newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    host_ip = row.get("host_ip", "").strip()
                    if not host_ip:
                        stats["vulns_skipped"] += 1
                        continue

                    host_id = self._get_or_create_host(conn, host_ip)
                    if host_id is None:
                        host_id = self._merge_host(conn, {"ip": host_ip})

                    port_num = row.get("port", "").strip()
                    port_id = None
                    if port_num:
                        try:
                            port_id = self._get_port_id(conn, host_id, int(port_num))
                        except (ValueError, TypeError):
                            pass

                    conn.execute(
                        "INSERT INTO vulnerabilities (host_id, port_id, template_id, name, severity, description, evidence, matched_at) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            host_id,
                            port_id,
                            row.get("template_id", ""),
                            row.get("name", ""),
                            row.get("severity", ""),
                            row.get("description", ""),
                            row.get("evidence", ""),
                            row.get("matched_at", ""),
                        ),
                    )
                    stats["vulns_imported"] += 1

            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error("CSV vuln import failed: %s", e)
            return {"error": str(e), "imported": False}
        finally:
            conn.close()

        stats["imported"] = True
        stats["mode"] = mode
        logger.info("Vulns CSV import complete: %s", stats)
        return stats
