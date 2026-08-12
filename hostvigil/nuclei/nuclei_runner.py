"""
Nuclei Runner - Automated vulnerability scanning with stealth considerations.

Provides:
- Target generation from scan results (HTTP/HTTPS ports → URLs, others → host:port)
- Rate-limited, low-concurrency nuclei execution
- JSONL result parsing into structured vulnerability records
- Severity classification for red team prioritization
- Template filtering by severity, type, or custom paths
"""

import json
import logging
import os
import sqlite3
import subprocess
import tempfile
from typing import Dict, List, Optional

logger = logging.getLogger("hostvigil.nuclei")

# Ports that typically serve HTTP/HTTPS
HTTP_PORTS = {80, 8080, 8000, 8888, 3000, 5000, 9090, 9000}
HTTPS_PORTS = {443, 8443, 4443, 9443}
ALL_WEB_PORTS = HTTP_PORTS | HTTPS_PORTS | {4443, 9443}

# Severity levels ordered by criticality
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# Template IDs / tags that indicate exploit-ready findings
EXPLOIT_READY_TAGS = {
    "rce",
    "sqli",
    "ssti",
    "ssrf",
    "lfi",
    "rfi",
    "command-injection",
    "deserialization",
    "upload",
    "auth-bypass",
    "default-login",
    "unauth",
}

# Tags indicating informational findings only
INFORMATIONAL_TAGS = {
    "tech",
    "detection",
    "fingerprint",
    "version",
    "headers",
    "robots",
    "sitemap",
}


class NucleiRunner:
    """Orchestrates Nuclei vulnerability scans with stealth and red team focus."""

    def __init__(self, config: dict, db_path: str):
        """Initialize NucleiRunner.

        Args:
            config: Nuclei configuration dict with keys like binary_path,
                    rate_limit, concurrency, severity_filter, timeout, etc.
            db_path: Path to the SQLite database file.
        """
        self.config = config
        self.db_path = db_path
        self.binary = config.get("binary_path", "nuclei")
        self.rate_limit = config.get("rate_limit", 10)
        self.concurrency = config.get("concurrency", 2)
        self.bulk_size = config.get("bulk_size", 5)
        self.severity_filter = config.get("severity_filter", ["critical", "high", "medium"])
        self.timeout = config.get("timeout", 15)
        self.update_templates_enabled = config.get("update_templates", True)
        # Accept both the documented singular key and the legacy plural list
        self.template_paths = config.get("template_paths", []) or config.get("templates_path", "")
        if isinstance(self.template_paths, str):
            self.template_paths = [self.template_paths] if self.template_paths else []
        self.exclude_tags = config.get("exclude_tags", [])
        self.max_host_errors = config.get("max_host_errors", 3)
        self.retries = config.get("retries", 1)

        import shutil as _shutil

        # Resolve the binary once so PATH changes mid-daemon don't break scans
        resolved = _shutil.which(self.binary)
        if resolved:
            self.binary = resolved
            logger.info("Nuclei binary resolved to %s", resolved)
        elif os.path.isabs(self.binary) and os.path.exists(self.binary):
            logger.info("Nuclei binary found at %s", self.binary)
        else:
            logger.warning("Nuclei binary '%s' not found in PATH — vulnerability scanning unavailable", self.binary)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run_scan(self, targets: List[str] = None) -> List[Dict]:
        """Execute nuclei scan on targets (or auto-generate from DB).

        Automatically updates nuclei templates before scanning if updates
        are available.

        Args:
            targets: Optional list of targets. If None, auto-generates from DB.

        Returns:
            List of parsed vulnerability dictionaries.
        """
        if not self.is_nuclei_available():
            logger.error("Nuclei binary not found at: %s", self.binary)
            return []

        # Update templates before scanning (stealth: can be disabled via config)
        if self.update_templates_enabled:
            self.update_templates()
        else:
            logger.debug("Template auto-update disabled via config")

        if targets is not None:
            target_file = self._write_target_file(targets)
            target_count = len(targets)
        else:
            target_file = self._generate_targets()
            if not target_file or not os.path.exists(target_file):
                logger.warning("No targets available for nuclei scan")
                return []
            target_count = self._count_targets_in_file(target_file)

        try:
            command = self._build_command(target_file)
            output = self._execute(command, target_count=target_count)
            findings = self._parse_results(output)
            for vuln in findings:
                self._store_vulnerability(vuln)
            logger.info("Nuclei scan complete: %d findings", len(findings))
            return findings
        except Exception as e:
            logger.error("Nuclei scan failed: %s", str(e))
            return []
        finally:
            if target_file and os.path.exists(target_file):
                try:
                    os.unlink(target_file)
                except OSError:
                    pass

    def get_findings_summary(self) -> Dict:
        """Return summary of all findings grouped by severity.

        Returns:
            Dict with severity counts, total, and top templates.
        """
        conn = self._get_connection()
        try:
            cursor = conn.cursor()

            # Count by severity
            cursor.execute("""
                SELECT severity, COUNT(*) as count
                FROM vulnerabilities
                GROUP BY severity
                ORDER BY CASE severity
                    WHEN 'critical' THEN 0
                    WHEN 'high' THEN 1
                    WHEN 'medium' THEN 2
                    WHEN 'low' THEN 3
                    WHEN 'info' THEN 4
                END
            """)
            severity_counts = {row[0]: row[1] for row in cursor.fetchall()}

            # Total count
            cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
            total = cursor.fetchone()[0]

            # Top 10 templates
            cursor.execute("""
                SELECT template_id, name, severity, COUNT(*) as hits
                FROM vulnerabilities
                WHERE template_id IS NOT NULL
                GROUP BY template_id
                ORDER BY hits DESC
                LIMIT 10
            """)
            top_templates = [
                {
                    "template_id": row[0],
                    "name": row[1],
                    "severity": row[2],
                    "hits": row[3],
                }
                for row in cursor.fetchall()
            ]

            # Unique affected hosts
            cursor.execute("SELECT COUNT(DISTINCT host_id) FROM vulnerabilities")
            unique_hosts = cursor.fetchone()[0]

            return {
                "total": total,
                "by_severity": severity_counts,
                "unique_hosts_affected": unique_hosts,
                "top_templates": top_templates,
            }
        except Exception:
            return {"total": 0, "by_severity": {}, "unique_hosts_affected": 0, "top_templates": []}

    def get_exploitable_targets(self) -> List[Dict]:
        """Return targets classified as ready for exploitation.

        Queries vulnerabilities that have redteam_classification = exploit_ready
        (stored in the description field as a tag prefix).

        Returns:
            List of dicts with host, port, vulnerability, and evidence info.
        """
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT v.id, v.name, v.severity, v.template_id, v.matched_at,
                       v.evidence, v.description, h.ip, h.hostname,
                       p.port, p.protocol, p.service
                FROM vulnerabilities v
                JOIN hosts h ON v.host_id = h.id
                LEFT JOIN ports p ON v.port_id = p.id
                WHERE v.description LIKE '%[redteam:exploit_ready]%'
                ORDER BY CASE v.severity
                    WHEN 'critical' THEN 0
                    WHEN 'high' THEN 1
                    WHEN 'medium' THEN 2
                    WHEN 'low' THEN 3
                    ELSE 4
                END
            """)
            results = []
            for row in cursor.fetchall():
                results.append(
                    {
                        "vuln_id": row[0],
                        "name": row[1],
                        "severity": row[2],
                        "template_id": row[3],
                        "matched_at": row[4],
                        "evidence": row[5],
                        "description": row[6],
                        "host_ip": row[7],
                        "hostname": row[8],
                        "port": row[9],
                        "protocol": row[10],
                        "service": row[11],
                    }
                )
            return results
        except Exception:
            return []

    def is_nuclei_available(self) -> bool:
        """Check if nuclei binary is accessible.

        Returns:
            True if the binary can be executed, False otherwise.
        """
        try:
            result = subprocess.run(
                [self.binary, "-version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return False

    def update_templates(self) -> bool:
        """Update nuclei templates if new versions are available.

        Runs `nuclei -update-templates` which checks for and downloads
        any new or updated templates from the nuclei-templates repository.

        Returns:
            True if update succeeded (or no updates needed), False on error.
        """
        logger.info("Checking for nuclei template updates...")
        try:
            result = subprocess.run(
                [self.binary, "-update-templates"],
                capture_output=True,
                text=True,
                timeout=120,  # 2 min timeout for template download
            )
            stdout = (result.stdout or "").strip()
            stderr = (result.stderr or "").strip()

            if result.returncode == 0:
                # Check if templates were actually updated
                if "no new updates" in stdout.lower() or "already up to date" in stdout.lower():
                    logger.info("Nuclei templates already up to date")
                else:
                    logger.info("Nuclei templates updated successfully")
                    if stdout:
                        # Log relevant lines (template count, new additions)
                        for line in stdout.splitlines()[:5]:
                            logger.info("  %s", line.strip())
                return True
            else:
                logger.warning("Nuclei template update returned code %d: %s", result.returncode, stderr[:300])
                # Non-fatal: proceed with existing templates
                return False

        except subprocess.TimeoutExpired:
            logger.warning("Nuclei template update timed out (120s) — proceeding with existing templates")
            return False
        except (FileNotFoundError, OSError) as e:
            logger.warning("Failed to update nuclei templates: %s — proceeding with existing", e)
            return False

    # ------------------------------------------------------------------
    # Private Helpers
    # ------------------------------------------------------------------

    def _generate_targets(self) -> str:
        """Stream targets from database directly into a temp file for nuclei.

        Avoids loading 600k+ targets into a Python list. Returns the path
        to the temp file containing one target per line.
        """
        fd, path = tempfile.mkstemp(prefix="hostvigil_targets_", suffix=".txt")
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT h.ip, h.hostname, p.port, p.protocol, p.service "
                "FROM ports p JOIN hosts h ON p.host_id = h.id "
                "WHERE p.is_active = 1 AND p.state = 'open' AND h.is_active = 1 "
                "ORDER BY h.ip, p.port"
            )

            seen = set()
            target_count = 0
            with os.fdopen(fd, "w") as f:
                for row in cursor:
                    ip, hostname, port, protocol, service = row
                    host = hostname if hostname else ip
                    target = self._format_target(host, port, service)
                    if target and target not in seen:
                        f.write(f"{target}\n")
                        seen.add(target)
                        target_count += 1

                if target_count == 0:
                    logger.info("No open ports in DB — falling back to active hosts with common ports")
                    cursor.execute(
                        "SELECT ip, hostname FROM hosts WHERE is_active = 1 ORDER BY last_seen DESC LIMIT 500"
                    )
                    fallback_ports = [80, 443, 8080, 8443]
                    for fb_row in cursor:
                        ip, hostname = fb_row
                        host = hostname if hostname else ip
                        for fp in fallback_ports:
                            target = self._format_target(host, fp, "http" if fp in (80, 8080) else "https")
                            if target and target not in seen:
                                f.write(f"{target}\n")
                                seen.add(target)
                                target_count += 1

            logger.info("Wrote %d targets to %s from database", target_count, path)
            return path
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            try:
                os.unlink(path)
            except OSError:
                pass
            raise
        finally:
            if conn:
                conn.close()

    def _format_target(self, host: str, port: int, service: Optional[str]) -> str:
        """Format a single host:port into a nuclei-compatible target string.

        Args:
            host: IP address or hostname.
            port: Port number.
            service: Detected service name (e.g., 'http', 'https', 'ssh').

        Returns:
            Formatted target string.
        """
        service_lower = (service or "").lower()

        # Determine if this is an HTTP/HTTPS service
        is_https = port in HTTPS_PORTS or "https" in service_lower or "ssl" in service_lower or "tls" in service_lower
        is_http = port in HTTP_PORTS or "http" in service_lower or "web" in service_lower

        if is_https:
            if port == 443:
                return f"https://{host}"
            return f"https://{host}:{port}"
        elif is_http:
            if port == 80:
                return f"http://{host}"
            return f"http://{host}:{port}"
        else:
            # Non-HTTP services: use host:port format
            return f"{host}:{port}"

    def _build_command(self, target_file: str) -> List[str]:
        """Construct nuclei CLI command with stealth options.

        Args:
            target_file: Path to file containing target list.

        Returns:
            List of command arguments for subprocess.
        """
        cmd = [
            self.binary,
            "-list",
            target_file,
            "-jsonl",
            "-silent",
            "-no-color",
            "-rate-limit",
            str(self.rate_limit),
            "-concurrency",
            str(self.concurrency),
            "-bulk-size",
            str(self.bulk_size),
            "-timeout",
            str(self.timeout),
            "-retries",
            str(self.retries),
            "-max-host-error",
            str(self.max_host_errors),
        ]

        # Severity filter — only apply if explicitly configured to restrict
        # An empty list or list containing all severities means no filter
        all_severities = {"critical", "high", "medium", "low", "info"}
        if self.severity_filter and set(self.severity_filter) != all_severities:
            cmd.extend(["-severity", ",".join(self.severity_filter)])

        # Custom template paths
        if self.template_paths:
            for tpath in self.template_paths:
                cmd.extend(["-t", str(tpath)])

        # Exclude tags (reduce noise)
        if self.exclude_tags:
            cmd.extend(["-etags", ",".join(self.exclude_tags)])

        return cmd

    def _split_targets_file(self, target_file: str) -> tuple:
        """Split targets into (web_file, network_file) for scoped template runs."""
        import tempfile as _tempfile

        web_fd, web_path = _tempfile.mkstemp(prefix="hv_web_", suffix=".txt")
        net_fd, net_path = _tempfile.mkstemp(prefix="hv_net_", suffix=".txt")
        web_count = 0
        net_count = 0
        try:
            with open(target_file) as src, os.fdopen(web_fd, "w") as wf, os.fdopen(net_fd, "w") as nf:
                for line in src:
                    line = line.strip()
                    if not line:
                        continue
                    is_web = False
                    for port in ALL_WEB_PORTS:
                        if f":{port}" in line or line.startswith("http"):
                            is_web = True
                            break
                    if is_web:
                        wf.write(f"{line}\n")
                        web_count += 1
                    else:
                        nf.write(f"{line}\n")
                        net_count += 1
            logger.info("Split targets: %d web, %d network", web_count, net_count)
            return web_path, net_path, web_count, net_count
        except Exception:
            try:
                os.unlink(web_path)
            except OSError:
                pass
            try:
                os.unlink(net_path)
            except OSError:
                pass
            raise

    def _execute(self, command: List[str], target_count: int = 100) -> str:
        """Run nuclei subprocess and capture output.

        Args:
            command: List of command arguments.
            target_count: Number of targets being scanned, used to scale the
                overall timeout (at least 5 min, 3s per target, capped at 4h).

        Returns:
            Raw stdout output from nuclei (JSONL format).

        Raises:
            RuntimeError: If nuclei execution fails critically.
        """
        logger.debug("Executing: %s", " ".join(command))

        # Scale timeout by target count: at least 5 min, 3s per target, capped at 4 hours
        overall_timeout = max(300, min(target_count * 3, 14400))

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=overall_timeout,
            )

            if result.returncode not in (0, 1):
                # returncode 1 can mean "findings found" in some nuclei versions
                stderr = result.stderr.strip()
                if stderr:
                    logger.warning("Nuclei stderr: %s", stderr[:500])

            if result.stdout:
                logger.debug("Nuclei produced %d bytes of output", len(result.stdout))

            return result.stdout or ""

        except subprocess.TimeoutExpired:
            logger.error("Nuclei scan timed out after %d seconds", overall_timeout)
            return ""
        except FileNotFoundError as e:
            logger.error("Nuclei binary not found: %s", self.binary)
            raise RuntimeError(f"Nuclei binary not found: {self.binary}") from e
        except OSError as e:
            logger.error("Failed to execute nuclei: %s", str(e))
            raise RuntimeError(f"Nuclei execution error: {e}") from e

    def _parse_results(self, output: str) -> List[Dict]:
        """Parse nuclei JSONL output into structured findings.

        Each line of output is a JSON object representing one finding.

        Args:
            output: Raw JSONL output from nuclei.

        Returns:
            List of normalized vulnerability dictionaries.
        """
        findings = []

        if not output or not output.strip():
            return findings

        for line_num, line in enumerate(output.strip().splitlines(), 1):
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError as e:
                logger.debug("Failed to parse nuclei output line %d: %s", line_num, e)
                continue

            vuln = self._normalize_finding(data)
            if vuln:
                # Add red team classification
                vuln["redteam_classification"] = self._classify_for_redteam(vuln)
                findings.append(vuln)

        logger.info("Parsed %d findings from nuclei output", len(findings))
        return findings

    def _normalize_finding(self, data: Dict) -> Optional[Dict]:
        """Normalize a raw nuclei JSON finding into a standard format.

        Args:
            data: Raw JSON dict from nuclei output.

        Returns:
            Normalized vulnerability dict, or None if invalid.
        """
        # Extract core fields - nuclei output format varies by version
        template_id = data.get("template-id") or data.get("templateID", "")
        info = data.get("info", {})

        name = info.get("name") or data.get("name", "Unknown")
        severity = (info.get("severity") or data.get("severity", "info")).lower()
        description = info.get("description", "")
        tags = info.get("tags", [])
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",")]

        # Target info
        matched_at = data.get("matched-at") or data.get("host", "")
        host = data.get("host") or data.get("ip", "")

        # Evidence / extracted data
        extracted = data.get("extracted-results", [])
        matcher_name = data.get("matcher-name", "")
        curl_command = data.get("curl-command", "")

        evidence_parts = []
        if matcher_name:
            evidence_parts.append(f"matcher: {matcher_name}")
        if extracted:
            evidence_parts.append(f"extracted: {', '.join(str(e) for e in extracted[:5])}")
        if curl_command:
            evidence_parts.append(f"curl: {curl_command[:200]}")
        evidence = " | ".join(evidence_parts) if evidence_parts else None

        # Parse host and port from matched_at
        parsed_host, parsed_port = self._parse_host_port(matched_at or host)

        return {
            "template_id": template_id,
            "name": name,
            "severity": severity,
            "description": description,
            "matched_at": matched_at,
            "evidence": evidence,
            "host": parsed_host,
            "port": parsed_port,
            "tags": tags,
            "raw": data,
        }

    def _parse_host_port(self, target: str) -> tuple:
        """Extract host and port from a target string.

        Handles URLs (http://host:port/path) and host:port format.

        Args:
            target: Target string from nuclei output.

        Returns:
            Tuple of (host, port) where port may be None.
        """
        if not target:
            return ("", None)

        # Strip protocol
        host = target
        default_port = None

        if "://" in host:
            scheme, _, remainder = host.partition("://")
            host = remainder
            if scheme == "https":
                default_port = 443
            elif scheme == "http":
                default_port = 80

        # Strip path
        if "/" in host:
            host = host.split("/")[0]

        # Extract port
        port = default_port
        if ":" in host:
            parts = host.rsplit(":", 1)
            try:
                port = int(parts[1])
                host = parts[0]
            except (ValueError, IndexError):
                pass

        # Strip brackets from IPv6
        host = host.strip("[]")

        return (host, port)

    def _store_vulnerability(self, vuln: Dict):
        """Store vulnerability in database with deduplication.

        Deduplicates based on host_id + template_id + matched_at combination.
        Adds redteam_classification as a tag in the description field.

        Args:
            vuln: Normalized vulnerability dictionary.
        """
        conn = self._get_connection()
        try:
            cursor = conn.cursor()

            # Resolve host_id from IP/hostname
            host_id = self._resolve_host_id(cursor, vuln.get("host", ""))
            if host_id is None:
                logger.debug("Skipping vuln storage - host not found in DB: %s", vuln.get("host"))
                return

            # Resolve port_id if port is known
            port_id = None
            if vuln.get("port"):
                port_id = self._resolve_port_id(cursor, host_id, vuln["port"])

            # Build description with redteam classification tag
            description = vuln.get("description", "") or ""
            classification = vuln.get("redteam_classification", "informational")
            tagged_description = f"{description} [redteam:{classification}]".strip()

            template_id = vuln.get("template_id", "")
            matched_at = vuln.get("matched_at", "")

            # Deduplication check
            cursor.execute(
                """
                SELECT id FROM vulnerabilities
                WHERE host_id = ? AND template_id = ? AND matched_at = ?
            """,
                (host_id, template_id, matched_at),
            )

            existing = cursor.fetchone()
            if existing:
                # Update evidence if we have new info
                if vuln.get("evidence"):
                    cursor.execute(
                        """
                        UPDATE vulnerabilities
                        SET evidence = ?, description = ?
                        WHERE id = ?
                    """,
                        (vuln.get("evidence"), tagged_description, existing[0]),
                    )
                    conn.commit()
                logger.debug("Deduplicated vuln: %s on %s", template_id, matched_at)
                return

            # Insert new vulnerability
            cursor.execute(
                """
                INSERT INTO vulnerabilities
                    (host_id, port_id, template_id, name, severity,
                     description, matched_at, evidence, is_verified)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
            """,
                (
                    host_id,
                    port_id,
                    template_id,
                    vuln.get("name", "Unknown"),
                    vuln.get("severity", "info"),
                    tagged_description,
                    matched_at,
                    vuln.get("evidence"),
                ),
            )
            conn.commit()

            logger.debug("Stored vulnerability: %s [%s] on %s", vuln.get("name"), vuln.get("severity"), matched_at)

        except sqlite3.Error as e:
            logger.error("Database error storing vulnerability: %s", e)
            conn.rollback()
        finally:
            conn.close()

    def _classify_for_redteam(self, vuln: Dict) -> str:
        """Classify finding for red team usage.

        Classification levels:
        - exploit_ready: Directly exploitable (RCE, SQLi, auth bypass, etc.)
        - needs_validation: Potentially exploitable, requires manual verification
        - informational: Detection/fingerprint only, useful for recon

        Args:
            vuln: Normalized vulnerability dictionary.

        Returns:
            Classification string.
        """
        severity = vuln.get("severity", "info").lower()
        tags = set(t.lower() for t in vuln.get("tags", []))
        template_id = (vuln.get("template_id", "") or "").lower()
        name = (vuln.get("name", "") or "").lower()

        # Check for exploit-ready indicators
        if tags & EXPLOIT_READY_TAGS:
            return "exploit_ready"

        # Check template ID and name for exploit keywords
        exploit_keywords = [
            "rce",
            "sqli",
            "injection",
            "bypass",
            "default-login",
            "unauth",
            "upload",
            "traversal",
            "deserialization",
        ]
        for keyword in exploit_keywords:
            if keyword in template_id or keyword in name:
                return "exploit_ready"

        # Critical/high severity with evidence tends to be exploitable
        if severity == "critical":
            return "exploit_ready"

        if severity == "high":
            # High severity with evidence → needs validation at minimum
            if vuln.get("evidence"):
                return "exploit_ready"
            return "needs_validation"

        # Medium severity → needs manual validation
        if severity == "medium":
            return "needs_validation"

        # Check for purely informational tags
        if tags & INFORMATIONAL_TAGS:
            return "informational"

        # Low/info severity
        if severity in ("low", "info"):
            return "informational"

        return "needs_validation"

    def _write_target_file(self, targets: List[str]) -> str:
        """Write targets to a temporary file for nuclei -list flag.

        Args:
            targets: List of target strings.

        Returns:
            Path to the temporary target file.
        """
        fd, path = tempfile.mkstemp(prefix="hostvigil_targets_", suffix=".txt")
        try:
            with os.fdopen(fd, "w") as f:
                f.writelines(f"{t}\n" for t in targets)
        except Exception:
            # If os.fdopen itself failed, fd is still open; otherwise the
            # context manager's __exit__ already closed it. In either case,
            # attempt cleanup of the file on disk.
            try:
                os.unlink(path)
            except OSError:
                pass
            raise
        return path

    @staticmethod
    def _count_targets_in_file(path: str) -> int:
        try:
            count = 0
            with open(path) as f:
                for _ in f:
                    count += 1
            return count
        except (OSError, IOError):
            return 100

    def _get_connection(self) -> sqlite3.Connection:
        if not hasattr(self, "_shared_conn") or self._shared_conn is None:
            self._shared_conn = sqlite3.connect(self.db_path, timeout=10)
            self._shared_conn.execute("PRAGMA journal_mode=WAL")
            self._shared_conn.execute("PRAGMA foreign_keys=ON")
        return self._shared_conn

    def _resolve_host_id(self, cursor: sqlite3.Cursor, host: str) -> Optional[int]:
        """Resolve a host string (IP or hostname) to a host_id in the database.

        Args:
            cursor: Active database cursor.
            host: IP address or hostname.

        Returns:
            host_id integer or None if not found.
        """
        if not host:
            return None

        # Try by IP first
        cursor.execute("SELECT id FROM hosts WHERE ip = ?", (host,))
        row = cursor.fetchone()
        if row:
            return row[0]

        # Try by hostname
        cursor.execute("SELECT id FROM hosts WHERE hostname = ?", (host,))
        row = cursor.fetchone()
        if row:
            return row[0]

        return None

    def _resolve_port_id(self, cursor: sqlite3.Cursor, host_id: int, port: int) -> Optional[int]:
        """Resolve a port number to a port_id for a given host.

        Args:
            cursor: Active database cursor.
            host_id: Host ID from hosts table.
            port: Port number.

        Returns:
            port_id integer or None if not found.
        """
        cursor.execute("SELECT id FROM ports WHERE host_id = ? AND port = ?", (host_id, port))
        row = cursor.fetchone()
        return row[0] if row else None
