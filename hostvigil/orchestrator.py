"""
HostVigil Orchestrator - Coordinates all scanning and analysis modules.

Manages the full reconnaissance pipeline:
  Discovery -> Scan -> ML Analysis -> Nuclei (conditional) -> Dashboard

Supports single-run mode, individual module execution, and continuous
daemon mode with configurable scheduling and stealth timing.
"""

import hashlib
import json
import logging
import os
import random
import signal
import threading
import time as _time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from hostvigil.alerting import WebhookAlerter
from hostvigil.config import Config
from hostvigil.dashboard import create_app
from hostvigil.discovery import StealthDiscovery
from hostvigil.ml_engine import AnomalyDetector
from hostvigil.ml_engine.enrichment import MLEnrichmentEngine
from hostvigil.nuclei import NucleiRunner
from hostvigil.scanner import StealthScanner
from hostvigil.scanner.nmap_service_scan import NmapServiceScanner
from hostvigil.scanner.os_fingerprint import OSFingerprinter
from hostvigil.scanner.service_enum import ServiceEnumerator
from hostvigil.scanner.tls_inspector import TLSInspector
from hostvigil.utils import get_db_connection, init_database, now_iso, setup_logging, wal_checkpoint

logger = logging.getLogger("hostvigil.orchestrator")


class PipelineStatus:
    """Tracks pipeline execution state for status reporting."""

    def __init__(self):
        self.state: str = "idle"
        self.current_phase: Optional[str] = None
        self.last_run_start: Optional[str] = None
        self.last_run_end: Optional[str] = None
        self.last_run_result: Optional[str] = None
        self.total_runs: int = 0
        self.total_errors: int = 0
        self.hosts_discovered: int = 0
        self.ports_found: int = 0
        self.anomalies_detected: int = 0
        self.vulns_found: int = 0
        self._lock = threading.Lock()

    def increment_errors(self, n: int = 1) -> None:
        with self._lock:
            self.total_errors += n

    def increment_runs(self) -> None:
        with self._lock:
            self.total_runs += 1

    def increment_hosts_discovered(self, n: int) -> None:
        with self._lock:
            self.hosts_discovered += n

    def increment_ports_found(self, n: int) -> None:
        with self._lock:
            self.ports_found += n

    def increment_anomalies_detected(self, n: int) -> None:
        with self._lock:
            self.anomalies_detected += n

    def increment_vulns_found(self, n: int) -> None:
        with self._lock:
            self.vulns_found += n

    def update(self, **kwargs) -> None:
        with self._lock:
            for key, value in kwargs.items():
                if hasattr(self, key) and not key.startswith("_"):
                    setattr(self, key, value)

    def to_dict(self) -> dict:
        with self._lock:
            return {
                "state": self.state,
                "current_phase": self.current_phase,
                "last_run_start": self.last_run_start,
                "last_run_end": self.last_run_end,
                "last_run_result": self.last_run_result,
                "total_runs": self.total_runs,
                "total_errors": self.total_errors,
                "hosts_discovered": self.hosts_discovered,
                "ports_found": self.ports_found,
                "anomalies_detected": self.anomalies_detected,
                "vulns_found": self.vulns_found,
            }


class HostVigilOrchestrator:
    """Main orchestrator coordinating all HostVigil modules."""

    def __init__(self, config_path: str = "config.yaml"):
        self.config = Config(config_path)
        self.db_path = self.config.database["path"]
        self.stealth_config = self.config.stealth
        self.scheduler_config = self.config.scheduler

        self.running = False
        self._shutdown_event = threading.Event()
        self._daemon_thread: Optional[threading.Thread] = None
        self.status = PipelineStatus()
        self._phase_last_run = {}  # Per-phase interval tracking
        self._phase_in_flight: set = set()  # Phases still running past their deadline
        self._phase_in_flight_lock = threading.Lock()

        # Setup logging (stealth: file-only)
        setup_logging()

        # Initialize database
        init_database(self.db_path).close()

        # Initialize modules
        self.discovery = StealthDiscovery(self.config.hostvigil, self.db_path)
        self.scanner = StealthScanner(self.config.hostvigil, self.db_path)
        self.ml_engine = AnomalyDetector(self.config.ml_engine, self.db_path)
        self.nuclei = NucleiRunner(self.config.nuclei, self.db_path)

        # Initialize deep-scan modules
        os_fp_config = {**self.stealth_config, **self.config.get("os_fingerprint", default={})}
        tls_config = {**self.stealth_config, **self.config.get("tls_inspection", default={})}
        enum_config = {**self.stealth_config, **self.config.get("service_enum", default={})}

        self.os_fingerprinter = OSFingerprinter(os_fp_config, self.db_path)
        self.tls_inspector = TLSInspector(tls_config, self.db_path)
        self.service_enum = ServiceEnumerator(enum_config, self.db_path)

        # Deep service/version detection via nmap -sV (operator-driven)
        svc_scan_config = {**self.stealth_config, **self.config.get("service_scan", default={})}
        self.nmap_service_scanner = NmapServiceScanner(svc_scan_config, self.db_path)

        # ML enrichment engine (learns from feedback and history)
        self.ml_enrichment = MLEnrichmentEngine(self.config.ml_engine, self.db_path)

        # Webhook alerting (no-ops gracefully if not configured/enabled)
        self.alerter = WebhookAlerter(self.config.alerting, self.db_path)

        # Heartbeat file for daemon liveness detection (#10)
        self._heartbeat_path = Path(self.db_path).parent / ".daemon_heartbeat"
        self._last_heartbeat = 0.0

        # Stealth decay scheduler (F6): times the aging of the operation so that
        # delays/concurrency ramp over the lifetime of the daemon.
        self._daemon_start_time = _time.time()
        self._stealth_shaper = None
        try:
            from hostvigil.scanner.traffic_shaper import StealthTrafficShaper

            self._stealth_shaper = StealthTrafficShaper(profile=self.stealth_config.get("profile", "business_hours"))
        except Exception:
            self._stealth_shaper = None

        # Scale validation warnings for enterprise configs
        scale_warnings = self.config.validate_scale()
        for w in scale_warnings:
            logger.warning("Scale: %s", w)

        # Log effective per-phase delays for operator verification (#13)
        self._log_effective_delays(os_fp_config, tls_config, enum_config)

        logger.info("HostVigil Orchestrator initialized (db=%s)", str(Path(self.db_path).resolve()))

    # ------------------------------------------------------------------
    # Stealth Timing
    # ------------------------------------------------------------------

    def _stealth_delay(self, phase: str = "inter-phase") -> None:
        """Apply randomized delay between pipeline phases for stealth."""
        if self._shutdown_event.is_set():
            return

        min_delay = self.stealth_config.get("min_delay", 10.0)
        max_delay = self.stealth_config.get("max_delay", 45.0)
        jitter = self.stealth_config.get("jitter_factor", 0.3)

        decay_enabled = self.stealth_config.get("decay_enabled", False)
        if decay_enabled and self._stealth_shaper is not None:
            ramp_hours = self.stealth_config.get("decay_ramp_hours", 24.0)
            max_mult = self.stealth_config.get("decay_max_multiplier", 3.0)
            base_delay = self._stealth_shaper.get_decayed_delay(
                base_min=min_delay,
                base_max=max_delay,
                ramp_hours=ramp_hours,
                max_multiplier=max_mult,
            )
        else:
            base_delay = random.uniform(min_delay, max_delay)

        jitter_amount = base_delay * random.uniform(-jitter, jitter)
        delay = max(1.0, base_delay + jitter_amount)

        logger.debug(f"Stealth delay ({phase}): {delay:.1f}s")
        self._shutdown_event.wait(timeout=delay)

        if self._shutdown_event.is_set():
            raise InterruptedError("Shutdown requested during stealth delay")

    # ------------------------------------------------------------------
    # Effective delay logging (#13) + Heartbeat (#10)
    # ------------------------------------------------------------------

    def _log_effective_delays(self, os_fp_cfg: dict, tls_cfg: dict, enum_cfg: dict) -> None:
        """Log effective per-phase delays so operators can verify config coverage."""
        phases = {
            "discovery+scan": (self.stealth_config, "nmap/naabu rate controls"),
            "service_enum": (enum_cfg, "per-host delay in enumerate_all"),
            "tls_inspection": (tls_cfg, "per-host:port delay in inspect_all"),
            "os_fingerprint": (os_fp_cfg, "per-host delay in fingerprint_all"),
        }
        for name, (cfg, context) in phases.items():
            mn = cfg.get("min_delay", "?")
            mx = cfg.get("max_delay", "?")
            enabled = cfg.get("enabled", True)
            status = "on" if enabled else "OFF"
            logger.info("Delays [%s] %s: %.2f-%.2fs (%s)", name, status, float(mn), float(mx), context)

    def _write_heartbeat(self) -> None:
        """Write a heartbeat timestamp for external liveness monitoring."""
        now = _time.time()
        if now - self._last_heartbeat < 30:
            return
        self._last_heartbeat = now
        try:
            self._heartbeat_path.parent.mkdir(parents=True, exist_ok=True)
            self._heartbeat_path.write_text(f"{datetime.now(timezone.utc).isoformat()}\n")
        except OSError:
            pass

    # ------------------------------------------------------------------
    # Checkpoint (daemon resume support) — atomic writes with checksum (#7)
    # ------------------------------------------------------------------

    def _checkpoint_path(self) -> Path:
        """Return the path to the daemon checkpoint file."""
        return Path(self.db_path).parent / ".daemon_checkpoint.json"

    def _save_checkpoint(self, cycle: int, phase: str, completed_phases: list[str]) -> None:
        """Save current daemon progress to a checkpoint file (atomic write)."""
        checkpoint = {
            "cycle": cycle,
            "phase": phase,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "completed_phases": completed_phases,
        }
        payload = json.dumps(checkpoint, indent=2)
        checkpoint["_sha256"] = hashlib.sha256(payload.encode()).hexdigest()[:16]
        payload = json.dumps(checkpoint, indent=2)
        try:
            path = self._checkpoint_path()
            tmp = Path(str(path) + ".tmp")
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp.write_text(payload, encoding="utf-8")
            os.replace(tmp, path)  # atomic on Linux
        except Exception as e:
            logger.warning(f"Failed to save checkpoint: {e}")

    def _load_checkpoint(self) -> Optional[dict]:
        """Load checkpoint from disk. Returns None if no checkpoint or corrupted."""
        try:
            path = self._checkpoint_path()
            if not path.exists():
                return None
            data = json.loads(path.read_text(encoding="utf-8"))
            saved_hash = data.pop("_sha256", None)
            if saved_hash:
                payload = json.dumps(data, indent=2)
                computed = hashlib.sha256(payload.encode()).hexdigest()[:16]
                if computed != saved_hash:
                    logger.warning("Checkpoint checksum mismatch — ignoring corrupted checkpoint")
                    return None
            return data
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Failed to load checkpoint (ignoring): {e}")
        return None

    def _clear_checkpoint(self) -> None:
        """Remove the checkpoint file after a successful cycle."""
        try:
            path = self._checkpoint_path()
            if path.exists():
                path.unlink()
        except OSError as e:
            logger.warning(f"Failed to clear checkpoint: {e}")

    # ------------------------------------------------------------------
    # Database Helpers
    # ------------------------------------------------------------------

    def _get_active_hosts(self) -> list[str]:
        """Retrieve active host IPs from the database."""
        try:
            conn = get_db_connection(self.db_path)
            try:
                rows = conn.execute("SELECT ip FROM hosts WHERE is_active = 1").fetchall()
                return [row[0] for row in rows]
            finally:
                conn.close()
        except Exception as e:
            logger.error(f"Failed to fetch active hosts: {e}")
            return []

    def _has_web_ports(self) -> bool:
        """Check if any active hosts have web ports (HTTP/HTTPS) open."""
        return self._count_web_ports() > 0

    def _count_web_ports(self) -> int:
        """Count distinct hosts with web ports open (for nuclei threshold)."""
        WEB_PORTS = (80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9090, 9000, 4443, 9443)
        try:
            conn = get_db_connection(self.db_path)
            try:
                placeholders = ",".join("?" * len(WEB_PORTS))
                row = conn.execute(
                    f"SELECT COUNT(DISTINCT host_id) FROM ports WHERE state = 'open' AND is_active = 1 AND port IN ({placeholders})",
                    WEB_PORTS,
                ).fetchone()
                return row[0] if row else 0
            finally:
                conn.close()
        except Exception:
            return 0

    # ------------------------------------------------------------------
    # Individual Module Execution
    # ------------------------------------------------------------------

    def run_discovery(self) -> dict:
        """Execute host discovery phase."""
        self.status.update(current_phase="discovery")
        logger.info("Starting discovery phase")
        try:
            result = self.discovery.run_discovery()
            hosts_found = result.get("hosts_found", 0)
            self.status.increment_hosts_discovered(hosts_found)
            logger.info(f"Discovery complete: {hosts_found} hosts found")
            return result
        except Exception as e:
            logger.error(f"Discovery phase failed: {e}")
            self.status.increment_errors()
            return {"error": str(e), "hosts_found": 0}

    def run_observer(self) -> dict:
        """Passive-only observer mode (F3): gather intel without active probing.

        Runs passive/listen-only discovery techniques against the configured ranges
        and feeds the ML engine + attack-path engine with whatever is already in the
        database. No port scans, no service connects, no nuclei — the operator sees
        the network's baseline without touching it.

        Returns:
            {'hosts_observed': int, 'passive_techniques': [...], 'analysis': {...}, 'error': str or None}
        """
        self.status.update(state="running", current_phase="observer")
        logger.info("Starting passive observer mode (no active probing)")

        observer_cfg = self.config.get("observer", default={})
        techniques = observer_cfg.get(
            "passive_techniques",
            ["passive_sniff", "dhcp_passive", "mdns_enum", "nbns_query", "ssdp_discover"],
        )

        result = {"hosts_observed": 0, "passive_techniques": techniques, "error": None}

        try:
            discovery_result = self.discovery.run_discovery(techniques=techniques)
            hosts_found = discovery_result.get("hosts_found", 0)
            self.status.increment_hosts_discovered(hosts_found)
            result["hosts_observed"] = hosts_found
            logger.info("Passive observation complete: %d host(s) observed", hosts_found)
        except Exception as e:
            logger.error(f"Passive observation failed: {e}")
            self.status.increment_errors()
            result["error"] = str(e)

        try:
            analysis = self.run_analysis()
            result["analysis"] = {
                "anomalies_detected": analysis.get("anomalies_detected", 0),
                "max_anomaly_score": analysis.get("max_anomaly_score", 0.0),
            }
        except Exception as e:
            logger.debug("Observer analysis skipped: %s", e)

        self.status.update(state="idle", current_phase=None)
        return result

    def run_scan(self) -> dict:
        """Execute port scanning phase on all active hosts."""
        self.status.update(current_phase="scanning")
        logger.info("Starting scan phase")
        try:
            hosts = self._get_active_hosts()
            if not hosts:
                logger.warning("No active hosts to scan")
                return {"ports_found": 0, "reason": "no active hosts"}

            # Check scanner mode configuration
            scanner_mode = self.config.scanner.get("mode", "two_phase")

            if scanner_mode == "two_phase":
                return self._run_two_phase_scan(hosts)
            else:
                # Default: traditional nmap-only scan
                results = self.scanner.scan_hosts(hosts, port_profile="standard")
                ports_found = len(results) if isinstance(results, list) else 0
                self.status.increment_ports_found(ports_found)
                logger.info(f"Scan complete: {ports_found} open ports found")
                return {"ports_found": ports_found, "results": results}
        except Exception as e:
            logger.error(f"Scan phase failed: {e}")
            self.status.increment_errors()
            return {"error": str(e), "ports_found": 0}

    def _run_two_phase_scan(self, hosts: list) -> dict:
        """
        Execute two-phase scan: naabu (fast) → Nmap (deep).

        Optimized for large corporate environments (200,000+ hosts).
        """
        import shutil
        import uuid

        logger.info("Starting two-phase scan (naabu → Nmap)")

        scan_id = str(uuid.uuid4())[:8]

        try:
            # Determine ports from profile
            profile_name = self.config.scanner.get("port_profile", "standard")
            port_profiles = self.config.scanner.get("ports", {})
            profile_ports = port_profiles.get(profile_name, [22, 80, 443, 445, 3389])
            ports_range = ",".join(str(p) for p in profile_ports)

            # Phase 1: Fast port discovery with naabu
            if shutil.which("naabu"):
                logger.info(f"Phase 1: naabu on {len(hosts)} hosts (ports: {ports_range})...")
                open_ports_map = self._run_naabu_scan(hosts, ports_range, stream_from_db=len(hosts) > 10000)
            else:
                logger.warning("naabu not available, falling back to Nmap only")
                return self._run_nmap_only_scan(hosts)

            total_ports = sum(len(ports) for ports in open_ports_map.values())
            hosts_with_ports = len([h for h, p in open_ports_map.items() if p])

            logger.info(f"Phase 1 complete: {total_ports} open ports on {hosts_with_ports} hosts")
            self.status.increment_ports_found(total_ports)

            # Store Phase 1 results
            self._store_port_results(open_ports_map, scan_id)

            # Phase 2: Nmap deep scan on discovered ports only
            if hosts_with_ports > 0:
                logger.info(f"Phase 2: Nmap deep scan on {hosts_with_ports} hosts...")
                # Build preloaded map of ip -> port list for targeted scanning
                preloaded = {ip: ports for ip, ports in open_ports_map.items() if ports}
                try:
                    self.nmap_service_scanner.scan_hosts(list(preloaded.keys()), _preloaded=preloaded)
                except Exception as e:
                    logger.warning(f"Nmap Phase 2 scan failed: {e}")
                logger.info("Phase 2 complete: Deep scan finished")

            return {
                "mode": "two_phase",
                "scan_id": scan_id,
                "hosts_scanned": len(hosts),
                "hosts_with_open_ports": hosts_with_ports,
                "total_open_ports": total_ports,
                "ports_found": total_ports,  # Alias for pipeline consistency
                "phase1_complete": True,
                "phase2_complete": True,
            }

        except Exception as e:
            logger.error(f"Two-phase scan failed: {e}")
            self.status.increment_errors()
            return {"error": str(e), "phase": "two_phase_scan"}

    def _run_naabu_scan(self, hosts: list, ports: str, stream_from_db: bool = False) -> dict:
        """Fast port discovery using naabu (ProjectDiscovery).

        When stream_from_db is True and hosts > 10k, writes IPs directly from
        the database cursor into the temp file to avoid a 200k-element Python list.
        """
        import subprocess
        import tempfile

        results = {}
        host_count = len(hosts)
        # Write hosts to temp file (naabu reads from stdin or -list file)
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", prefix="hv_naabu_", delete=False)
        try:
            if stream_from_db and host_count > 10000:
                conn = get_db_connection(self.db_path)
                try:
                    cursor = conn.execute("SELECT ip FROM hosts WHERE is_active = 1")
                    for row in cursor:
                        tmp.write(f"{row[0]}\n")
                finally:
                    conn.close()
                # Re-count from file lines for accurate host count
                tmp.flush()
                host_count = sum(1 for _ in open(tmp.name))
            else:
                tmp.write("\n".join(hosts))
            tmp.close()

            cmd = [
                "naabu",
                "-list",
                tmp.name,
                "-p",
                ports,
                "-silent",
                "-rate",
                str(self.config.scanner.get("naabu", {}).get("rate", 5000)),
                "-c",
                str(self.config.scanner.get("naabu", {}).get("threads", 50)),
            ]

            logger.info(f"naabu: scanning {host_count} hosts, ports={ports}")
            timeout = max(host_count // 100, 300)  # ~1s per 100 hosts, min 5 min

            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

            if proc.returncode != 0 and proc.stderr:
                logger.warning(f"naabu stderr: {proc.stderr[:200]}")

            # Parse output: "10.0.1.5:22\n10.0.1.5:80\n..."
            from collections import defaultdict

            port_map = defaultdict(list)
            for line in proc.stdout.strip().split("\n"):
                line = line.strip()
                if ":" in line:
                    try:
                        ip, port = line.rsplit(":", 1)
                        port_map[ip.strip()].append(int(port.strip()))
                    except (ValueError, IndexError):
                        continue

            results = dict(port_map)
            total = sum(len(p) for p in results.values())
            logger.info(f"naabu: found {total} open ports on {len(results)} hosts")

        except subprocess.TimeoutExpired:
            logger.error(f"naabu timed out scanning {len(hosts)} hosts")
        except Exception as e:
            logger.error(f"naabu scan failed: {e}")
        finally:
            import os

            try:
                os.unlink(tmp.name)
            except OSError:
                pass

        return results

    def _run_nmap_only_scan(self, hosts: list) -> dict:
        """Traditional Nmap-only scan (fallback mode)."""
        results = self.scanner.scan_hosts(hosts, port_profile="standard")
        ports_found = len(results) if isinstance(results, list) else 0
        self.status.increment_ports_found(ports_found)
        return {"ports_found": ports_found, "mode": "nmap_only"}

    def _store_port_results(self, open_ports_map: dict, scan_id: str):
        """Store port scan results in database with proper connection handling."""
        conn = None
        try:
            conn = get_db_connection(self.db_path)
            now = datetime.now(timezone.utc).isoformat()

            for ip, ports in open_ports_map.items():
                # Ensure host exists
                cursor = conn.execute("SELECT id FROM hosts WHERE ip = ?", (ip,))
                host_row = cursor.fetchone()

                if not host_row:
                    # Create host entry if missing
                    conn.execute(
                        """INSERT INTO hosts (ip, is_active, first_seen, last_seen)
                           VALUES (?, 1, ?, ?)""",
                        (ip, now, now),
                    )
                    host_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
                else:
                    host_id = host_row[0]
                    # Update last_seen
                    conn.execute("UPDATE hosts SET last_seen = ? WHERE id = ?", (now, host_id))

                # Store open ports — upsert to update last_seen and state for existing entries
                for port in ports:
                    conn.execute(
                        """INSERT INTO ports (host_id, port, protocol, state, is_active, first_seen, last_seen)
                           VALUES (?, ?, 'tcp', 'open', 1, ?, ?)
                           ON CONFLICT(host_id, port, protocol) DO UPDATE SET
                               state = 'open',
                               is_active = 1,
                               last_seen = excluded.last_seen""",
                        (host_id, port, now, now),
                    )

            conn.commit()
            logger.debug(f"Stored port scan results for {len(open_ports_map)} hosts")

        except Exception as e:
            logger.error(f"Failed to store port scan results: {e}")
            raise
        finally:
            if conn:
                conn.close()

    def run_analysis(self) -> dict:
        """Execute ML anomaly detection phase."""
        self.status.update(current_phase="ml_analysis")
        logger.info("Starting ML analysis phase")
        try:
            anomalies = self.ml_engine.detect_anomalies()
            count = len(anomalies) if isinstance(anomalies, list) else 0
            max_score = 0.0
            if anomalies:
                max_score = max((a.get("score", 0.0) for a in anomalies), default=0.0)
            self.status.increment_anomalies_detected(count)
            logger.info(f"ML analysis complete: {count} anomalies detected")
            return {
                "anomalies_detected": count,
                "max_anomaly_score": max_score,
                "anomalies": anomalies,
            }
        except Exception as e:
            logger.error(f"ML analysis phase failed: {e}")
            self.status.increment_errors()
            return {"error": str(e), "anomalies_detected": 0}

    def run_nuclei(self) -> dict:
        """Execute Nuclei vulnerability scanning phase."""
        self.status.update(current_phase="nuclei")
        logger.info("Starting Nuclei scan phase")
        try:
            findings = self.nuclei.run_scan()
            vulns = len(findings) if isinstance(findings, list) else 0
            self.status.increment_vulns_found(vulns)
            logger.info(f"Nuclei scan complete: {vulns} vulnerabilities found")
            return {"vulnerabilities_found": vulns, "findings": findings}
        except Exception as e:
            logger.error(f"Nuclei scan phase failed: {e}")
            self.status.increment_errors()
            return {"error": str(e), "vulnerabilities_found": 0}

    def run_udp_scan(self) -> dict:
        """Execute UDP port scanning phase on all active hosts."""
        self.status.update(current_phase="udp_scanning")
        logger.info("Starting UDP scan phase")
        try:
            hosts = self._get_active_hosts()
            if not hosts:
                logger.warning("No active hosts for UDP scan")
                return {"ports_found": 0, "reason": "no active hosts"}

            udp_profile = self.config.scanner.get("udp_profile", "standard")
            results = self.scanner.scan_udp(hosts, port_profile=udp_profile)
            ports_found = len(results) if isinstance(results, list) else 0
            logger.info(f"UDP scan complete: {ports_found} open/filtered ports found")
            return {"ports_found": ports_found, "results": results}
        except Exception as e:
            logger.error(f"UDP scan phase failed: {e}")
            self.status.increment_errors()
            return {"error": str(e), "ports_found": 0}

    def run_os_fingerprint(self) -> dict:
        """Execute OS fingerprinting on all active hosts."""
        self.status.update(current_phase="os_fingerprint")
        logger.info("Starting OS fingerprinting phase")
        try:
            if not self.config.get("os_fingerprint", "enabled", default=True):
                return {"skipped": True, "reason": "disabled in config"}

            results = self.os_fingerprinter.fingerprint_all()
            count = len(results) if isinstance(results, list) else 0
            logger.info(f"OS fingerprinting complete: {count} hosts fingerprinted")
            return {"hosts_fingerprinted": count, "results": results}
        except Exception as e:
            logger.error(f"OS fingerprinting failed: {e}")
            self.status.increment_errors()
            return {"error": str(e), "hosts_fingerprinted": 0}

    def run_tls_inspection(self) -> dict:
        """Execute TLS inspection on hosts with TLS-enabled ports."""
        self.status.update(current_phase="tls_inspection")
        logger.info("Starting TLS inspection phase")
        try:
            if not self.config.get("tls_inspection", "enabled", default=True):
                return {"skipped": True, "reason": "disabled in config"}

            results = self.tls_inspector.inspect_all()
            count = len(results) if isinstance(results, list) else 0
            weak_count = sum(1 for r in (results or []) if r.get("weaknesses"))
            logger.info(f"TLS inspection complete: {count} certs inspected, {weak_count} with weaknesses")
            return {"certs_inspected": count, "weak_certs": weak_count, "results": results}
        except Exception as e:
            logger.error(f"TLS inspection failed: {e}")
            self.status.increment_errors()
            return {"error": str(e), "certs_inspected": 0}

    def run_service_enum(self) -> dict:
        """Execute deep service enumeration on relevant ports."""
        self.status.update(current_phase="service_enum")
        logger.info("Starting service enumeration phase")
        try:
            if not self.config.get("service_enum", "enabled", default=True):
                return {"skipped": True, "reason": "disabled in config"}

            results = self.service_enum.enumerate_all()
            count = len(results) if isinstance(results, list) else 0
            critical = sum(1 for r in (results or []) if r.get("risk_level") in ("critical", "high"))
            logger.info(f"Service enumeration complete: {count} services checked, {critical} critical/high findings")
            return {"services_enumerated": count, "critical_findings": critical, "results": results}
        except Exception as e:
            logger.error(f"Service enumeration failed: {e}")
            self.status.increment_errors()
            return {"error": str(e), "services_enumerated": 0}

    def run_service_scan(self) -> dict:
        """Run deep service/version detection (nmap -sV) on open ports.

        Operator-driven enrichment; not part of the stealth daemon pipeline.
        """
        self.status.update(current_phase="service_scan")
        logger.info("Starting nmap -sV service/version detection phase")
        try:
            if not self.config.get("service_scan", "enabled", default=True):
                return {"skipped": True, "reason": "disabled in config"}

            result = self.nmap_service_scanner.scan_all()
            if result.get("error"):
                logger.warning("Service scan reported: %s", result["error"])
            else:
                logger.info(
                    "Service scan complete: %d host(s), %d port(s) enriched",
                    result.get("hosts_scanned", 0),
                    result.get("ports_enriched", 0),
                )
            return result
        except Exception as e:
            logger.error(f"Service scan failed: {e}")
            self.status.increment_errors()
            return {"error": str(e), "ports_enriched": 0}

    # ------------------------------------------------------------------
    # Full Pipeline
    # ------------------------------------------------------------------

    def _should_run_nuclei(self, scan_results: dict, ml_results: dict, **extra_results) -> bool:
        """Determine if Nuclei should run based on scan/ML/enum results."""
        if not self.config.nuclei.get("auto_run", True):
            return False
        if scan_results.get("ports_found", 0) > 0:
            return True
        if ml_results.get("anomalies_detected", 0) > 0:
            return True
        high_score = ml_results.get("max_anomaly_score", 0.0)
        threshold = self.config.ml_engine.get("anomaly_threshold", 0.7)
        if high_score >= threshold:
            return True
        # Trigger on critical service enumeration findings
        enum_results = extra_results.get("enum_results", {})
        if enum_results.get("critical_findings", 0) > 0:
            return True
        # Trigger on TLS weaknesses
        tls_results = extra_results.get("tls_results", {})
        if tls_results.get("weak_certs", 0) > 0:
            return True
        return False

    def run_once(self) -> dict:
        """Execute the full pipeline once.

        Pipeline: Discovery -> Scan -> ML Analysis -> Nuclei (conditional)
        """
        self.status.update(
            state="running",
            last_run_start=now_iso(),
            last_run_end=None,
            last_run_result=None,
        )
        pipeline_results = {"start_time": now_iso(), "phases": {}}

        logger.info("=" * 60)
        logger.info("Starting full pipeline execution")
        logger.info("=" * 60)

        try:
            # Phase 1: Discovery
            discovery_results = self.run_discovery()
            pipeline_results["phases"]["discovery"] = {"hosts_found": discovery_results.get("hosts_found", 0)}
            if self._shutdown_event.is_set():
                raise InterruptedError("Shutdown requested")
            self._stealth_delay("post-discovery")

            # Phase 2: Port Scanning
            scan_results = self.run_scan()
            pipeline_results["phases"]["scan"] = {"ports_found": scan_results.get("ports_found", 0)}
            if self._shutdown_event.is_set():
                raise InterruptedError("Shutdown requested")
            self._stealth_delay("post-scan")

            # Phase 2b: UDP Scanning
            if self.config.scanner.get("udp_scan_enabled", True):
                udp_results = self.run_udp_scan()
                pipeline_results["phases"]["udp_scan"] = {"ports_found": udp_results.get("ports_found", 0)}
                if self._shutdown_event.is_set():
                    raise InterruptedError("Shutdown requested")
                self._stealth_delay("post-udp-scan")

            # Phase 2c: OS Fingerprinting
            os_results = self.run_os_fingerprint()
            pipeline_results["phases"]["os_fingerprint"] = {
                "hosts_fingerprinted": os_results.get("hosts_fingerprinted", 0)
            }
            if self._shutdown_event.is_set():
                raise InterruptedError("Shutdown requested")
            self._stealth_delay("post-os-fingerprint")

            # Phase 2d: TLS Inspection
            tls_results = self.run_tls_inspection()
            pipeline_results["phases"]["tls_inspection"] = {
                "certs_inspected": tls_results.get("certs_inspected", 0),
                "weak_certs": tls_results.get("weak_certs", 0),
            }
            if self._shutdown_event.is_set():
                raise InterruptedError("Shutdown requested")
            self._stealth_delay("post-tls-inspection")

            # Phase 2e: Service Enumeration
            enum_results = self.run_service_enum()
            pipeline_results["phases"]["service_enum"] = {
                "services_enumerated": enum_results.get("services_enumerated", 0),
                "critical_findings": enum_results.get("critical_findings", 0),
            }
            if self._shutdown_event.is_set():
                raise InterruptedError("Shutdown requested")
            self._stealth_delay("post-service-enum")

            # Phase 3: ML Analysis
            ml_results = self.run_analysis()
            pipeline_results["phases"]["ml_analysis"] = {
                "anomalies_detected": ml_results.get("anomalies_detected", 0),
                "max_anomaly_score": ml_results.get("max_anomaly_score", 0.0),
            }
            if self._shutdown_event.is_set():
                raise InterruptedError("Shutdown requested")

            # Phase 4: Nuclei (conditional)
            if self._should_run_nuclei(scan_results, ml_results, enum_results=enum_results, tls_results=tls_results):
                self._stealth_delay("pre-nuclei")
                nuclei_results = self.run_nuclei()
                pipeline_results["phases"]["nuclei"] = {
                    "vulnerabilities_found": nuclei_results.get("vulnerabilities_found", 0)
                }
            else:
                pipeline_results["phases"]["nuclei"] = {"skipped": True, "reason": "no triggers"}
                logger.info("Nuclei scan skipped: no vulnerability indicators")

            pipeline_results["end_time"] = now_iso()
            pipeline_results["success"] = True
            self.status.update(
                state="idle",
                current_phase=None,
                last_run_end=now_iso(),
                last_run_result="success",
            )
            self.status.increment_runs()
            logger.info("Pipeline execution complete")

        except InterruptedError:
            pipeline_results["end_time"] = now_iso()
            pipeline_results["success"] = False
            pipeline_results["interrupted"] = True
            self.status.update(
                state="stopped",
                current_phase=None,
                last_run_end=now_iso(),
                last_run_result="interrupted",
            )
            logger.warning("Pipeline interrupted by shutdown signal")

        except Exception as e:
            pipeline_results["end_time"] = now_iso()
            pipeline_results["success"] = False
            pipeline_results["error"] = str(e)
            self.status.update(
                state="idle",
                current_phase=None,
                last_run_end=now_iso(),
                last_run_result=f"error: {e}",
            )
            self.status.increment_errors()
            logger.error(f"Pipeline failed: {e}")

        # Store for dashboard live display
        self._last_pipeline_result = pipeline_results
        self._store_scan_record(pipeline_results)
        return pipeline_results

    # ------------------------------------------------------------------
    # Continuous Daemon Mode
    # ------------------------------------------------------------------

    def run_continuous(self) -> None:
        """Run the pipeline continuously with stealth-randomized intervals.

        Pipeline: Discovery -> Scan -> UDP Scan -> OS Fingerprint -> TLS -> Enum -> ML -> Nuclei (auto if configured)
        Nuclei runs on its own interval (default 6h) when auto_run=true and web ports exist.
        """
        self.running = True
        self.status.update(state="running")
        logger.info("HostVigil daemon started - continuous mode (Nuclei excluded)")

        discovery_interval = self.scheduler_config.get("discovery_interval_hours", 4) * 3600
        scan_interval = self.scheduler_config.get("scan_interval_hours", 2) * 3600
        base_interval = min(discovery_interval, scan_interval)

        run_count = 0

        # Check for incomplete checkpoint from a prior run
        skip_phases: Optional[list[str]] = None
        checkpoint = self._load_checkpoint()
        if checkpoint and checkpoint.get("completed_phases"):
            completed = checkpoint["completed_phases"]
            logger.info(
                "Resuming from checkpoint (cycle %d, interrupted during '%s'). Skipping already-completed phases: %s",
                checkpoint.get("cycle", "?"),
                checkpoint.get("phase", "?"),
                ", ".join(completed),
            )
            skip_phases = completed

        consecutive_crashes = 0
        max_consecutive_crashes = 3
        crash_restart_delay = 60

        while not self._shutdown_event.is_set():
            run_count += 1
            logger.info(f"Daemon cycle #{run_count} starting")
            self._write_heartbeat()

            try:
                self._run_daemon_cycle(cycle_number=run_count, skip_phases=skip_phases)
                consecutive_crashes = 0
            except InterruptedError:
                raise
            except Exception as e:
                logger.error("Daemon cycle #%d crashed: %s", run_count, e, exc_info=True)
                consecutive_crashes += 1
                if consecutive_crashes >= max_consecutive_crashes:
                    logger.critical(
                        "Daemon crashed %d consecutive times — shutting down",
                        consecutive_crashes,
                    )
                    break
                logger.warning(
                    "Crash recovery: restarting next cycle in %ds (crash %d/%d)",
                    crash_restart_delay,
                    consecutive_crashes,
                    max_consecutive_crashes,
                )
                self._shutdown_event.wait(timeout=crash_restart_delay)
                continue

            # Only skip on the very first cycle after resume
            skip_phases = None

            if self._shutdown_event.is_set():
                break

            jitter = self.stealth_config.get("jitter_factor", 0.3)
            jitter_amount = base_interval * random.uniform(-jitter, jitter)
            wait_time = max(60.0, base_interval + jitter_amount)

            logger.info(f"Daemon cycle #{run_count} complete. Next in {wait_time / 60:.1f} min")
            self._shutdown_event.wait(timeout=wait_time)

        self.running = False
        self.status.update(state="stopped")
        logger.info("HostVigil daemon stopped")

    def _is_phase_due(self, phase_name: str) -> bool:
        """Check if a phase is due to run based on scheduler intervals."""
        # Map phase names to scheduler interval config keys (all in hours)
        interval_map = {
            "discovery": self.scheduler_config.get("discovery_interval_hours", 4) * 3600,
            "scanning": self.scheduler_config.get("scan_interval_hours", 2) * 3600,
            "service_enum": self.scheduler_config.get("service_enum_interval_hours", 8) * 3600,
            "tls_inspection": self.scheduler_config.get("tls_inspection_interval_hours", 12) * 3600,
            "os_fingerprint": self.scheduler_config.get("os_fingerprint_interval_hours", 12) * 3600,
            "udp_scanning": self.scheduler_config.get("discovery_interval_hours", 4) * 3600,
            "ml_analysis": self.scheduler_config.get("scan_interval_hours", 2) * 3600,
            "nuclei": self.config.nuclei.get("run_interval_hours", 6) * 3600,
        }
        interval = interval_map.get(phase_name, 0)
        if interval == 0:
            return True  # No interval configured, always run
        last_run = self._phase_last_run.get(phase_name, 0)
        return (_time.time() - last_run) >= interval

    def _mark_phase_run(self, phase_name: str) -> None:
        """Record that a phase just ran."""
        self._phase_last_run[phase_name] = _time.time()

    def _get_phase_deadline(self, phase_name: str) -> float:
        """Return max duration (seconds) for a phase, 0 = no limit."""
        deadline_map = {
            "scanning": "phase_deadline_scanning",
            "service_enum": "phase_deadline_service_enum",
            "tls_inspection": "phase_deadline_tls",
            "os_fingerprint": "phase_deadline_os_fingerprint",
            "udp_scanning": "phase_deadline_udp",
            "ml_analysis": "phase_deadline_ml",
            "nuclei": "phase_deadline_nuclei",
        }
        key = deadline_map.get(phase_name)
        if not key:
            return 0
        return self.scheduler_config.get(key, 0)

    def _run_phase_with_deadline(self, phase_name: str, phase_func, *args, **kwargs) -> dict:
        """Run a phase with a deadline. Returns result dict or {'deadline_exceeded': True}.

        If a previous run of this phase is still alive past its deadline
        (a background thread we can't kill), the phase is skipped rather than
        stacked with a second concurrent run.
        """
        deadline = self._get_phase_deadline(phase_name)
        if deadline <= 0:
            return phase_func(*args, **kwargs)

        with self._phase_in_flight_lock:
            if phase_name in self._phase_in_flight:
                logger.warning(
                    "Phase '%s' still running from a previous cycle (deadline exceeded) — skipping to avoid overlap",
                    phase_name,
                )
                return {"deadline_exceeded": True, "phase": phase_name, "skipped": True, "deadline_seconds": deadline}
            self._phase_in_flight.add(phase_name)

        result_container = {"result": None, "done": False, "error": None}

        def _worker():
            try:
                result_container["result"] = phase_func(*args, **kwargs)
            except Exception as e:
                result_container["error"] = str(e)
            finally:
                result_container["done"] = True
                with self._phase_in_flight_lock:
                    self._phase_in_flight.discard(phase_name)

        thread = threading.Thread(target=_worker, name=f"hv-phase-{phase_name}", daemon=True)
        thread.start()
        thread.join(timeout=deadline)

        if not result_container["done"]:
            logger.warning(
                "Phase '%s' exceeded deadline of %ds — aborting and continuing pipeline",
                phase_name,
                deadline,
            )
            return {"deadline_exceeded": True, "phase": phase_name, "deadline_seconds": deadline}

        if result_container["error"]:
            raise RuntimeError(result_container["error"])

        return result_container["result"] or {}

    def _run_daemon_cycle(self, cycle_number: int = 0, skip_phases: Optional[list[str]] = None) -> dict:
        """Single daemon cycle: everything EXCEPT Nuclei.

        Nuclei is excluded from auto-runs to keep load low.
        Use the dashboard 'Nuclei Vuln Scan' button or `python run.py nuclei` to trigger it manually.

        Args:
            cycle_number: Current cycle count (for checkpoint tracking).
            skip_phases: List of phase keys to skip (already completed in a prior interrupted cycle).
        """
        # Check scan window — skip cycle if outside allowed hours
        if self.stealth_config.get("scan_window_enabled", False):
            current_hour = datetime.now().hour
            window_start = self.stealth_config.get("scan_window_start", 8)
            window_end = self.stealth_config.get("scan_window_end", 18)
            if window_start <= window_end:
                in_window = window_start <= current_hour < window_end
            else:
                # Wraps midnight (e.g. start=22, end=6)
                in_window = current_hour >= window_start or current_hour < window_end
            if not in_window:
                logger.info(
                    "Outside scan window (hour=%d, window=%d-%d), skipping cycle",
                    current_hour,
                    window_start,
                    window_end,
                )
                return {
                    "start_time": now_iso(),
                    "end_time": now_iso(),
                    "phases": {},
                    "mode": "daemon",
                    "success": True,
                    "skipped": True,
                    "reason": "outside_scan_window",
                }

        if skip_phases is None:
            skip_phases = []

        self.status.update(
            state="running",
            last_run_start=now_iso(),
            last_run_end=None,
            last_run_result=None,
        )
        pipeline_results = {"start_time": now_iso(), "phases": {}, "mode": "daemon"}
        completed_phases: list[str] = []

        try:
            # ---------------------------------------------------------------
            # Phase 1+2: Discovery + Port Scanning
            # When parallel_scan is enabled, these run concurrently:
            #   - Discovery finds hosts and writes them to DB
            #   - Scanner picks up new hosts in batches and scans immediately
            # This prevents enterprise environments from waiting 12+ hours
            # for discovery to complete before any ports are scanned.
            # ---------------------------------------------------------------
            use_parallel = self._is_parallel_scan_enabled()
            discovery_due = self._is_phase_due("discovery")
            scanning_due = self._is_phase_due("scanning")

            if (
                use_parallel
                and discovery_due
                and scanning_due
                and "discovery" not in skip_phases
                and "scanning" not in skip_phases
            ):
                # PARALLEL MODE: discovery + naabu scan run concurrently in batches
                self._save_checkpoint(cycle_number, "parallel_discovery_scan", completed_phases)
                parallel_results = self._run_parallel_discovery_and_scan(cycle_number)

                # Record discovery results
                pipeline_results["phases"]["discovery"] = {
                    "hosts_found": parallel_results.get("hosts_found", 0),
                    "mode": "parallel",
                }
                self._mark_phase_run("discovery")
                completed_phases.append("discovery")

                # Record scan results
                scan_results = {"ports_found": parallel_results.get("ports_found", 0)}
                pipeline_results["phases"]["scan"] = {
                    "ports_found": parallel_results.get("ports_found", 0),
                    "hosts_scanned": parallel_results.get("hosts_scanned", 0),
                    "batches": parallel_results.get("scan_batches", 0),
                    "mode": "parallel",
                }
                self._mark_phase_run("scanning")
                completed_phases.append("scanning")

                # Alert on new hosts discovered
                new_hosts = parallel_results.get("hosts_found", 0)
                if new_hosts > 0:
                    self.alerter.notify_async(
                        "new_host",
                        f"{new_hosts} new host(s) discovered",
                        f"Parallel discovery+scan found {new_hosts} host(s) and "
                        f"{parallel_results.get('ports_found', 0)} open port(s).",
                        severity="medium" if new_hosts < 10 else "high",
                        extra={
                            "hosts_found": new_hosts,
                            "ports_found": parallel_results.get("ports_found", 0),
                            "mode": "parallel",
                        },
                    )

            else:
                # SEQUENTIAL MODE (original behavior): discovery then scan
                # Phase 1: Discovery
                if "discovery" in skip_phases:
                    pipeline_results["phases"]["discovery"] = {"skipped": True, "reason": "resumed from checkpoint"}
                    completed_phases.append("discovery")
                elif discovery_due:
                    self._save_checkpoint(cycle_number, "discovery", completed_phases)
                    discovery_results = self.run_discovery()
                    pipeline_results["phases"]["discovery"] = {"hosts_found": discovery_results.get("hosts_found", 0)}
                    self._mark_phase_run("discovery")
                    completed_phases.append("discovery")
                    # Alert on new hosts discovered
                    new_hosts = discovery_results.get("hosts_found", 0)
                    if new_hosts > 0:
                        self.alerter.notify_async(
                            "new_host",
                            f"{new_hosts} new host(s) discovered",
                            f"Discovery phase found {new_hosts} host(s) on the network.",
                            severity="medium" if new_hosts < 10 else "high",
                            extra={"hosts_found": new_hosts},
                        )
                else:
                    pipeline_results["phases"]["discovery"] = {"skipped": True, "reason": "not due yet"}
                    completed_phases.append("discovery")
                if self._shutdown_event.is_set():
                    raise InterruptedError("Shutdown requested")
                self._stealth_delay("post-discovery")

                # Phase 2: TCP Port Scanning (immediate value — finds open services)
                if "scanning" in skip_phases:
                    scan_results = {"ports_found": 0}
                    pipeline_results["phases"]["scan"] = {"skipped": True, "reason": "resumed from checkpoint"}
                    completed_phases.append("scanning")
                elif scanning_due:
                    self._save_checkpoint(cycle_number, "scanning", completed_phases)
                    scan_results = self.run_scan()
                    pipeline_results["phases"]["scan"] = {"ports_found": scan_results.get("ports_found", 0)}
                    self._mark_phase_run("scanning")
                    completed_phases.append("scanning")
                else:
                    scan_results = {"ports_found": 0}
                    pipeline_results["phases"]["scan"] = {"skipped": True, "reason": "not due yet"}
                    completed_phases.append("scanning")

            if self._shutdown_event.is_set():
                raise InterruptedError("Shutdown requested")
            self._stealth_delay("post-scan")

            # Phase 3: Service Enumeration (low-hanging fruit — no-auth services,
            # SMB null sessions, relay targets, exposed APIs)
            if "service_enum" in skip_phases:
                pipeline_results["phases"]["service_enum"] = {"skipped": True, "reason": "resumed from checkpoint"}
                completed_phases.append("service_enum")
            elif self._is_phase_due("service_enum"):
                self._save_checkpoint(cycle_number, "service_enum", completed_phases)
                enum_results = self._run_phase_with_deadline("service_enum", self.run_service_enum)
                pipeline_results["phases"]["service_enum"] = {
                    "services_enumerated": enum_results.get("services_enumerated", 0),
                    "critical_findings": enum_results.get("critical_findings", 0),
                    "deadline_exceeded": enum_results.get("deadline_exceeded", False),
                }
                self._mark_phase_run("service_enum")
                completed_phases.append("service_enum")
                # Alert on critical/high service exposure findings
                critical_findings = enum_results.get("critical_findings", 0)
                if critical_findings > 0:
                    self.alerter.notify_async(
                        "service_exposed",
                        f"{critical_findings} exposed service(s) found",
                        f"Service enumeration found {critical_findings} critical/high-risk "
                        f"exposed service(s) (no-auth, null sessions, etc.).",
                        severity="critical" if critical_findings >= 5 else "high",
                        extra={
                            "critical_findings": critical_findings,
                            "services_enumerated": enum_results.get("services_enumerated", 0),
                        },
                    )
            else:
                pipeline_results["phases"]["service_enum"] = {"skipped": True, "reason": "not due yet"}
                completed_phases.append("service_enum")
            if self._shutdown_event.is_set():
                raise InterruptedError("Shutdown requested")
            self._stealth_delay("post-service-enum")

            # Phase 4: TLS Inspection (expired certs, weak ciphers — quick wins)
            if "tls_inspection" in skip_phases:
                pipeline_results["phases"]["tls_inspection"] = {"skipped": True, "reason": "resumed from checkpoint"}
                completed_phases.append("tls_inspection")
            elif self._is_phase_due("tls_inspection"):
                self._save_checkpoint(cycle_number, "tls_inspection", completed_phases)
                tls_results = self._run_phase_with_deadline("tls_inspection", self.run_tls_inspection)
                pipeline_results["phases"]["tls_inspection"] = {
                    "certs_inspected": tls_results.get("certs_inspected", 0),
                    "weak_certs": tls_results.get("weak_certs", 0),
                    "deadline_exceeded": tls_results.get("deadline_exceeded", False),
                }
                self._mark_phase_run("tls_inspection")
                completed_phases.append("tls_inspection")
            else:
                pipeline_results["phases"]["tls_inspection"] = {"skipped": True, "reason": "not due yet"}
                completed_phases.append("tls_inspection")
            if self._shutdown_event.is_set():
                raise InterruptedError("Shutdown requested")
            self._stealth_delay("post-tls-inspection")

            # Phase 5: OS Fingerprinting (enrichment, slower)
            if "os_fingerprint" in skip_phases:
                pipeline_results["phases"]["os_fingerprint"] = {"skipped": True, "reason": "resumed from checkpoint"}
                completed_phases.append("os_fingerprint")
            elif self._is_phase_due("os_fingerprint"):
                self._save_checkpoint(cycle_number, "os_fingerprint", completed_phases)
                os_results = self._run_phase_with_deadline("os_fingerprint", self.run_os_fingerprint)
                pipeline_results["phases"]["os_fingerprint"] = {
                    "hosts_fingerprinted": os_results.get("hosts_fingerprinted", 0),
                    "deadline_exceeded": os_results.get("deadline_exceeded", False),
                }
                self._mark_phase_run("os_fingerprint")
                completed_phases.append("os_fingerprint")
            else:
                pipeline_results["phases"]["os_fingerprint"] = {"skipped": True, "reason": "not due yet"}
                completed_phases.append("os_fingerprint")
            if self._shutdown_event.is_set():
                raise InterruptedError("Shutdown requested")
            self._stealth_delay("post-os-fingerprint")

            # Phase 6: UDP Scanning (slow, background enrichment)
            if self.config.scanner.get("udp_scan_enabled", True):
                if "udp_scanning" in skip_phases:
                    pipeline_results["phases"]["udp_scan"] = {"skipped": True, "reason": "resumed from checkpoint"}
                    completed_phases.append("udp_scanning")
                elif self._is_phase_due("udp_scanning"):
                    self._save_checkpoint(cycle_number, "udp_scanning", completed_phases)
                    udp_results = self._run_phase_with_deadline("udp_scanning", self.run_udp_scan)
                    pipeline_results["phases"]["udp_scan"] = {
                        "ports_found": udp_results.get("ports_found", 0),
                        "deadline_exceeded": udp_results.get("deadline_exceeded", False),
                    }
                    self._mark_phase_run("udp_scanning")
                    completed_phases.append("udp_scanning")
                else:
                    pipeline_results["phases"]["udp_scan"] = {"skipped": True, "reason": "not due yet"}
                    completed_phases.append("udp_scanning")
                if self._shutdown_event.is_set():
                    raise InterruptedError("Shutdown requested")
                self._stealth_delay("post-udp-scan")

            # Phase 7: ML Analysis
            if "ml_analysis" in skip_phases:
                pipeline_results["phases"]["ml_analysis"] = {"skipped": True, "reason": "resumed from checkpoint"}
                completed_phases.append("ml_analysis")
            elif self._is_phase_due("ml_analysis"):
                self._save_checkpoint(cycle_number, "ml_analysis", completed_phases)
                ml_results = self._run_phase_with_deadline("ml_analysis", self.run_analysis)
                pipeline_results["phases"]["ml_analysis"] = {
                    "anomalies_detected": ml_results.get("anomalies_detected", 0),
                    "max_anomaly_score": ml_results.get("max_anomaly_score", 0.0),
                    "deadline_exceeded": ml_results.get("deadline_exceeded", False),
                }
                self._mark_phase_run("ml_analysis")
                completed_phases.append("ml_analysis")
                # Alert on high-confidence anomalies (score > 0.8)
                if ml_results.get("anomalies"):
                    high_anomalies = [a for a in ml_results["anomalies"] if a.get("score", 0.0) > 0.8]
                    if high_anomalies:
                        self.alerter.notify_async(
                            "high_anomaly",
                            f"{len(high_anomalies)} high-confidence anomaly(ies) detected",
                            f"ML engine detected {len(high_anomalies)} anomaly(ies) with "
                            f"confidence > 0.8. Max score: {ml_results.get('max_anomaly_score', 0.0):.2f}.",
                            severity="high",
                            extra={
                                "count": len(high_anomalies),
                                "max_score": ml_results.get("max_anomaly_score", 0.0),
                                "total_anomalies": ml_results.get("anomalies_detected", 0),
                            },
                        )
            else:
                pipeline_results["phases"]["ml_analysis"] = {"skipped": True, "reason": "not due yet"}
                completed_phases.append("ml_analysis")

            # Phase 7b: ML Enrichment (incremental learning)
            try:
                enrichment_result = self.ml_enrichment.incremental_update()
                pipeline_results["phases"]["ml_enrichment"] = {
                    "temporal_updated": enrichment_result.get("temporal", {}).get("status") == "updated",
                    "correlations_updated": enrichment_result.get("correlations", {}).get("status") == "updated",
                    "drift_detected": enrichment_result.get("snapshot", {}).get("drift_detected", False),
                }
                # Alert on network drift detection
                if enrichment_result.get("snapshot", {}).get("drift_detected", False):
                    enrichment_result.get("snapshot", {})
                    self.alerter.notify_async(
                        "drift_detected",
                        "Network drift detected",
                        "ML enrichment engine detected significant network changes "
                        "(host/port/service drift exceeding threshold).",
                        severity="high",
                        extra={
                            "temporal_updated": enrichment_result.get("temporal", {}).get("status"),
                            "correlations_updated": enrichment_result.get("correlations", {}).get("status"),
                        },
                    )
            except Exception as e:
                logger.error(f"ML enrichment update failed: {e}")
                pipeline_results["phases"]["ml_enrichment"] = {"error": str(e)}

            # Phase 8: Nuclei (conditional — auto-run if configured)
            # Runs on its own interval when auto_run is enabled and web ports exist
            nuclei_auto = self.config.nuclei.get("auto_run", False)
            nuclei_min_targets = self.config.nuclei.get("min_targets", 50)
            # Check for open ports from scan results (handles both scan modes)
            ports_from_scan = scan_results.get("ports_found", 0) or scan_results.get("total_open_ports", 0)

            if nuclei_auto and self._is_phase_due("nuclei"):
                # Check minimum target threshold before wasting a nuclei run
                web_port_count = self._count_web_ports()
                if web_port_count >= nuclei_min_targets:
                    self._stealth_delay("pre-nuclei")
                    nuclei_results = self._run_phase_with_deadline("nuclei", self.run_nuclei)
                    pipeline_results["phases"]["nuclei"] = {
                        "vulnerabilities_found": nuclei_results.get("vulnerabilities_found", 0),
                        "deadline_exceeded": nuclei_results.get("deadline_exceeded", False),
                    }
                    self._mark_phase_run("nuclei")
                    logger.info(f"Nuclei auto-run complete: {nuclei_results.get('vulnerabilities_found', 0)} vulns")
                    # Alert on critical/high vulnerabilities
                    vulns_found = nuclei_results.get("vulnerabilities_found", 0)
                    if vulns_found > 0:
                        self.alerter.notify_async(
                            "critical_vuln",
                            f"{vulns_found} vulnerability(ies) found by Nuclei",
                            f"Nuclei vulnerability scan discovered {vulns_found} "
                            f"critical/high severity vulnerability(ies).",
                            severity="critical",
                            extra={"vulnerabilities_found": vulns_found, "web_targets_scanned": web_port_count},
                        )
                elif ports_from_scan > 0 or web_port_count > 0:
                    pipeline_results["phases"]["nuclei"] = {
                        "skipped": True,
                        "reason": f"waiting for min targets ({web_port_count}/{nuclei_min_targets} web ports found)",
                    }
                    logger.info(
                        f"Nuclei skipped: {web_port_count}/{nuclei_min_targets} web targets (threshold not met)"
                    )
                else:
                    pipeline_results["phases"]["nuclei"] = {"skipped": True, "reason": "no web ports discovered yet"}
            else:
                pipeline_results["phases"]["nuclei"] = {
                    "skipped": True,
                    "reason": "not due yet" if nuclei_auto else "auto_run disabled",
                }

            # Phase 9: Attack chain correlation (F4) — persist + export chains once per cycle
            self._run_attack_chain_correlation(pipeline_results)

            pipeline_results["end_time"] = now_iso()
            pipeline_results["success"] = True
            self.status.update(
                state="running",  # Stay running in daemon mode
                current_phase=None,
                last_run_end=now_iso(),
                last_run_result="success",
            )
            self.status.increment_runs()

            # Cycle completed successfully — clear the checkpoint
            self._clear_checkpoint()
            logger.info("Daemon cycle complete")

        except InterruptedError:
            pipeline_results["end_time"] = now_iso()
            pipeline_results["success"] = False
            pipeline_results["interrupted"] = True
            self.status.update(
                state="stopped",
                current_phase=None,
                last_run_end=now_iso(),
                last_run_result="interrupted",
            )

        except Exception as e:
            pipeline_results["end_time"] = now_iso()
            pipeline_results["success"] = False
            pipeline_results["error"] = str(e)
            self.status.update(
                state="running",  # Stay running in daemon mode — cycle failed, not the daemon
                current_phase=None,
                last_run_end=now_iso(),
                last_run_result=f"error: {e}",
            )
            self.status.increment_errors()
            logger.error(f"Daemon cycle failed: {e}")

        # Store last pipeline result for dashboard consumption
        self._last_pipeline_result = pipeline_results
        self._store_scan_record(pipeline_results)
        self._export_metrics(pipeline_results, cycle_number)
        return pipeline_results

    def _run_attack_chain_correlation(self, pipeline_results: dict) -> None:
        """Run attack-chain correlation (F4) as a safe, best-effort phase."""
        try:
            from hostvigil.attack_paths import AttackPathEngine

            engine = AttackPathEngine(self.db_path)
            correlation = engine.correlate_attack_chains(limit=50)
            pipeline_results["phases"]["attack_chains"] = {
                "chain_count": correlation.get("chain_count", 0),
                "rows_written": correlation.get("rows_written", 0),
                "export_path": correlation.get("export_path"),
            }
            if correlation.get("error"):
                pipeline_results["phases"]["attack_chains"]["error"] = correlation["error"]
        except Exception as e:
            logger.debug("Attack chain correlation skipped: %s", e)
            pipeline_results.setdefault("phases", {})["attack_chains"] = {"skipped": True, "reason": str(e)}

    def _export_metrics(self, results: dict, cycle: int) -> None:
        """Write structured metrics.json for external monitoring (#9)."""
        try:
            phases = results.get("phases", {})
            status = self.status.to_dict()
            metrics = {
                "daemon": {
                    "cycle": cycle,
                    "state": status.get("state", "unknown"),
                    "total_runs": status.get("total_runs", 0),
                    "total_errors": status.get("total_errors", 0),
                    "hosts_discovered": status.get("hosts_discovered", 0),
                    "ports_found": status.get("ports_found", 0),
                    "anomalies_detected": status.get("anomalies_detected", 0),
                    "vulns_found": status.get("vulns_found", 0),
                },
                "last_cycle": {
                    "started": results.get("start_time"),
                    "ended": results.get("end_time"),
                    "mode": results.get("mode"),
                    "success": results.get("success", True),
                    "phases": {k: {sk: sv for sk, sv in v.items() if sk != "results"} for k, v in phases.items()},
                },
                "exported_at": now_iso(),
            }
            path = Path(self.db_path).parent / "metrics.json"
            tmp = Path(str(path) + ".tmp")
            tmp.parent.mkdir(parents=True, exist_ok=True)
            tmp.write_text(json.dumps(metrics, indent=2, default=str), encoding="utf-8")
            os.replace(tmp, path)
        except Exception as e:
            logger.debug("Failed to export metrics: %s", e)

    # ------------------------------------------------------------------
    # Parallel Discovery + Port Scanning (Enterprise Pipeline)
    # ------------------------------------------------------------------

    def _is_parallel_scan_enabled(self) -> bool:
        """Check if parallel discovery+scan is enabled in config."""
        parallel_cfg = self.config.get("parallel_scan", default={})
        return parallel_cfg.get("enabled", False)

    def _get_parallel_scan_config(self) -> dict:
        """Get parallel scan configuration with defaults."""
        parallel_cfg = self.config.get("parallel_scan", default={})
        return {
            "enabled": parallel_cfg.get("enabled", False),
            "batch_size": parallel_cfg.get("batch_size", 100),
            "scan_interval_sec": parallel_cfg.get("scan_interval_sec", 30),
            "max_scan_threads": parallel_cfg.get("max_scan_threads", 2),
        }

    def _run_parallel_discovery_and_scan(self, cycle_number: int) -> dict:
        """Run discovery and naabu port scanning in parallel.

        Instead of: discover ALL hosts (12+ hours) → then scan ALL
        This does:  discover in background → every batch_size hosts → fire naabu scan

        The discovery thread runs all configured techniques. Every scan_interval_sec
        seconds (or when batch_size new hosts accumulate), the main thread fires
        naabu on the newly discovered batch while discovery continues.

        Returns combined results dict for both phases.
        """
        import shutil

        parallel_cfg = self._get_parallel_scan_config()
        batch_size = parallel_cfg["batch_size"]
        scan_interval = parallel_cfg["scan_interval_sec"]

        logger.info(
            "Starting PARALLEL discovery + scan pipeline (batch_size=%d, interval=%ds)",
            batch_size,
            scan_interval,
        )
        self.status.update(current_phase="parallel_discovery_scan")

        # Track hosts that existed before this cycle (already scanned)
        pre_existing_hosts = set(self._get_active_hosts())
        logger.info("Pre-existing active hosts: %d", len(pre_existing_hosts))

        # Discovery runs in a background thread
        discovery_result = {"hosts": 0, "error": None, "done": False}
        discovery_lock = threading.Lock()

        def _discovery_worker():
            try:
                result = self.discovery.run_discovery()
                with discovery_lock:
                    discovery_result["hosts"] = result.get("hosts_found", 0)
            except Exception as e:
                with discovery_lock:
                    discovery_result["error"] = str(e)
                logger.error(f"Parallel discovery failed: {e}")
            finally:
                with discovery_lock:
                    discovery_result["done"] = True

        discovery_thread = threading.Thread(
            target=_discovery_worker,
            name="parallel-discovery",
            daemon=True,
        )
        discovery_thread.start()

        # Port scanning happens in the main thread, polling for new hosts
        total_hosts_scanned = 0
        total_ports_found = 0
        scanned_hosts = set()  # Track what we've already scanned this cycle
        scan_batches = 0
        naabu_available = shutil.which("naabu") is not None

        if not naabu_available:
            logger.warning("naabu not in PATH — parallel scan will use nmap connect scan (slower)")

        # Get port profile for scanning
        profile_name = self.config.scanner.get("port_profile", "standard")
        port_profiles = self.config.scanner.get("ports", {})
        profile_ports = port_profiles.get(profile_name, [22, 80, 443, 445, 3389])
        ports_str = ",".join(str(p) for p in profile_ports)

        # Poll loop: check for new hosts and scan them in batches
        while True:
            self._write_heartbeat()
            if self._shutdown_event.is_set():
                logger.info("Parallel pipeline interrupted by shutdown")
                break

            # Wait for scan_interval or until discovery finishes
            self._shutdown_event.wait(timeout=scan_interval)
            if self._shutdown_event.is_set():
                break

            # Get current active hosts from DB (discovery writes to DB as it finds hosts)
            current_hosts = set(self._get_active_hosts())
            new_hosts = current_hosts - pre_existing_hosts - scanned_hosts

            # Check if discovery is done
            with discovery_lock:
                discovery_done = discovery_result["done"]

            if len(new_hosts) >= batch_size or (discovery_done and new_hosts):
                # We have enough hosts for a batch (or discovery is done with remaining)
                batch = list(new_hosts)[: batch_size * 2]  # Allow slightly larger final batch
                scan_batches += 1

                logger.info(
                    "Parallel scan batch #%d: scanning %d new hosts (ports: %s)",
                    scan_batches,
                    len(batch),
                    ports_str,
                )

                # Run naabu or fallback scan on this batch
                batch_ports = self._scan_batch_parallel(batch, ports_str, naabu_available)
                batch_port_count = sum(len(p) for p in batch_ports.values())

                total_hosts_scanned += len(batch)
                total_ports_found += batch_port_count
                scanned_hosts.update(batch)

                # Store results in DB
                if batch_ports:
                    import uuid

                    scan_id = f"parallel-{uuid.uuid4().hex[:8]}"
                    self._store_port_results(batch_ports, scan_id)

                logger.info(
                    "Batch #%d complete: %d ports on %d/%d hosts",
                    scan_batches,
                    batch_port_count,
                    len([h for h in batch if batch_ports.get(h)]),
                    len(batch),
                )

                self.status.increment_ports_found(batch_port_count)

            elif discovery_done and not new_hosts:
                # Discovery finished and no more new hosts to scan
                logger.info("Discovery complete, no more new hosts to scan")
                break

        # Wait for discovery thread to finish (should already be done or close)
        discovery_thread.join(timeout=60)

        # Final sweep: any hosts discovered in the last moments
        final_hosts = set(self._get_active_hosts()) - pre_existing_hosts - scanned_hosts
        if final_hosts:
            logger.info("Final sweep: scanning %d remaining hosts", len(final_hosts))
            final_batch = list(final_hosts)
            batch_ports = self._scan_batch_parallel(final_batch, ports_str, naabu_available)
            batch_port_count = sum(len(p) for p in batch_ports.values())
            total_ports_found += batch_port_count
            total_hosts_scanned += len(final_batch)
            if batch_ports:
                import uuid

                scan_id = f"parallel-final-{uuid.uuid4().hex[:8]}"
                self._store_port_results(batch_ports, scan_id)

        # Compile results
        with discovery_lock:
            hosts_found = discovery_result.get("hosts", 0)
            discovery_error = discovery_result.get("error")

        self.status.increment_hosts_discovered(hosts_found)

        results = {
            "mode": "parallel_discovery_scan",
            "hosts_found": hosts_found,
            "hosts_scanned": total_hosts_scanned,
            "ports_found": total_ports_found,
            "scan_batches": scan_batches,
            "batch_size": batch_size,
        }
        if discovery_error:
            results["discovery_error"] = discovery_error

        logger.info(
            "Parallel pipeline complete: discovered=%d, scanned=%d, ports=%d, batches=%d",
            hosts_found,
            total_hosts_scanned,
            total_ports_found,
            scan_batches,
        )
        return results

    def _scan_batch_parallel(self, hosts: list, ports_str: str, naabu_available: bool) -> dict:
        """Scan a batch of hosts using naabu (preferred) or fallback nmap connect.

        Args:
            hosts: List of IP addresses to scan.
            ports_str: Comma-separated port list (e.g. "22,80,443,445,3389").
            naabu_available: Whether naabu binary is in PATH.

        Returns:
            Dict mapping IP -> list of open ports: {ip: [port1, port2, ...]}
        """
        if not hosts:
            return {}

        if naabu_available:
            return self._naabu_batch_scan(hosts, ports_str)
        else:
            return self._fallback_batch_scan(hosts, ports_str)

    def _naabu_batch_scan(self, hosts: list, ports_str: str) -> dict:
        """Run naabu on a batch of hosts. Returns {ip: [ports]}."""
        import subprocess
        import tempfile
        from collections import defaultdict

        naabu_cfg = self.config.scanner.get("naabu", {})
        rate = naabu_cfg.get("rate", 5000)
        threads = naabu_cfg.get("threads", 50)

        results = defaultdict(list)
        tmp = None

        try:
            tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", prefix="hv_parallel_", delete=False)
            tmp.write("\n".join(hosts))
            tmp.close()

            cmd = [
                "naabu",
                "-list",
                tmp.name,
                "-p",
                ports_str,
                "-silent",
                "-rate",
                str(rate),
                "-c",
                str(threads),
            ]

            # Timeout: ~1s per 100 hosts minimum, at least 60s
            timeout = max(60, len(hosts) // 50)
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

            if proc.returncode != 0 and proc.stderr:
                logger.warning("naabu batch stderr: %s", proc.stderr[:200])

            for line in proc.stdout.strip().split("\n"):
                line = line.strip()
                if ":" in line:
                    try:
                        ip, port = line.rsplit(":", 1)
                        results[ip.strip()].append(int(port.strip()))
                    except (ValueError, IndexError):
                        continue

        except subprocess.TimeoutExpired:
            logger.warning("naabu batch timed out for %d hosts", len(hosts))
        except Exception as e:
            logger.error("naabu batch scan failed: %s", e)
        finally:
            if tmp:
                import os

                try:
                    os.unlink(tmp.name)
                except OSError:
                    pass

        return dict(results)

    def _fallback_batch_scan(self, hosts: list, ports_str: str) -> dict:
        """Fallback: scan batch using the built-in scanner (slower but no naabu needed)."""
        try:
            profile_name = self.config.scanner.get("port_profile", "standard")
            results = self.scanner.scan_hosts(hosts, port_profile=profile_name)
            # Convert scanner results format to {ip: [ports]}
            from collections import defaultdict

            port_map = defaultdict(list)
            if isinstance(results, list):
                for r in results:
                    if isinstance(r, dict) and "ip" in r and "port" in r:
                        port_map[r["ip"]].append(r["port"])
            return dict(port_map)
        except Exception as e:
            logger.error("Fallback batch scan failed: %s", e)
            return {}

    def _store_scan_record(self, results: dict):
        """Store a scan record in the scans table for dashboard history."""
        try:
            conn = get_db_connection(self.db_path)
            try:
                phases = results.get("phases", {})
                hosts_found = phases.get("discovery", {}).get("hosts_found", 0)
                ports_found = phases.get("scan", {}).get("ports_found", 0)
                conn.execute(
                    "INSERT INTO scans (scan_type, start_time, end_time, hosts_found, ports_found) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (
                        results.get("mode", "full"),
                        results.get("start_time", now_iso()),
                        results.get("end_time", now_iso()),
                        hosts_found,
                        ports_found,
                    ),
                )
                conn.commit()
            finally:
                conn.close()
        except Exception as e:
            logger.error(f"Failed to store scan record: {e}")
        try:
            wal_checkpoint(self.db_path)
        except Exception:
            pass

    def start_daemon(self) -> None:
        """Start continuous mode in a background thread."""
        if self._daemon_thread and self._daemon_thread.is_alive():
            logger.warning("Daemon already running")
            return
        self._shutdown_event.clear()
        self._daemon_thread = threading.Thread(
            target=self.run_continuous,
            name="hostvigil-daemon",
            daemon=True,
        )
        self._daemon_thread.start()

    # ------------------------------------------------------------------
    # Dashboard
    # ------------------------------------------------------------------

    def run_dashboard(self, host: Optional[str] = None, port: Optional[int] = None) -> None:
        """Start the web dashboard."""
        import secrets as _secrets

        dashboard_config = self.config.dashboard
        bind_host = host or dashboard_config.get("host", "127.0.0.1")
        bind_port = port or dashboard_config.get("port", 5000)

        secret_key = dashboard_config.get("secret_key", "hostvigil-default-key")
        if secret_key in ("change-this-in-production", "hostvigil-default-key"):
            secret_key = _secrets.token_hex(32)
            logger.warning("Dashboard using auto-generated secret_key")

        app = create_app(
            {
                "db_path": self.db_path,
                "secret_key": secret_key,
                "refresh_interval": dashboard_config.get("refresh_interval", 30),
                "orchestrator": self,
            }
        )

        logger.info(f"Starting dashboard on {bind_host}:{bind_port}")
        print(f"[*] HostVigil Dashboard: http://{bind_host}:{bind_port}")
        print("[*] Press Ctrl+C to stop")
        app.run(host=bind_host, port=bind_port, debug=False, use_reloader=False)

    # ------------------------------------------------------------------
    # Status & Control
    # ------------------------------------------------------------------

    def get_status(self) -> dict:
        """Get current orchestrator and pipeline status."""
        db_stats = self._get_db_stats()
        return {
            "orchestrator": self.status.to_dict(),
            "database": db_stats,
            "config": {
                "stealth_min_delay": self.stealth_config.get("min_delay"),
                "stealth_max_delay": self.stealth_config.get("max_delay"),
                "scan_interval_hours": self.scheduler_config.get("scan_interval_hours"),
                "discovery_interval_hours": self.scheduler_config.get("discovery_interval_hours"),
                "nuclei_interval_hours": self.scheduler_config.get("nuclei_interval_hours"),
            },
        }

    def get_live_status(self) -> dict:
        """Get lightweight live daemon status (zero DB queries).

        Designed for the Live Status page — returns only in-memory state
        so it can be polled at high frequency without performance impact,
        even with 200k+ hosts in the database.
        """
        status_dict = self.status.to_dict()
        now = _time.time()

        # Pipeline phase definitions in execution order
        phases = [
            {"key": "discovery", "label": "Discovery", "icon": "search"},
            {"key": "scanning", "label": "TCP Scan", "icon": "ethernet"},
            {"key": "service_enum", "label": "Service Enum", "icon": "list-check"},
            {"key": "tls_inspection", "label": "TLS Inspect", "icon": "lock"},
            {"key": "os_fingerprint", "label": "OS Fingerprint", "icon": "fingerprint"},
            {"key": "udp_scanning", "label": "UDP Scan", "icon": "broadcast"},
            {"key": "ml_analysis", "label": "ML Analysis", "icon": "cpu"},
        ]

        # Determine phase states (completed/active/pending/skipped)
        current_phase = status_dict.get("current_phase")
        phase_timeline = []
        for phase in phases:
            last_run = self._phase_last_run.get(phase["key"], 0)
            phase_info = {
                "key": phase["key"],
                "label": phase["label"],
                "icon": phase["icon"],
                "last_run": last_run if last_run > 0 else None,
                "state": "pending",
            }
            # Determine state
            if current_phase and current_phase == phase["key"]:
                phase_info["state"] = "active"
            elif last_run > 0 and status_dict.get("last_run_start"):
                # Phase ran during current/last cycle
                phase_info["state"] = "completed"
            phase_timeline.append(phase_info)

        # Calculate next cycle ETA
        next_cycle_eta = None
        time_until_next = None
        base_interval = min(
            self.scheduler_config.get("discovery_interval_hours", 4) * 3600,
            self.scheduler_config.get("scan_interval_hours", 2) * 3600,
        )
        last_run_end = status_dict.get("last_run_end")
        if last_run_end and not current_phase:
            # Parse ISO timestamp to epoch
            try:
                dt = datetime.fromisoformat(last_run_end.replace("Z", "+00:00"))
                end_epoch = dt.timestamp()
                next_epoch = end_epoch + base_interval
                time_until_next = max(0, next_epoch - now)
                next_cycle_eta = datetime.fromtimestamp(next_epoch, tz=timezone.utc).isoformat()
            except (ValueError, TypeError):
                pass

        # Last cycle results (from in-memory store)
        last_result = getattr(self, "_last_pipeline_result", None)
        last_cycle_phases = {}
        if last_result and isinstance(last_result, dict):
            last_cycle_phases = last_result.get("phases", {})

        return {
            "daemon_running": self.running,
            "state": status_dict.get("state", "stopped"),
            "current_phase": current_phase,
            "total_runs": status_dict.get("total_runs", 0),
            "total_errors": status_dict.get("total_errors", 0),
            "last_run_start": status_dict.get("last_run_start"),
            "last_run_end": last_run_end,
            "last_run_result": status_dict.get("last_run_result"),
            "hosts_discovered": status_dict.get("hosts_discovered", 0),
            "ports_found": status_dict.get("ports_found", 0),
            "anomalies_detected": status_dict.get("anomalies_detected", 0),
            "vulns_found": status_dict.get("vulns_found", 0),
            "phase_timeline": phase_timeline,
            "next_cycle_eta": next_cycle_eta,
            "time_until_next_seconds": time_until_next,
            "base_interval_seconds": base_interval,
            "last_cycle_phases": last_cycle_phases,
            "scan_window_enabled": self.stealth_config.get("scan_window_enabled", False),
            "scan_window_start": self.stealth_config.get("scan_window_start", 8),
            "scan_window_end": self.stealth_config.get("scan_window_end", 18),
        }

    def _get_db_stats(self) -> dict:
        """Query database for current statistics."""
        try:
            conn = get_db_connection(self.db_path)
            try:
                stats = {}
                stats["total_hosts"] = conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
                stats["active_hosts"] = conn.execute("SELECT COUNT(*) FROM hosts WHERE is_active = 1").fetchone()[0]
                stats["total_ports"] = conn.execute("SELECT COUNT(*) FROM ports WHERE is_active = 1").fetchone()[0]
                stats["total_vulnerabilities"] = conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
                stats["total_anomalies"] = conn.execute("SELECT COUNT(*) FROM anomalies").fetchone()[0]
                stats["total_scans"] = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
                return stats
            finally:
                conn.close()
        except Exception as e:
            logger.error(f"Failed to get DB stats: {e}")
            return {"error": str(e)}

    # ------------------------------------------------------------------
    # Shutdown
    # ------------------------------------------------------------------

    def shutdown(self) -> None:
        """Graceful shutdown of all running operations."""
        logger.info("Shutdown requested")
        self.status.update(state="stopping")
        self._shutdown_event.set()
        self.running = False

        if self._daemon_thread and self._daemon_thread.is_alive():
            logger.info("Waiting for daemon thread to stop...")
            self._daemon_thread.join(timeout=30)
            if self._daemon_thread.is_alive():
                logger.warning("Daemon thread did not stop within timeout")

        self.status.update(state="stopped", current_phase=None)
        logger.info("HostVigil shutdown complete")

    def install_signal_handlers(self) -> None:
        """Install OS signal handlers for graceful shutdown."""

        def _handler(signum, frame):
            sig_name = signal.Signals(signum).name
            logger.info(f"Received signal {sig_name}")
            print(f"\n[!] Received {sig_name}, shutting down gracefully...")
            self.shutdown()
            # Clean PID file
            pid_file = Path("data/.hostvigil.pid")
            if pid_file.exists():
                pid_file.unlink(missing_ok=True)
            # Flush logs before force-exit
            import logging as _logging

            for h in _logging.getLogger("hostvigil").handlers:
                h.flush()
                h.close()
            # Force exit — Flask's socket accept() won't respond to sys.exit
            os._exit(0)

        signal.signal(signal.SIGINT, _handler)
        signal.signal(signal.SIGTERM, _handler)
        if hasattr(signal, "SIGPIPE"):
            # Ignore SIGPIPE so a client aborting a connection (e.g. navigating
            # away from a dashboard page mid-request) raises BrokenPipeError in
            # the handler instead of killing the whole process. SIG_DFL would
            # terminate the daemon on the first broken pipe.
            signal.signal(signal.SIGPIPE, signal.SIG_IGN)
        if hasattr(signal, "SIGBREAK"):
            signal.signal(signal.SIGBREAK, _handler)
