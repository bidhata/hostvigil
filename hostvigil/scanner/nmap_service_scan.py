"""
Deep service/version detection using ``nmap -sV``.

This is an *operator-driven* enrichment step (mirroring how Nuclei is kept out
of the stealth daemon). It reuses nmap's continuously-maintained
``nmap-service-probes`` database to extract structured product / version / CPE
information for ports that HostVigil already discovered, and writes those into
the ``ports`` table (``product``, ``version``, ``cpe``, ``extra_info``).

It only probes ports that are already known to be open, so it does not perform
its own port discovery. It uses a TCP connect scan (``-sT``) so no root/raw
sockets are required, and it skips host discovery/DNS (``-Pn -n``).

Because ``nmap -sV`` has a recognizable probe signature, this module is not part
of the continuous stealth pipeline; it is triggered on demand from the CLI
(``python run.py servicescan``) or the dashboard.
"""

import ipaddress
import logging
import os
import re
import shutil
import sqlite3
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("hostvigil")


class NmapServiceScanner:
    """Run ``nmap -sV`` against known-open ports and enrich the ports table."""

    def __init__(self, config: dict, db_path: str):
        """Initialize the scanner.

        Args:
            config: Merged config dict (stealth + optional ``service_scan``
                section). Recognized keys:
                - ``nmap_binary`` (str): path/name of nmap (default 'nmap').
                - ``version_intensity`` (int 0-9): nmap ``--version-intensity``
                  (default 5). Lower is quieter/faster, higher is more thorough.
                - ``nmap_timing`` (str): timing template, e.g. 'T2' (default).
                - ``scan_delay`` (str): optional nmap ``--scan-delay`` (e.g.
                  '1s') for extra stealth. Empty/None disables it.
                - ``host_timeout`` (str): optional nmap ``--host-timeout``.
                - ``parallel`` (int): number of concurrent nmap processes
                  (default 4). Set to 1 for the quietest operation.
                - ``max_hosts`` (int): safety cap on hosts per run (default 0 =
                  no cap).
                - ``scan_timeout`` (int): per-host subprocess timeout seconds
                  (default 300).
            db_path: Path to the SQLite database.
        """
        self.config = config or {}
        self.db_path = db_path

        self.nmap_binary = str(self.config.get("nmap_binary", "nmap"))
        self.version_intensity = int(self.config.get("version_intensity", 5))
        self.timing = str(self.config.get("nmap_timing", "T2")).lstrip("-")
        if not re.match(r"^T[0-5]$", self.timing, re.IGNORECASE):
            logger.warning("service scan: invalid nmap_timing '%s', defaulting to T2", self.timing)
            self.timing = "T2"
        self.scan_delay = str(self.config.get("scan_delay", "") or "")
        if self.scan_delay and not re.match(r"^\d+(\.\d+)?(ms|s|m|h)?$", self.scan_delay):
            logger.warning("service scan: invalid scan_delay '%s', disabling", self.scan_delay)
            self.scan_delay = ""
        self.host_timeout = str(self.config.get("host_timeout", "") or "")
        if self.host_timeout and not re.match(r"^\d+(\.\d+)?(ms|s|m|h)?$", self.host_timeout):
            logger.warning("service scan: invalid host_timeout '%s', disabling", self.host_timeout)
            self.host_timeout = ""
        self.parallel = max(1, int(self.config.get("parallel", 4)))
        self.max_hosts = int(self.config.get("max_hosts", 0))
        self.scan_timeout = int(self.config.get("scan_timeout", 300))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def scan_all(self) -> Dict:
        """Run service/version detection across all active hosts with open ports.

        Returns:
            Summary dict: hosts_scanned, ports_enriched, services_identified,
            and optionally 'error'.
        """
        targets = self._load_open_ports()
        if not targets:
            return {
                "hosts_scanned": 0,
                "ports_enriched": 0,
                "services_identified": 0,
                "message": "No open TCP ports found. Run a TCP scan first.",
            }
        hosts = list(targets.keys())
        # Apply max_hosts cap
        if self.max_hosts > 0:
            hosts = hosts[: self.max_hosts]
        return self.scan_hosts(hosts, _preloaded=targets)

    def scan_host(self, ip: str) -> Dict:
        """Run service/version detection against a single host's open ports."""
        return self.scan_hosts([ip])

    def scan_hosts(self, ips: List[str], _preloaded: Optional[Dict[str, List[int]]] = None) -> Dict:
        """Run service/version detection against the given hosts.

        Args:
            ips: List of host IPs to scan.
            _preloaded: Optional pre-fetched {ip: [ports]} map (internal).

        Returns:
            Summary dict.
        """
        nmap_path = shutil.which(self.nmap_binary)
        if not nmap_path:
            logger.error("nmap not found in PATH; cannot run service scan")
            return {
                "error": "nmap not found in PATH",
                "hosts_scanned": 0,
                "ports_enriched": 0,
                "services_identified": 0,
            }

        port_map = _preloaded if _preloaded is not None else self._load_open_ports()
        # Restrict to requested hosts that actually have open ports
        work = {ip: port_map[ip] for ip in ips if port_map.get(ip)}

        if self.max_hosts and len(work) > self.max_hosts:
            logger.warning(
                "service scan: %d hosts exceed max_hosts (%d); truncating",
                len(work),
                self.max_hosts,
            )
            work = dict(list(work.items())[: self.max_hosts])

        if not work:
            return {
                "hosts_scanned": 0,
                "ports_enriched": 0,
                "services_identified": 0,
                "message": "No open TCP ports found for the requested host(s).",
            }

        total_enriched = 0
        total_services = 0
        hosts_scanned = 0

        workers = min(self.parallel, len(work))
        logger.info(
            "service scan: nmap -sV on %d host(s) with %d worker(s)",
            len(work),
            workers,
        )

        def _scan_one(item: Tuple[str, List[int]]):
            ip, ports = item
            parsed = self._run_nmap_sv(nmap_path, ip, ports)
            return ip, parsed

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(_scan_one, item): item[0] for item in work.items()}
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    _ip, parsed = future.result()
                    if parsed:
                        enriched, services = self._store_results(_ip, parsed)
                        total_enriched += enriched
                        total_services += services
                    hosts_scanned += 1
                except Exception as exc:
                    logger.error("service scan failed for %s: %s", ip, exc)

        logger.info(
            "service scan complete: %d host(s), %d port(s) enriched, %d service(s) identified",
            hosts_scanned,
            total_enriched,
            total_services,
        )
        return {
            "hosts_scanned": hosts_scanned,
            "ports_enriched": total_enriched,
            "services_identified": total_services,
        }

    # ------------------------------------------------------------------
    # Database helpers
    # ------------------------------------------------------------------
    def _load_open_ports(self) -> Dict[str, List[int]]:
        """Return {ip: [open tcp ports]} for active hosts."""
        result: Dict[str, List[int]] = defaultdict(list)
        try:
            conn = sqlite3.connect(self.db_path, timeout=30)
            conn.execute("PRAGMA busy_timeout=30000")
            try:
                rows = conn.execute(
                    """
                    SELECT h.ip AS ip, p.port AS port
                    FROM ports p
                    JOIN hosts h ON h.id = p.host_id
                    WHERE p.state = 'open'
                      AND p.protocol = 'tcp'
                      AND p.is_active = 1
                      AND h.is_active = 1
                    """
                ).fetchall()
            finally:
                conn.close()
        except sqlite3.Error as exc:
            logger.error("service scan: failed to load open ports: %s", exc)
            return {}

        for ip, port in rows:
            if ip and port:
                result[ip].append(int(port))
        return dict(result)

    def _store_results(self, ip: str, parsed: Dict[int, Dict]) -> Tuple[int, int]:
        """Update ports rows for a host with parsed service info.

        Returns (ports_enriched, services_identified).
        """
        now = datetime.now(timezone.utc).isoformat()
        enriched = 0
        services = 0
        conn = None
        try:
            conn = sqlite3.connect(self.db_path, timeout=30)
            conn.execute("PRAGMA busy_timeout=30000")
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            cur = conn.cursor()

            row = cur.execute("SELECT id FROM hosts WHERE ip = ?", (ip,)).fetchone()
            if not row:
                return 0, 0
            host_id = row[0]

            for port, info in parsed.items():
                product = info.get("product") or None
                version = info.get("version") or None
                cpe = info.get("cpe") or None
                extra = info.get("extra_info") or None
                svc_name = info.get("name") or None

                # Only fill service if we don't already have a classification;
                # the deep scan enriches version data without clobbering the
                # existing banner-based service label.
                existing = cur.execute(
                    "SELECT id, service FROM ports WHERE host_id = ? AND port = ? AND protocol = 'tcp'",
                    (host_id, port),
                ).fetchone()
                if not existing:
                    continue
                port_id, cur_service = existing

                new_service = cur_service
                if (not cur_service or cur_service in ("", "unknown")) and svc_name:
                    new_service = svc_name.upper()

                cur.execute(
                    "UPDATE ports SET service = ?, product = ?, version = ?, "
                    "cpe = ?, extra_info = ?, last_seen = ? WHERE id = ?",
                    (new_service, product, version, cpe, extra, now, port_id),
                )
                enriched += 1
                if product or version or svc_name:
                    services += 1

            conn.commit()
        except sqlite3.Error as exc:
            logger.error("service scan: failed to store results for %s: %s", ip, exc)
        finally:
            if conn:
                conn.close()
        return enriched, services

    # ------------------------------------------------------------------
    # nmap invocation + parsing
    # ------------------------------------------------------------------
    def _run_nmap_sv(self, nmap_path: str, ip: str, ports: List[int]) -> Dict[int, Dict]:
        """Run ``nmap -sV`` against a single host's ports and parse the XML.

        Returns {port: {name, product, version, extra_info, cpe}}.
        """
        if not ports:
            return {}

        try:
            ipaddress.ip_address(ip)
        except ValueError:
            logger.warning("service scan: invalid IP '%s', skipping", ip)
            return {}

        port_list = ",".join(str(p) for p in sorted(set(ports)))

        flags = [
            "-sV",
            "-Pn",  # hosts already known up; skip discovery
            "-n",  # no DNS resolution
            "-sT",  # TCP connect scan (no root needed)
            "--version-intensity",
            str(self.version_intensity),
            "-" + self.timing,
        ]
        if self.scan_delay:
            flags += ["--scan-delay", self.scan_delay]
        if self.host_timeout:
            flags += ["--host-timeout", self.host_timeout]

        tmp_xml = None
        try:
            fd, tmp_xml = tempfile.mkstemp(prefix="hv_nmapsv_", suffix=".xml")
            os.close(fd)
            cmd = [nmap_path] + flags + ["-p", port_list, "-oX", tmp_xml, ip]
            logger.info("service scan: %s", " ".join(cmd))
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                _stdout, stderr = proc.communicate(timeout=self.scan_timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate()
                logger.warning(
                    "service scan timed out after %ds for %s (parsing partial XML)",
                    self.scan_timeout,
                    ip,
                )
                return self._parse_sv_xml(tmp_xml)
            except Exception:
                if proc.poll() is None:
                    proc.kill()
                    proc.communicate()
                raise

            if proc.returncode not in (0, None):
                logger.warning(
                    "nmap -sV exited with code %d for %s: %s",
                    proc.returncode,
                    ip,
                    (stderr or "").strip()[:200],
                )
            return self._parse_sv_xml(tmp_xml)
        finally:
            if tmp_xml:
                try:
                    Path(tmp_xml).unlink(missing_ok=True)
                except OSError:
                    pass

    @staticmethod
    def _parse_sv_xml(xml_path: str) -> Dict[int, Dict]:
        """Parse an ``nmap -sV -oX`` file into {port: service info}."""
        results: Dict[int, Dict] = {}
        try:
            tree = ET.parse(xml_path)
        except (ET.ParseError, FileNotFoundError, OSError) as exc:
            logger.error("Failed to parse nmap -sV XML '%s': %s", xml_path, exc)
            return results

        root = tree.getroot()
        for host_el in root.findall("host"):
            ports_el = host_el.find("ports")
            if ports_el is None:
                continue
            for port_el in ports_el.findall("port"):
                if port_el.get("protocol") != "tcp":
                    continue
                try:
                    portid = int(port_el.get("portid"))
                except (TypeError, ValueError):
                    continue

                svc = port_el.find("service")
                if svc is None:
                    continue

                cpes = [c.text for c in svc.findall("cpe") if c.text]
                results[portid] = {
                    "name": svc.get("name") or "",
                    "product": svc.get("product") or "",
                    "version": svc.get("version") or "",
                    "extra_info": svc.get("extrainfo") or "",
                    "cpe": ";".join(cpes),
                }
        return results
