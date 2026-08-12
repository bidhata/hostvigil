"""
Stealth Host Discovery Module for HostVigil.

Implements multiple low-noise discovery techniques:
- ARP Sweep (LAN, randomized, batched)
- Passive Sniffing (zero packet generation)
- mDNS Enumeration (.local queries)
- NetBIOS Name Service (NBNS) queries
- DNS Reverse Walk (reverse lookups with heavy jitter)

All techniques respect stealth timing configuration and store
results in the SQLite database.
"""

import ipaddress
import logging
import os
import random
import shutil
import socket
import sqlite3
import struct
import subprocess
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    from scapy.all import ARP, DNS, DNSQR, IP, UDP, Ether, srp
    from scapy.all import sniff as scapy_sniff

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

logger = logging.getLogger("hostvigil.discovery")


class StealthDiscovery:
    """Stealth network host discovery engine.

    Uses multiple techniques with randomized timing and jitter
    to minimize detection footprint on the network.
    """

    # Mapping of technique names to method names
    TECHNIQUE_MAP = {
        "nmap_discover": "_nmap_discover",
        "arp_sweep": "_arp_sweep",
        "passive_sniff": "_passive_sniff",
        "mdns_enum": "_mdns_enum",
        "nbns_query": "_nbns_query",
        "dns_reverse_walk": "_dns_reverse_walk",
        "snmp_sweep": "_snmp_sweep",
        "ssdp_discover": "_ssdp_discover",
        "tcp_syn_discover": "_tcp_syn_discover",
        "dhcp_passive": "_dhcp_passive_sniff",
        "dns_custom": "_dns_custom_discover",
    }

    def __init__(self, config: dict, db_path: str):
        """Initialize stealth discovery with configuration and database path.

        Args:
            config: Full configuration dictionary (top-level 'hostvigil' key expected).
            db_path: Path to the SQLite database file.
        """
        # Extract relevant config sections
        hv_config = config.get("hostvigil", config)
        self._stealth_cfg = hv_config.get("stealth", {})
        self._discovery_cfg = hv_config.get("discovery", {})

        # Stealth timing parameters
        self._min_delay = self._stealth_cfg.get("min_delay", 10.0)
        self._max_delay = self._stealth_cfg.get("max_delay", 45.0)
        self._jitter_factor = self._stealth_cfg.get("jitter_factor", 0.3)
        self._max_threads = self._stealth_cfg.get("max_threads", 3)

        # Discovery parameters
        self._target_ranges = self._discovery_cfg.get("target_ranges", ["192.168.0.0/16"])
        self._techniques = self._discovery_cfg.get("techniques", list(self.TECHNIQUE_MAP.keys()))
        self._sniff_duration = self._discovery_cfg.get("passive_sniff_duration", 300)
        self._arp_batch_size = self._discovery_cfg.get("arp_batch_size", 16)
        self._arp_batch_delay = self._discovery_cfg.get("arp_batch_delay", 5.0)

        # nmap host-discovery parameters (used by the 'nmap_discover' technique)
        self._nmap_timing = str(self._discovery_cfg.get("nmap_timing", "T2"))
        self._nmap_host_timeout = str(self._discovery_cfg.get("nmap_host_timeout", "") or "")
        self._nmap_scan_timeout = int(self._discovery_cfg.get("nmap_scan_timeout", 1800))
        _raw_extra_args = self._discovery_cfg.get("nmap_extra_args", [])
        if isinstance(_raw_extra_args, str):
            # Handle case where config provides a single string instead of a list
            self._nmap_extra_args = _raw_extra_args.split()
        elif isinstance(_raw_extra_args, list):
            self._nmap_extra_args = [str(a) for a in _raw_extra_args]
        else:
            self._nmap_extra_args = []
        # Force ICMP/TCP ping instead of ARP. Left False for portability; the
        # technique auto-enables it as a fallback if nmap crashes (7.80/Windows).
        self._nmap_disable_arp_ping = bool(self._discovery_cfg.get("nmap_disable_arp_ping", False))
        # Skip IPv4 ranges larger than this (prefix smaller than) to avoid
        # accidentally launching an nmap sweep across millions of addresses.
        self._nmap_min_prefix = int(self._discovery_cfg.get("nmap_min_prefix", 16))
        # Maximum number of /16 chunks to scan in a single nmap discovery call.
        self._nmap_max_chunks = int(self._discovery_cfg.get("nmap_max_chunks", 256))
        # Parallel nmap processes for chunked scans
        self._nmap_parallel = int(self._discovery_cfg.get("nmap_parallel_chunks", 4))

        # SNMP configuration
        self._snmp_communities = list(self._discovery_cfg.get("snmp_communities", ["public", "private"]))
        self._snmp_delay = float(self._discovery_cfg.get("snmp_delay", 45.0))

        # Custom DNS discovery configuration
        self._dns_custom_server = str(self._discovery_cfg.get("dns_custom_server", "") or "")
        self._dns_custom_domain = str(self._discovery_cfg.get("dns_custom_domain", "") or "")
        self._dns_custom_timeout = float(self._discovery_cfg.get("dns_custom_timeout", 3.0))

        # Database
        self._db_path = str(db_path)
        self._db_lock = threading.Lock()
        self._ensure_db()

        # Thread safety for discovered hosts list
        self._results_lock = threading.Lock()

        self._max_hosts = int(config.get("max_hosts", 0)) or 0
        self._host_count = 0

        # Auto-detect local subnets and prioritize them
        self._target_ranges = self._prioritize_local_subnets(self._target_ranges)

        logger.info("StealthDiscovery initialized: techniques=%s, targets=%s", self._techniques, self._target_ranges)

    def _ensure_db(self) -> None:
        """Ensure the database and hosts table exist."""
        db_path = Path(self._db_path)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self._db_path) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS hosts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT NOT NULL UNIQUE,
                    mac TEXT,
                    hostname TEXT,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    discovery_method TEXT,
                    is_active INTEGER NOT NULL DEFAULT 1
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_hosts_active ON hosts(is_active)")
            conn.commit()

    # ------------------------------------------------------------------
    # Auto-detect Local Network
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_local_subnets() -> List[str]:
        """Detect the system's local IP addresses and derive their /24 subnets.

        Returns a list of CIDR strings (e.g., ['192.168.1.0/24', '10.0.5.0/24']).
        Skips loopback, link-local, and virtual/docker interfaces where possible.
        """
        local_subnets = []
        try:
            # Method 1: Use socket to get all interface addresses (cross-platform)
            import socket as _socket

            # Get all IPs via connecting to external (doesn't send traffic)
            # This gives the primary interface IP
            try:
                s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
                try:
                    s.settimeout(0.1)
                    # Connect to a non-routable address to determine primary interface
                    s.connect(("10.255.255.255", 1))
                    primary_ip = s.getsockname()[0]
                finally:
                    s.close()
                if primary_ip and not primary_ip.startswith("127."):
                    net = ipaddress.ip_network(f"{primary_ip}/24", strict=False)
                    local_subnets.append(str(net))
            except Exception:
                pass

            # Method 2: Use psutil if available for full interface enumeration
            try:
                import psutil

                for iface_name, addrs in psutil.net_if_addrs().items():
                    # Skip common virtual interface names
                    skip_names = ("lo", "loopback", "docker", "veth", "br-", "virbr")
                    if any(iface_name.lower().startswith(s) for s in skip_names):
                        continue
                    for addr in addrs:
                        if addr.family == _socket.AF_INET:
                            ip = addr.address
                            netmask = addr.netmask
                            if ip.startswith("127.") or ip.startswith("169.254."):
                                continue
                            try:
                                if netmask:
                                    net = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                                else:
                                    net = ipaddress.IPv4Network(f"{ip}/24", strict=False)
                                subnet_str = str(net)
                                if subnet_str not in local_subnets:
                                    local_subnets.append(subnet_str)
                            except (ValueError, TypeError):
                                pass
            except ImportError:
                pass

            # Method 3: Fallback — parse ipconfig/ifconfig output
            if not local_subnets:
                import platform
                import subprocess as _sp

                try:
                    if platform.system() == "Windows":
                        output = _sp.check_output(["ipconfig"], text=True, timeout=5)
                        lines = output.split("\n")
                        for _i, line in enumerate(lines):
                            if "IPv4 Address" in line or "IPv4" in line:
                                parts = line.split(":")
                                if len(parts) >= 2:
                                    ip = parts[-1].strip()
                                    if ip and not ip.startswith("127."):
                                        net = ipaddress.ip_network(f"{ip}/24", strict=False)
                                        subnet_str = str(net)
                                        if subnet_str not in local_subnets:
                                            local_subnets.append(subnet_str)
                    else:
                        output = _sp.check_output(["ip", "-4", "addr", "show"], text=True, timeout=5)
                        for line in output.split("\n"):
                            if "inet " in line and "127." not in line:
                                # Extract CIDR e.g. "inet 192.168.1.5/24"
                                parts = line.strip().split()
                                for p in parts:
                                    if "/" in p and "." in p:
                                        try:
                                            net = ipaddress.ip_network(p, strict=False)
                                            subnet_str = str(net)
                                            if subnet_str not in local_subnets:
                                                local_subnets.append(subnet_str)
                                        except ValueError:
                                            pass
                except Exception:
                    pass

        except Exception as e:
            logger.warning(f"Failed to auto-detect local subnets: {e}")

        return local_subnets

    def _prioritize_local_subnets(self, target_ranges: List[str]) -> List[str]:
        """Reorder target_ranges to scan local subnets first.

        Detects the system's own IP subnets, adds them to the front of
        the target list, then appends remaining configured ranges.
        This ensures the host's own network is scanned immediately on startup.
        """
        local_subnets = self._detect_local_subnets()

        if not local_subnets:
            logger.info("Could not detect local subnets, using config order")
            return target_ranges

        logger.info("Auto-detected local subnets: %s (will scan first)", local_subnets)

        # Build prioritized list: local subnets first, then everything else
        prioritized = list(local_subnets)
        for r in target_ranges:
            # Check if already covered by a local subnet
            try:
                target_net = ipaddress.ip_network(r, strict=False)
                already_covered = False
                for local in local_subnets:
                    local_net = ipaddress.ip_network(local, strict=False)
                    if target_net.subnet_of(local_net) or target_net == local_net:
                        already_covered = True
                        break
                if not already_covered and r not in prioritized:
                    prioritized.append(r)
            except (ValueError, TypeError):
                if r not in prioritized:
                    prioritized.append(r)

        # Deduplicate: remove ranges that are subnets of other ranges in the list
        final = []
        for net_str in prioritized:
            try:
                net = ipaddress.ip_network(net_str, strict=False)
                is_covered = any(
                    net != other and net.subnet_of(other)
                    for other_str in prioritized
                    if other_str != net_str
                    for other in [ipaddress.ip_network(other_str, strict=False)]
                )
                if not is_covered:
                    final.append(net_str)
            except (ValueError, TypeError):
                final.append(net_str)
        prioritized = final

        return prioritized

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run_discovery(self, techniques: List[str] = None) -> Dict:
        """Run specified discovery techniques and return found hosts.

        Args:
            techniques: List of technique names to run. If None, uses config.

        Returns:
            List of dicts with keys: ip, mac, hostname, discovery_method
        """
        active_techniques = techniques or self._techniques
        self._host_count = 0

        logger.info("Starting discovery run with techniques: %s", active_techniques)

        for technique_name in active_techniques:
            if technique_name not in self.TECHNIQUE_MAP:
                logger.warning("Unknown technique '%s', skipping", technique_name)
                continue

            method_name = self.TECHNIQUE_MAP[technique_name]
            method = getattr(self, method_name, None)
            if method is None:
                logger.error("Method %s not found", method_name)
                continue

            try:
                logger.info("Running technique: %s", technique_name)
                if technique_name == "passive_sniff":
                    hosts = method(self._sniff_duration)
                elif technique_name in ("mdns_enum", "ssdp_discover", "dhcp_passive"):
                    hosts = method()
                else:
                    # Techniques that iterate over target ranges
                    hosts = []
                    # Filter out IPv6 ranges — only IPv4 is supported.
                    ipv4_ranges = []
                    for r in self._target_ranges:
                        try:
                            net = ipaddress.ip_network(r, strict=False)
                            if net.version == 4:
                                ipv4_ranges.append(r)
                        except ValueError:
                            logger.warning("Skipping invalid target range: %s", r)
                    for target_range in ipv4_ranges:
                        found = method(target_range)
                        hosts.extend(found)
                        # Inter-range delay
                        time.sleep(self._apply_jitter(self._min_delay / 2))

                if hosts:
                    self._store_hosts_batch(hosts, method=technique_name)
                    with self._results_lock:
                        self._host_count += len(hosts)

                logger.info("Technique '%s' found %d hosts", technique_name, len(hosts))
            except Exception as exc:
                logger.error("Technique '%s' failed: %s", technique_name, exc, exc_info=True)

            if self._max_hosts > 0 and self._host_count >= self._max_hosts:
                logger.warning(
                    "Discovery max_hosts cap (%d) reached — stopping further techniques",
                    self._max_hosts,
                )
                break

            # Delay between techniques
            time.sleep(self._apply_jitter(self._min_delay))

        logger.info("Discovery run complete. Total hosts found: %d", self._host_count)
        return {"hosts_found": self._host_count, "capped": self._max_hosts > 0 and self._host_count >= self._max_hosts}

    # ------------------------------------------------------------------
    # Nmap Host Discovery (first-pass, works without scapy)
    # ------------------------------------------------------------------

    def _nmap_discover(self, target_range: str) -> List[Dict]:
        """Host discovery using an external nmap ping scan (``nmap -sn``).

        This is intended as the *first* discovery pass: nmap performs ARP
        discovery on local segments (via Npcap/libdnet) and ICMP/TCP/UDP
        pings elsewhere, so it reliably finds live hosts even when scapy is
        unavailable. No port scan is performed here (``-sn``); port scanning
        remains the scanner module's responsibility.

        Args:
            target_range: CIDR notation network (e.g. '192.168.1.0/24').

        Returns:
            List of discovered host dicts with keys: ip, mac, hostname,
            discovery_method.
        """
        nmap_path = shutil.which("nmap")
        if not nmap_path:
            logger.warning("nmap not found in PATH - skipping nmap discovery")
            return []

        # Validate the target range and guard against oversized sweeps.
        try:
            network = ipaddress.ip_network(target_range, strict=False)
        except ValueError as exc:
            logger.error("Invalid target range '%s': %s", target_range, exc)
            return []

        if network.version == 6:
            # IPv6 scanning is not supported.
            logger.info("Skipping IPv6 range %s (not supported)", target_range)
            return []

        # For large networks (prefix < chunk_prefix), split into smaller
        # subnets so each nmap subprocess finishes within the timeout.
        # A /16 = 65K hosts ≈ 13s at --min-rate 5000; safe margin.
        #
        # nmap_min_prefix guards against accidental mega-runs: ranges larger
        # than /nmap_min_prefix are chunked into /nmap_min_prefix pieces.
        # If the chunk count would exceed nmap_max_chunks, we refuse loudly
        # rather than silently scanning only part of the target range.
        chunk_prefix = 16
        if network.prefixlen < self._nmap_min_prefix:
            # Auto-chunk large networks into scannable /min_prefix subnets
            logger.info(
                "Auto-chunking %s into /%d subnets for nmap discovery",
                target_range,
                self._nmap_min_prefix,
            )
            all_hosts: List[Dict] = []
            subnets = list(network.subnets(new_prefix=self._nmap_min_prefix))
            random.shuffle(subnets)
            if len(subnets) > self._nmap_max_chunks:
                logger.error(
                    "nmap discovery: %s would require %d chunks but nmap_max_chunks=%d. "
                    "Refusing to silently skip part of the target range. "
                    "Raise nmap_max_chunks or narrow target_ranges.",
                    target_range,
                    len(subnets),
                    self._nmap_max_chunks,
                )
                return []

            # Run chunks in parallel for speed (each is an independent nmap process)
            workers = min(self._nmap_parallel, len(subnets))
            logger.info(
                "nmap discovery: scanning %d chunks with %d parallel workers",
                len(subnets),
                workers,
            )

            def _scan_chunk(subnet):
                return self._nmap_discover_single(nmap_path, str(subnet), store_db=False)

            from concurrent.futures import as_completed

            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = {executor.submit(_scan_chunk, s): s for s in subnets}
                for future in as_completed(futures):
                    try:
                        chunk_hosts = future.result()
                        if chunk_hosts:
                            all_hosts.extend(chunk_hosts)
                            self._store_hosts_batch(chunk_hosts, method="nmap_discover")
                            logger.info(
                                "nmap chunk %s: %d hosts",
                                futures[future],
                                len(chunk_hosts),
                            )
                    except Exception as exc:
                        logger.error("nmap chunk %s failed: %s", futures[future], exc)
            logger.info(
                "nmap discovery found %d total live hosts in %s (%d chunks)",
                len(all_hosts),
                target_range,
                len(subnets),
            )
            return all_hosts

        if network.prefixlen < chunk_prefix:
            logger.info(
                "Chunking %s into /%d subnets for nmap discovery",
                target_range,
                chunk_prefix,
            )
            all_hosts: List[Dict] = []
            subnets = list(network.subnets(new_prefix=chunk_prefix))
            random.shuffle(subnets)  # Randomize order for stealth
            if len(subnets) > self._nmap_max_chunks:
                logger.error(
                    "nmap discovery: %s would require %d chunks but nmap_max_chunks=%d. "
                    "Refusing to silently skip part of the target range. "
                    "Raise nmap_max_chunks or narrow target_ranges.",
                    target_range,
                    len(subnets),
                    self._nmap_max_chunks,
                )
                return []

            # Run chunks in parallel for speed (each is an independent nmap process)
            workers = min(self._nmap_parallel, len(subnets))
            logger.info(
                "nmap discovery: scanning %d chunks with %d parallel workers",
                len(subnets),
                workers,
            )

            def _scan_chunk(subnet):
                # Don't write to DB from worker threads — collect results only
                return self._nmap_discover_single(nmap_path, str(subnet), store_db=False)

            from concurrent.futures import as_completed

            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = {executor.submit(_scan_chunk, s): s for s in subnets}
                for future in as_completed(futures):
                    try:
                        chunk_hosts = future.result()
                        if chunk_hosts:
                            all_hosts.extend(chunk_hosts)
                            # Store progressively — results appear in dashboard immediately
                            self._store_hosts_batch(chunk_hosts, method="nmap_discover")
                            logger.info(
                                "nmap chunk %s: %d hosts",
                                futures[future],
                                len(chunk_hosts),
                            )
                    except Exception as exc:
                        logger.error("nmap chunk %s failed: %s", futures[future], exc)
            logger.info(
                "nmap discovery found %d total live hosts in %s (%d chunks)",
                len(all_hosts),
                target_range,
                len(subnets),
            )
            return all_hosts

        return self._nmap_discover_single(nmap_path, target_range)

    def _nmap_discover_single(self, nmap_path: str, target_range: str, store_db: bool = True) -> List[Dict]:
        """Run nmap discovery on a single (small enough) target range.

        Handles ARP crash fallback. Optionally stores discovered hosts to DB.
        Returns list of host dicts.
        """

        # ----------------------------------------------------------------
        # Small-LAN rate guard: for /24 and smaller networks, cap nmap's
        # --min-rate and --max-rate to 300 pkt/s to prevent flooding the
        # switch and making the network inaccessible.
        # A /24 only has 254 hosts — 300 pkt/s is plenty fast (< 1s) and
        # won't overwhelm a home router or cheap managed switch.
        # ----------------------------------------------------------------
        try:
            _net = ipaddress.ip_network(target_range, strict=False)
            _is_small_lan = _net.prefixlen >= 24
        except ValueError:
            _is_small_lan = False

        def _sanitize_rate_args(args: list, max_allowed: int) -> list:
            """Cap --min-rate and --max-rate values in an arg list."""
            result = []
            i = 0
            while i < len(args):
                arg = args[i]
                if arg in ("--min-rate", "--max-rate") and i + 1 < len(args):
                    try:
                        rate = int(args[i + 1])
                        if rate > max_allowed:
                            logger.info(
                                "nmap discovery: capping %s %d → %d for small LAN (%s)",
                                arg,
                                rate,
                                max_allowed,
                                target_range,
                            )
                            rate = max_allowed
                    except (ValueError, TypeError):
                        rate = max_allowed
                    result.append(arg)
                    result.append(str(rate))
                    i += 2
                else:
                    result.append(arg)
                    i += 1
            return result

        # Base command. ARP ping (nmap's default on a local segment) gives the
        # best LAN discovery, so we try it first for portability. On
        # nmap 7.80/Windows an ARP sweep across a subnet aborts with
        # "Assertion failed: htn.toclock_running" (Target.cc:503); if we detect
        # that crash we transparently retry with --disable-arp-ping, which uses
        # ICMP/TCP ping probes instead and does not trip the bug.
        base_flags = ["-sn", "-" + self._nmap_timing.lstrip("-")]
        if self._nmap_host_timeout:
            # --host-timeout also triggers the same assertion on 7.80/Windows,
            # so only include it when explicitly configured.
            base_flags += ["--host-timeout", self._nmap_host_timeout]
        extra_args = list(self._nmap_extra_args)

        # Cap packet rates for small LANs (/24 or smaller) to avoid flooding
        if _is_small_lan:
            extra_args = _sanitize_rate_args(extra_args, max_allowed=300)
            # Also ensure --max-rate is present (adds it if not already there)
            if "--max-rate" not in extra_args:
                extra_args += ["--max-rate", "300"]

        base_flags += extra_args

        attempts = []
        if self._nmap_disable_arp_ping:
            attempts.append(base_flags + ["--disable-arp-ping"])
        else:
            attempts.append(base_flags)
            attempts.append(base_flags + ["--disable-arp-ping"])  # crash fallback

        hosts: List[Dict] = []
        for idx, flags in enumerate(attempts):
            rc, stderr, parsed_hosts = self._run_nmap(nmap_path, flags, target_range)
            crashed = self._nmap_crashed(rc, stderr)
            if crashed and idx + 1 < len(attempts):
                logger.warning(
                    "nmap aborted (likely nmap 7.80/Windows ARP assertion) for %s; retrying with --disable-arp-ping",
                    target_range,
                )
                continue
            if rc != 0:
                logger.warning(
                    "nmap exited with code %d for %s: %s",
                    rc,
                    target_range,
                    (stderr or "").strip()[:300],
                )
            hosts = parsed_hosts
            break

        self._store_hosts_batch(hosts, method="nmap_discover") if store_db else None
        logger.info(
            "nmap discovery found %d live hosts in %s",
            len(hosts),
            target_range,
        )
        return hosts

    @staticmethod
    def _nmap_crashed(returncode: int, stderr: str) -> bool:
        """Detect the nmap 7.80/Windows abort (assertion / access violation).

        Specifically excludes timeouts (rc == -1) which are not crashes.
        """
        if returncode == -1:
            return False  # Timeout, not a crash
        if "Assertion failed" in (stderr or ""):
            return True
        # Windows abort()/assertion surfaces as 0xC0000409 (3221226505) or
        # other 0xC000xxxx NTSTATUS codes; treat those as a crash.
        return returncode is not None and (returncode & 0xFFFFFFFF) >= 0xC0000000

    def _run_nmap(self, nmap_path: str, flags: List[str], target_range: str) -> Tuple[int, str, List[Dict]]:
        """Run one nmap invocation and parse its XML output.

        Returns (returncode, stderr, hosts). Hosts is the list of parsed
        host dicts from the nmap XML output.
        """
        hosts: List[Dict] = []
        tmp_xml = None
        try:
            fd, tmp_xml = tempfile.mkstemp(prefix="hv_nmap_", suffix=".xml")
            os.close(fd)

            cmd = [nmap_path] + [str(f) for f in flags] + ["-oX", tmp_xml, str(target_range)]
            logger.info("nmap discovery: %s", " ".join(cmd))
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                stdout, stderr = proc.communicate(timeout=self._nmap_scan_timeout)
            except subprocess.TimeoutExpired:
                # Kill nmap but still parse partial XML (nmap writes results
                # incrementally, so timed-out scans may have found some hosts).
                proc.kill()
                proc.communicate()
                hosts = self._parse_nmap_xml(tmp_xml)
                logger.warning(
                    "nmap discovery timed out after %ds for %s (partial results: %d hosts recovered)",
                    self._nmap_scan_timeout,
                    target_range,
                    len(hosts),
                )
                return -1, "timeout", hosts
            except Exception:
                # Ensure nmap doesn't become an orphan on unexpected errors
                if proc.poll() is None:
                    proc.kill()
                    proc.communicate()
                raise
            hosts = self._parse_nmap_xml(tmp_xml)
            return proc.returncode, stderr or "", hosts
        finally:
            if tmp_xml:
                try:
                    Path(tmp_xml).unlink(missing_ok=True)
                except Exception:
                    pass

    def _parse_nmap_xml(self, xml_path: str) -> List[Dict]:
        """Parse an nmap XML output file into a list of live-host dicts.

        Args:
            xml_path: Path to the nmap ``-oX`` output file.

        Returns:
            List of host dicts (ip, mac, hostname, discovery_method) for
            every host nmap reported as ``up``.
        """
        results: List[Dict] = []
        try:
            tree = ET.parse(xml_path)
        except (ET.ParseError, FileNotFoundError, OSError) as exc:
            logger.error("Failed to parse nmap XML '%s': %s", xml_path, exc)
            return results

        root = tree.getroot()
        for host_el in root.findall("host"):
            status = host_el.find("status")
            if status is None or status.get("state") != "up":
                continue

            ip = None
            mac = None
            for addr in host_el.findall("address"):
                addr_type = addr.get("addrtype")
                if addr_type in ("ipv4", "ipv6") and ip is None:
                    ip = addr.get("addr")
                elif addr_type == "mac":
                    mac = addr.get("addr")

            if not ip:
                continue

            hostname = None
            hostnames_el = host_el.find("hostnames")
            if hostnames_el is not None:
                hn = hostnames_el.find("hostname")
                if hn is not None:
                    hostname = hn.get("name")

            results.append(
                {
                    "ip": ip,
                    "mac": mac,
                    "hostname": hostname,
                    "discovery_method": "nmap_discover",
                }
            )

        return results

    # ------------------------------------------------------------------
    # Custom DNS Discovery (Internal DNS server)
    # ------------------------------------------------------------------

    def _dns_custom_discover(self, target_range: str) -> List[Dict]:
        """Discover hosts via reverse PTR lookups using a custom internal DNS server.

        Uses the configured ``dns_custom_server`` to perform reverse DNS
        lookups across the target range. This is useful when an internal
        DNS server has PTR records for hosts that don't respond to probes.

        Also attempts a zone transfer (AXFR) if ``dns_custom_domain`` is set.

        Args:
            target_range: CIDR notation network.

        Returns:
            List of discovered host dicts.
        """
        if not self._dns_custom_server:
            logger.info("dns_custom: no dns_custom_server configured - skipping")
            return []

        hosts: List[Dict] = []

        # Attempt zone transfer first (if domain is configured)
        if self._dns_custom_domain:
            axfr_hosts = self._dns_zone_transfer(self._dns_custom_server, self._dns_custom_domain)
            hosts.extend(axfr_hosts)

        # Reverse PTR lookups across the target range
        try:
            network = ipaddress.ip_network(target_range, strict=False)
        except ValueError:
            return hosts

        if network.version == 6:
            return hosts

        # Cap at /16 for PTR walks to prevent excessively long runs
        if network.prefixlen < 16:
            logger.info(
                "dns_custom: %s too large for PTR walk (< /16), skipping reverse lookups",
                target_range,
            )
            return hosts

        targets = [str(ip) for ip in network.hosts()]
        random.shuffle(targets)

        logger.info(
            "dns_custom: PTR lookup on %d hosts via DNS server %s",
            len(targets),
            self._dns_custom_server,
        )

        for ip_str in targets:
            hostname = self._dns_ptr_query(ip_str, self._dns_custom_server)
            if hostname:
                host_info = {
                    "ip": ip_str,
                    "mac": None,
                    "hostname": hostname,
                    "discovery_method": "dns_custom",
                }
                hosts.append(host_info)
                self._store_host(ip=ip_str, hostname=hostname, method="dns_custom")
            # Stealth delay between queries
            time.sleep(self._apply_jitter(0.5))

        logger.info("dns_custom: found %d hosts in %s", len(hosts), target_range)
        return hosts

    def _dns_ptr_query(self, ip: str, dns_server: str) -> Optional[str]:
        """Send a single PTR query to the custom DNS server.

        Args:
            ip: IP address to look up.
            dns_server: DNS server to query.

        Returns:
            Hostname string if resolved, else None.
        """
        try:
            rev_name = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
            query_id = random.randint(0, 65535)

            # Build DNS query packet (PTR type=12, class IN=1)
            packet = struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
            for label in rev_name.split("."):
                packet += struct.pack("B", len(label)) + label.encode()
            packet += b"\x00"
            packet += struct.pack(">HH", 12, 1)  # PTR, IN

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self._dns_custom_timeout)
            try:
                sock.sendto(packet, (dns_server, 53))
                response = sock.recv(1024)
            finally:
                sock.close()

            # Parse: check answer count
            if len(response) > 12:
                answer_count = struct.unpack(">H", response[6:8])[0]
                if answer_count > 0:
                    return self._parse_ptr_response(response)
        except (socket.timeout, OSError):
            pass
        except Exception as exc:
            logger.debug("dns_custom PTR query failed for %s: %s", ip, exc)
        return None

    def _parse_ptr_response(self, response: bytes) -> Optional[str]:
        """Parse a DNS PTR response to extract the hostname.

        Args:
            response: Raw DNS response bytes.

        Returns:
            Hostname string or None.
        """
        try:
            # Skip header (12 bytes) + question section
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

            # Parse first answer
            if offset >= len(response):
                return None

            # Skip answer name (may be compressed)
            if response[offset] & 0xC0 == 0xC0:
                offset += 2
            else:
                while offset < len(response) and response[offset] != 0:
                    offset += response[offset] + 1
                offset += 1

            if offset + 10 > len(response):
                return None

            # Read TYPE, CLASS, TTL, RDLENGTH
            rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", response[offset : offset + 10])
            offset += 10

            if rtype != 12:  # Not PTR
                return None

            # Parse PTR domain name from RDATA
            hostname_parts = []
            end = offset + rdlength
            while offset < end and offset < len(response):
                if response[offset] & 0xC0 == 0xC0:
                    # Compressed pointer
                    ptr_offset = struct.unpack(">H", response[offset : offset + 2])[0] & 0x3FFF
                    # Follow pointer (one level only)
                    while ptr_offset < len(response) and response[ptr_offset] != 0:
                        if response[ptr_offset] & 0xC0 == 0xC0:
                            break
                        length = response[ptr_offset]
                        hostname_parts.append(
                            response[ptr_offset + 1 : ptr_offset + 1 + length].decode("ascii", errors="ignore")
                        )
                        ptr_offset += length + 1
                    break
                elif response[offset] == 0:
                    break
                else:
                    length = response[offset]
                    hostname_parts.append(response[offset + 1 : offset + 1 + length].decode("ascii", errors="ignore"))
                    offset += length + 1

            return ".".join(hostname_parts) if hostname_parts else None
        except Exception:
            return None

    def _dns_zone_transfer(self, dns_server: str, domain: str) -> List[Dict]:
        """Attempt an AXFR zone transfer from the DNS server.

        Args:
            dns_server: DNS server IP.
            domain: Domain to transfer.

        Returns:
            List of host dicts found in the zone.
        """
        hosts: List[Dict] = []
        try:
            # Build AXFR query (TCP)
            query_id = random.randint(0, 65535)
            packet = struct.pack(">HHHHHH", query_id, 0x0000, 1, 0, 0, 0)
            for label in domain.split("."):
                packet += struct.pack("B", len(label)) + label.encode()
            packet += b"\x00"
            packet += struct.pack(">HH", 252, 1)  # AXFR=252, IN=1

            # AXFR uses TCP — prepend 2-byte length
            tcp_packet = struct.pack(">H", len(packet)) + packet

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect((dns_server, 53))
                sock.sendall(tcp_packet)

                # Read response
                data = b""
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if len(data) > 65536:  # Safety cap
                        break
            finally:
                sock.close()

            # Parse A records from zone transfer response (simplified)
            # Look for A record patterns (type=1) in the response
            if len(data) > 14:
                # Skip TCP length prefix (2) + DNS header (12)
                # This is a simplified parser; zone transfers are complex
                # Log success and extract what we can
                logger.info(
                    "dns_custom: zone transfer from %s for %s returned %d bytes",
                    dns_server,
                    domain,
                    len(data),
                )

                # Parse using basic heuristic: find IPv4 addresses in RDATA
                # A proper implementation would walk the full DNS message format
                import re

                # Look for 4-byte sequences that look like A record RDATA
                text_data = data.decode("latin-1")
                # Find hostnames followed by A records
                ip_pattern = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
                seen_ips = set()
                for match in ip_pattern.finditer(text_data):
                    ip_str = match.group(1)
                    if ip_str in seen_ips:
                        continue
                    try:
                        ip_obj = ipaddress.ip_address(ip_str)
                        if ip_obj.is_private and not ip_obj.is_loopback:
                            # Verify the IP falls within configured target ranges
                            if not any(
                                ip_obj in ipaddress.ip_network(r, strict=False)
                                for r in self._target_ranges
                                if ":" not in r
                            ):
                                continue
                            seen_ips.add(ip_str)
                            host_info = {
                                "ip": ip_str,
                                "mac": None,
                                "hostname": None,
                                "discovery_method": "dns_custom",
                            }
                            hosts.append(host_info)
                            self._store_host(ip=ip_str, method="dns_custom")
                    except ValueError:
                        continue

        except (socket.timeout, ConnectionRefusedError, OSError) as exc:
            logger.info("dns_custom: zone transfer failed for %s: %s", domain, exc)
        except Exception as exc:
            logger.error("dns_custom: zone transfer error: %s", exc)

        if hosts:
            logger.info("dns_custom: zone transfer found %d hosts", len(hosts))
        return hosts

    # ------------------------------------------------------------------
    # ARP Sweep (LAN Only)
    # ------------------------------------------------------------------

    def _arp_sweep(self, target_range: str) -> List[Dict]:
        """Slow ARP sweep with batching, randomized ordering, and delays.

        Only works on local network segments. Requires scapy.

        Args:
            target_range: CIDR notation network (e.g., '192.168.1.0/24')

        Returns:
            List of discovered host dicts.
        """
        if not SCAPY_AVAILABLE:
            logger.warning("ARP sweep requires scapy - skipping")
            return []

        hosts: List[Dict] = []

        try:
            network = ipaddress.ip_network(target_range, strict=False)
        except ValueError as exc:
            logger.error("Invalid target range '%s': %s", target_range, exc)
            return []

        # Only run on reasonably sized local networks
        if network.prefixlen < 16:
            logger.info("Network %s too large for ARP sweep (prefix < /16), skipping", target_range)
            return []

        # Build randomized target list
        targets = [str(ip) for ip in network.hosts()]
        random.shuffle(targets)

        logger.info("ARP sweep: %d targets in %s (batch_size=%d)", len(targets), target_range, self._arp_batch_size)

        # Process in batches
        for batch_start in range(0, len(targets), self._arp_batch_size):
            batch = targets[batch_start : batch_start + self._arp_batch_size]

            for target_ip in batch:
                try:
                    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip)
                    answered, _ = srp(pkt, timeout=2, verbose=0, retry=0)

                    for _sent, received in answered:
                        host_info = {
                            "ip": received.psrc,
                            "mac": received.hwsrc,
                            "hostname": None,
                            "discovery_method": "arp_sweep",
                        }
                        hosts.append(host_info)
                        self._store_host(ip=received.psrc, mac=received.hwsrc, hostname=None, method="arp_sweep")
                        logger.debug("ARP: found %s (%s)", received.psrc, received.hwsrc)

                except Exception as exc:
                    logger.debug("ARP probe to %s failed: %s", target_ip, exc)

                # Inter-probe delay with jitter
                time.sleep(self._apply_jitter(self._min_delay / 4))

            # Batch delay
            batch_delay = self._apply_jitter(self._arp_batch_delay)
            logger.debug("ARP batch complete, sleeping %.2fs", batch_delay)
            time.sleep(batch_delay)

        return hosts

    # ------------------------------------------------------------------
    # Passive Sniffing (Zero Packet Generation)
    # ------------------------------------------------------------------

    def _passive_sniff(self, duration: int) -> List[Dict]:
        """Listen passively on the network interface for host activity.

        Does NOT generate any packets. Discovers hosts by observing
        existing traffic on the wire.

        Args:
            duration: Number of seconds to sniff.

        Returns:
            List of discovered host dicts.
        """
        if not SCAPY_AVAILABLE:
            logger.warning("Passive sniffing requires scapy - skipping")
            return []

        discovered: Dict[str, Dict] = {}
        discovered_lock = threading.Lock()

        def _packet_handler(pkt):
            """Process each captured packet to extract host information."""
            if not pkt.haslayer(IP):
                return

            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            # Only track private/local IPs
            for ip_addr in (src_ip, dst_ip):
                try:
                    if not ipaddress.ip_address(ip_addr).is_private:
                        continue
                    if ipaddress.ip_address(ip_addr).is_loopback:
                        continue
                except ValueError:
                    continue

                with discovered_lock:
                    if ip_addr not in discovered:
                        # Try to get MAC from Ether layer
                        mac = None
                        if pkt.haslayer(Ether):
                            if ip_addr == src_ip:
                                mac = pkt[Ether].src
                            elif ip_addr == dst_ip:
                                mac = pkt[Ether].dst
                            # Skip broadcast MACs
                            if mac and mac.lower() == "ff:ff:ff:ff:ff:ff":
                                mac = None

                        discovered[ip_addr] = {
                            "ip": ip_addr,
                            "mac": mac,
                            "hostname": None,
                            "discovery_method": "passive_sniff",
                        }

        logger.info("Passive sniffing for %d seconds...", duration)

        try:
            scapy_sniff(
                prn=_packet_handler,
                timeout=duration,
                store=0,  # Don't store packets in memory
                quiet=True,
            )
        except Exception as exc:
            logger.error("Passive sniff error: %s", exc, exc_info=True)

        # Store all discovered hosts
        hosts = list(discovered.values())
        for host in hosts:
            self._store_host(ip=host["ip"], mac=host.get("mac"), hostname=None, method="passive_sniff")

        logger.info("Passive sniff discovered %d unique hosts", len(hosts))
        return hosts

    # ------------------------------------------------------------------
    # mDNS Enumeration
    # ------------------------------------------------------------------

    def _mdns_enum(self) -> List[Dict]:
        """Discover hosts via mDNS (multicast DNS) on .local domain.

        Sends mDNS queries to the multicast group 224.0.0.251:5353
        to discover devices advertising .local services.

        Returns:
            List of discovered host dicts.
        """
        hosts: List[Dict] = []
        MDNS_ADDR = "224.0.0.251"
        MDNS_PORT = 5353

        # Common mDNS service types to query
        service_types = [
            "_http._tcp.local",
            "_https._tcp.local",
            "_smb._tcp.local",
            "_ssh._tcp.local",
            "_printer._tcp.local",
            "_ipp._tcp.local",
            "_workstation._tcp.local",
            "_device-info._tcp.local",
            "_services._dns-sd._udp.local",
        ]

        random.shuffle(service_types)

        if SCAPY_AVAILABLE:
            hosts = self._mdns_enum_scapy(MDNS_ADDR, MDNS_PORT, service_types)
        else:
            hosts = self._mdns_enum_socket(MDNS_ADDR, MDNS_PORT, service_types)

        return hosts

    def _mdns_enum_scapy(self, mdns_addr: str, mdns_port: int, service_types: List[str]) -> List[Dict]:
        """mDNS enumeration using scapy."""
        hosts: List[Dict] = []
        discovered_ips: set = set()

        for service in service_types:
            try:
                # Build mDNS query packet
                pkt = (
                    IP(dst=mdns_addr, ttl=1)
                    / UDP(sport=mdns_port, dport=mdns_port)
                    / DNS(rd=0, qd=DNSQR(qname=service, qtype="PTR", qclass="IN"))
                )

                # Send and capture response
                from scapy.all import sr1

                resp = sr1(pkt, timeout=3, verbose=0)

                if resp and resp.haslayer(DNS):
                    src_ip = resp[IP].src
                    if src_ip not in discovered_ips:
                        discovered_ips.add(src_ip)
                        hostname = None
                        if resp[DNS].ancount and resp[DNS].an:
                            try:
                                hostname = resp[DNS].an.rdata.decode("utf-8", errors="ignore")
                            except (AttributeError, UnicodeDecodeError):
                                pass

                        host_info = {
                            "ip": src_ip,
                            "mac": None,
                            "hostname": hostname,
                            "discovery_method": "mdns_enum",
                        }
                        hosts.append(host_info)
                        self._store_host(ip=src_ip, hostname=hostname, method="mdns_enum")
                        logger.debug("mDNS: found %s (%s)", src_ip, hostname)

            except Exception as exc:
                logger.debug("mDNS query for '%s' failed: %s", service, exc)

            # Stealth delay between queries
            time.sleep(self._apply_jitter(self._min_delay / 3))

        return hosts

    def _mdns_enum_socket(self, mdns_addr: str, mdns_port: int, service_types: List[str]) -> List[Dict]:
        """mDNS enumeration using raw sockets (fallback)."""
        hosts: List[Dict] = []
        discovered_ips: set = set()

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(3.0)

            # Join multicast group
            mreq = struct.pack("4sL", socket.inet_aton(mdns_addr), socket.INADDR_ANY)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            sock.bind(("", mdns_port))

            try:
                for service in service_types:
                    try:
                        # Build minimal DNS query
                        query = self._build_dns_query(service, qtype=12)  # PTR
                        sock.sendto(query, (mdns_addr, mdns_port))

                        # Listen for responses
                        deadline = time.time() + 3.0
                        while time.time() < deadline:
                            try:
                                data, addr = sock.recvfrom(4096)
                                src_ip = addr[0]
                                if src_ip not in discovered_ips:
                                    discovered_ips.add(src_ip)
                                    host_info = {
                                        "ip": src_ip,
                                        "mac": None,
                                        "hostname": None,
                                        "discovery_method": "mdns_enum",
                                    }
                                    hosts.append(host_info)
                                    self._store_host(ip=src_ip, method="mdns_enum")
                                    logger.debug("mDNS (socket): found %s", src_ip)
                            except socket.timeout:
                                break

                    except Exception as exc:
                        logger.debug("mDNS socket query failed: %s", exc)

                    time.sleep(self._apply_jitter(self._min_delay / 3))
            finally:
                sock.close()
        except Exception as exc:
            logger.error("mDNS socket setup failed: %s", exc)

        return hosts

    # ------------------------------------------------------------------
    # NetBIOS Name Service (NBNS) Queries
    # ------------------------------------------------------------------

    def _nbns_query(self, target_range: str) -> List[Dict]:
        """Query NetBIOS Name Service to discover Windows hosts.

        Sends NBNS status queries (UDP port 137) with stealth timing
        to enumerate Windows machines on the network.

        Args:
            target_range: CIDR notation network.

        Returns:
            List of discovered host dicts.
        """
        hosts: List[Dict] = []

        try:
            network = ipaddress.ip_network(target_range, strict=False)
        except ValueError as exc:
            logger.error("Invalid target range '%s': %s", target_range, exc)
            return []

        # Limit scope for large networks
        if network.prefixlen < 20:
            logger.info("Network %s too large for NBNS queries (prefix < /20), skipping", target_range)
            return []

        targets = [str(ip) for ip in network.hosts()]
        random.shuffle(targets)

        NBNS_PORT = 137

        logger.info("NBNS query: %d targets in %s", len(targets), target_range)

        for target_ip in targets:
            try:
                hostname = self._nbns_status_query(target_ip, NBNS_PORT)
                if hostname:
                    host_info = {
                        "ip": target_ip,
                        "mac": None,
                        "hostname": hostname,
                        "discovery_method": "nbns_query",
                    }
                    hosts.append(host_info)
                    self._store_host(ip=target_ip, hostname=hostname, method="nbns_query")
                    logger.debug("NBNS: found %s (%s)", target_ip, hostname)

            except Exception as exc:
                logger.debug("NBNS query to %s failed: %s", target_ip, exc)

            # Heavy stealth delay between queries
            time.sleep(self._apply_jitter(self._min_delay / 2))

        return hosts

    def _nbns_status_query(self, target_ip: str, port: int = 137) -> Optional[str]:
        """Send a NetBIOS Node Status Request and parse the response.

        Args:
            target_ip: Target IP address.
            port: NBNS port (default 137).

        Returns:
            NetBIOS name if found, None otherwise.
        """
        # NetBIOS Node Status Request packet
        # Transaction ID (random)
        transaction_id = random.randint(0x0001, 0xFFFF)

        # NBSTAT query for wildcard name "*"
        # Encoded as: 0x20 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 0x00
        # which is the NetBIOS encoding of "*" padded with spaces
        nbns_query = struct.pack(">H", transaction_id)  # Transaction ID
        nbns_query += struct.pack(">H", 0x0000)  # Flags: query
        nbns_query += struct.pack(">H", 0x0001)  # Questions: 1
        nbns_query += struct.pack(">H", 0x0000)  # Answer RRs
        nbns_query += struct.pack(">H", 0x0000)  # Authority RRs
        nbns_query += struct.pack(">H", 0x0000)  # Additional RRs

        # Encoded name: CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA (wildcard *)
        nbns_query += b"\x20"  # Length: 32
        nbns_query += b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        nbns_query += b"\x00"  # Name terminator

        nbns_query += struct.pack(">H", 0x0021)  # Type: NBSTAT
        nbns_query += struct.pack(">H", 0x0001)  # Class: IN

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.settimeout(2.0)
                sock.sendto(nbns_query, (target_ip, port))

                data, _ = sock.recvfrom(1024)
            finally:
                sock.close()

            # Parse the response - extract first name entry
            if len(data) > 57:
                # Skip header (12 bytes) + query name section + answer header
                # Find the number of names in the response
                # The name count is at offset after the answer section header
                # Simplified: look for name entries starting after byte 56
                name_count = data[56] if len(data) > 56 else 0
                if name_count > 0 and len(data) > 57 + 18:
                    # First name is 15 bytes starting at offset 57
                    raw_name = data[57 : 57 + 15]
                    hostname = raw_name.decode("ascii", errors="ignore").strip()
                    if hostname and hostname.isprintable():
                        return hostname

        except (socket.timeout, socket.error, OSError):
            pass
        except Exception as exc:
            logger.debug("NBNS parse error for %s: %s", target_ip, exc)

        return None

    # ------------------------------------------------------------------
    # DNS Reverse Walk
    # ------------------------------------------------------------------

    def _dns_reverse_walk(self, target_range: str) -> List[Dict]:
        """Perform reverse DNS lookups on IP range with heavy jitter.

        Uses the system DNS resolver to perform PTR lookups. This is
        relatively passive as DNS queries are normal network activity,
        but we add heavy delays to avoid pattern detection.

        Args:
            target_range: CIDR notation network.

        Returns:
            List of discovered host dicts.
        """
        hosts: List[Dict] = []

        try:
            network = ipaddress.ip_network(target_range, strict=False)
        except ValueError as exc:
            logger.error("Invalid target range '%s': %s", target_range, exc)
            return []

        # Limit scope for large networks
        if network.prefixlen < 20:
            logger.info("Network %s too large for DNS reverse walk (prefix < /20), skipping", target_range)
            return []

        targets = [str(ip) for ip in network.hosts()]
        random.shuffle(targets)

        logger.info("DNS reverse walk: %d targets in %s", len(targets), target_range)

        for target_ip in targets:
            try:
                hostname = self._reverse_dns_lookup(target_ip)
                if hostname:
                    host_info = {
                        "ip": target_ip,
                        "mac": None,
                        "hostname": hostname,
                        "discovery_method": "dns_reverse_walk",
                    }
                    hosts.append(host_info)
                    self._store_host(ip=target_ip, hostname=hostname, method="dns_reverse_walk")
                    logger.debug("DNS reverse: %s -> %s", target_ip, hostname)

            except Exception as exc:
                logger.debug("DNS reverse lookup %s failed: %s", target_ip, exc)

            # Heavy delay - DNS reverse walk is meant to be very slow
            time.sleep(self._apply_jitter(self._max_delay / 2))

        return hosts

    def _reverse_dns_lookup(self, ip: str) -> Optional[str]:
        """Perform a single reverse DNS lookup.

        Args:
            ip: IP address to look up.

        Returns:
            Hostname if resolved, None otherwise.
        """
        try:
            result = socket.gethostbyaddr(ip)
            if result and result[0]:
                hostname = result[0]
                # Filter out generic PTR records that are just IP reformats
                ip_parts = ip.replace(".", "-")
                if ip_parts in hostname:
                    return None
                return hostname
        except (socket.herror, socket.gaierror, socket.timeout, OSError):
            pass
        return None

    # ------------------------------------------------------------------
    # Utility Methods
    # ------------------------------------------------------------------

    def _apply_jitter(self, base_delay: float) -> float:
        """Apply random jitter to a base delay value.

        The jitter is calculated as a random value within
        +/- (jitter_factor * base_delay) of the base.

        Args:
            base_delay: The base delay in seconds.

        Returns:
            Jittered delay value (always >= 0.1 seconds).
        """
        jitter_range = base_delay * self._jitter_factor
        jitter = random.uniform(-jitter_range, jitter_range)
        result = base_delay + jitter
        return max(0.1, result)

    def _store_host(self, ip: str, mac: str = None, hostname: str = None, method: str = "") -> None:
        """Store or update a discovered host in the database.

        Thread-safe. Uses INSERT OR IGNORE + UPDATE pattern to handle
        both new and previously seen hosts.

        Args:
            ip: IP address of the discovered host.
            mac: MAC address (if known).
            hostname: Hostname (if resolved).
            method: Discovery method used.
        """
        now = datetime.now(timezone.utc).isoformat()
        method = (method or "").strip()

        with self._db_lock:
            conn = None
            try:
                conn = sqlite3.connect(self._db_path)
                cursor = conn.cursor()

                # Check if host already exists
                cursor.execute("SELECT id, mac, hostname FROM hosts WHERE ip = ?", (ip,))
                row = cursor.fetchone()

                if row:
                    # Update existing host
                    host_id, existing_mac, existing_hostname = row
                    update_mac = mac if mac else existing_mac
                    update_hostname = hostname if hostname else existing_hostname
                    existing_methods = []
                    cursor.execute("SELECT discovery_method FROM hosts WHERE id = ?", (host_id,))
                    method_row = cursor.fetchone()
                    if method_row and method_row[0]:
                        existing_methods = [part.strip() for part in str(method_row[0]).split(",") if part.strip()]
                    if method and method not in existing_methods:
                        existing_methods.append(method)
                    update_method = ", ".join(existing_methods) if existing_methods else method

                    cursor.execute(
                        """
                        UPDATE hosts
                        SET mac = ?, hostname = ?, last_seen = ?,
                            discovery_method = ?, is_active = 1
                        WHERE id = ?
                        """,
                        (update_mac, update_hostname, now, update_method, host_id),
                    )
                else:
                    # Insert new host
                    cursor.execute(
                        """
                        INSERT INTO hosts (ip, mac, hostname, first_seen, last_seen,
                                          discovery_method, is_active)
                        VALUES (?, ?, ?, ?, ?, ?, 1)
                        """,
                        (ip, mac, hostname, now, now, method),
                    )

                conn.commit()

            except sqlite3.Error as exc:
                logger.error("Database error storing host %s: %s", ip, exc)
            finally:
                if conn:
                    conn.close()

    def _store_hosts_batch(self, hosts: List[Dict], method: str = "") -> None:
        """Store or update a batch of discovered hosts in a single transaction.

        Thread-safe. Opens one SQLite connection for all hosts, commits once.

        Args:
            hosts: List of host dicts with keys: ip, mac (optional),
                   hostname (optional), discovery_method (optional).
            method: Fallback discovery method if not specified per host.
        """
        if not hosts:
            return

        now = datetime.now(timezone.utc).isoformat()

        with self._db_lock:
            conn = None
            try:
                conn = sqlite3.connect(self._db_path, timeout=30)
                cursor = conn.cursor()

                for host in hosts:
                    ip = host.get("ip")
                    if not ip:
                        continue
                    mac = host.get("mac")
                    hostname = host.get("hostname")
                    host_method = host.get("discovery_method", method)

                    cursor.execute("SELECT id, mac, hostname FROM hosts WHERE ip = ?", (ip,))
                    row = cursor.fetchone()

                    if row:
                        host_id, existing_mac, existing_hostname = row
                        update_mac = mac if mac else existing_mac
                        update_hostname = hostname if hostname else existing_hostname
                        existing_methods = []
                        cursor.execute("SELECT discovery_method FROM hosts WHERE id = ?", (host_id,))
                        method_row = cursor.fetchone()
                        if method_row and method_row[0]:
                            existing_methods = [part.strip() for part in str(method_row[0]).split(",") if part.strip()]
                        if host_method and host_method not in existing_methods:
                            existing_methods.append(host_method)
                        update_method = ", ".join(existing_methods) if existing_methods else host_method
                        cursor.execute(
                            """
                            UPDATE hosts
                            SET mac = ?, hostname = ?, last_seen = ?,
                                discovery_method = ?, is_active = 1
                            WHERE id = ?
                            """,
                            (update_mac, update_hostname, now, update_method, host_id),
                        )
                    else:
                        cursor.execute(
                            """
                            INSERT INTO hosts (ip, mac, hostname, first_seen, last_seen,
                                              discovery_method, is_active)
                            VALUES (?, ?, ?, ?, ?, ?, 1)
                            """,
                            (ip, mac, hostname, now, now, host_method),
                        )

                conn.commit()
                logger.info("Stored %d hosts to database (method=%s)", len(hosts), method)

            except sqlite3.Error as exc:
                logger.error("Database error in batch store (%d hosts): %s", len(hosts), exc)
            finally:
                if conn:
                    conn.close()

    def _build_dns_query(self, name: str, qtype: int = 1) -> bytes:
        """Build a minimal DNS query packet.

        Args:
            name: Domain name to query.
            qtype: DNS query type (1=A, 12=PTR, 255=ANY).

        Returns:
            Raw bytes of the DNS query packet.
        """
        # Transaction ID
        transaction_id = struct.pack(">H", random.randint(0x0001, 0xFFFF))
        # Flags: standard query, recursion desired
        flags = struct.pack(">H", 0x0100)
        # Questions: 1, Answers: 0, Authority: 0, Additional: 0
        counts = struct.pack(">HHHH", 1, 0, 0, 0)

        # Encode domain name
        qname = b""
        for label in name.split("."):
            encoded_label = label.encode("utf-8")
            qname += struct.pack("B", len(encoded_label)) + encoded_label
        qname += b"\x00"  # Root label

        # Query type and class (IN)
        qtype_class = struct.pack(">HH", qtype, 1)

        return transaction_id + flags + counts + qname + qtype_class

    def get_all_hosts(self) -> List[Dict]:
        """Retrieve all active hosts from the database.

        Returns:
            List of host dicts from the database.
        """
        with self._db_lock:
            conn = None
            try:
                conn = sqlite3.connect(self._db_path)
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM hosts WHERE is_active = 1 ORDER BY last_seen DESC")
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
            except sqlite3.Error as exc:
                logger.error("Database error retrieving hosts: %s", exc)
                return []
            finally:
                if conn:
                    conn.close()

    def mark_hosts_inactive(self, max_age_hours: int = 24) -> int:
        """Mark hosts not seen recently as inactive.

        Args:
            max_age_hours: Hours since last_seen to consider inactive.

        Returns:
            Number of hosts marked inactive.
        """
        from datetime import timedelta

        cutoff = (datetime.now(timezone.utc) - timedelta(hours=max_age_hours)).isoformat()

        with self._db_lock:
            conn = None
            try:
                conn = sqlite3.connect(self._db_path)
                cursor = conn.cursor()
                cursor.execute("UPDATE hosts SET is_active = 0 WHERE last_seen < ? AND is_active = 1", (cutoff,))
                count = cursor.rowcount
                conn.commit()
                logger.info("Marked %d hosts as inactive (age > %dh)", count, max_age_hours)
                return count
            except sqlite3.Error as exc:
                logger.error("Database error marking hosts inactive: %s", exc)
                return 0
            finally:
                if conn:
                    conn.close()

    # ------------------------------------------------------------------
    # SNMP Sweep
    # ------------------------------------------------------------------

    def _snmp_sweep(self, target_range: str) -> List[Dict]:
        """SNMP sweep using SNMPv1/v2c GET requests with common community strings.

        Sends SNMP GET requests for sysDescr (OID 1.3.6.1.2.1.1.1.0) to discover
        network devices. Uses raw UDP sockets to avoid dependency on SNMP libraries.

        Very slow timing (30-60s between probes) as SNMP sweeps are highly
        suspicious on monitored networks.

        Args:
            target_range: CIDR notation network (e.g., '192.168.1.0/24')

        Returns:
            List of discovered host dicts.
        """
        hosts: List[Dict] = []
        SNMP_PORT = 161

        try:
            network = ipaddress.ip_network(target_range, strict=False)
        except ValueError as exc:
            logger.error("Invalid target range '%s': %s", target_range, exc)
            return []

        # Limit scope - SNMP sweep is slow, so cap at /22
        if network.prefixlen < 22:
            logger.info("Network %s too large for SNMP sweep (prefix < /22), skipping", target_range)
            return []

        targets = [str(ip) for ip in network.hosts()]
        random.shuffle(targets)

        logger.info("SNMP sweep: %d targets in %s", len(targets), target_range)

        discovered_ips: set = set()

        for target_ip in targets:
            for community in self._snmp_communities:
                try:
                    snmp_packet = self._build_snmp_get_request(community)

                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(3.0)
                    try:
                        sock.sendto(snmp_packet, (target_ip, SNMP_PORT))

                        try:
                            data, addr = sock.recvfrom(4096)
                            resp_ip = addr[0]

                            if resp_ip not in discovered_ips:
                                discovered_ips.add(resp_ip)

                                # Try to parse sysDescr from response
                                sys_descr = self._parse_snmp_response(data)

                                host_info = {
                                    "ip": resp_ip,
                                    "mac": None,
                                    "hostname": sys_descr,
                                    "discovery_method": "snmp_sweep",
                                }
                                hosts.append(host_info)
                                self._store_host(ip=resp_ip, hostname=sys_descr, method="snmp_sweep")
                                logger.debug(
                                    "SNMP: found %s (community='%s', descr='%s')", resp_ip, community, sys_descr
                                )
                                # Found with this community, skip remaining strings
                                break

                        except socket.timeout:
                            pass
                    finally:
                        sock.close()

                except Exception as exc:
                    logger.debug("SNMP probe to %s (community='%s') failed: %s", target_ip, community, exc)

            # Very slow delay between probes (configured via snmp_delay + jitter)
            time.sleep(self._apply_jitter(self._snmp_delay))

        return hosts

    def _build_snmp_get_request(self, community: str) -> bytes:
        """Build a raw SNMPv1 GET-request packet for OID 1.3.6.1.2.1.1.1.0 (sysDescr).

        Args:
            community: SNMP community string.

        Returns:
            Raw bytes of the SNMP GET-request packet.
        """
        # OID: 1.3.6.1.2.1.1.1.0 (sysDescr)
        oid_bytes = bytes([0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])

        # Varbind: SEQUENCE { OID, NULL }
        oid_tlv = bytes([0x06, len(oid_bytes)]) + oid_bytes
        null_tlv = bytes([0x05, 0x00])
        varbind = bytes([0x30, len(oid_tlv) + len(null_tlv)]) + oid_tlv + null_tlv

        # Varbind list: SEQUENCE { varbind }
        varbind_list = bytes([0x30, len(varbind)]) + varbind

        # Request ID (random)
        request_id = random.randint(1, 2147483647)
        request_id_bytes = request_id.to_bytes(4, "big")
        request_id_tlv = bytes([0x02, len(request_id_bytes)]) + request_id_bytes

        # Error status: 0
        error_status_tlv = bytes([0x02, 0x01, 0x00])

        # Error index: 0
        error_index_tlv = bytes([0x02, 0x01, 0x00])

        # PDU (GET-request = 0xA0)
        pdu_value = request_id_tlv + error_status_tlv + error_index_tlv + varbind_list
        pdu = bytes([0xA0, len(pdu_value)]) + pdu_value

        # Community string
        community_bytes = community.encode("ascii")
        community_tlv = bytes([0x04, len(community_bytes)]) + community_bytes

        # Version: SNMPv1 = 0
        version_tlv = bytes([0x02, 0x01, 0x00])

        # Message: SEQUENCE { version, community, pdu }
        message_value = version_tlv + community_tlv + pdu
        message = bytes([0x30, len(message_value)]) + message_value

        return message

    def _parse_snmp_response(self, data: bytes) -> Optional[str]:
        """Parse an SNMP GET-response to extract the sysDescr string.

        Simple BER/TLV parser that looks for the OctetString value
        in the varbind list of the response.

        Args:
            data: Raw bytes of the SNMP response.

        Returns:
            sysDescr string if successfully parsed, None otherwise.
        """
        try:
            # Minimal validation
            if not data or data[0] != 0x30:
                return None

            # Walk through the response looking for an OctetString (0x04)
            # after the OID in the varbind
            # Simple approach: find the OID for sysDescr and extract the next value
            oid_marker = bytes([0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])
            idx = data.find(oid_marker)

            if idx == -1:
                return None

            # Move past the OID TLV
            idx += len(oid_marker)

            # Next should be the value (OctetString tag = 0x04)
            if idx < len(data) and data[idx] == 0x04:
                idx += 1  # past tag byte
                if idx >= len(data):
                    return None
                # BER length decoding: handle multi-byte lengths
                length_byte = data[idx]
                idx += 1
                if length_byte & 0x80 == 0:
                    # Short form: length is the byte itself (0-127)
                    length = length_byte
                else:
                    # Long form: lower 7 bits = number of subsequent length bytes
                    num_length_bytes = length_byte & 0x7F
                    if num_length_bytes == 0 or idx + num_length_bytes > len(data):
                        return None
                    length = int.from_bytes(data[idx : idx + num_length_bytes], "big")
                    idx += num_length_bytes
                if idx + length <= len(data):
                    value = data[idx : idx + length]
                    return value.decode("utf-8", errors="ignore").strip()

        except (IndexError, ValueError) as exc:
            logger.debug("SNMP response parse error: %s", exc)

        return None

    # ------------------------------------------------------------------
    # SSDP/UPnP Discovery
    # ------------------------------------------------------------------

    def _ssdp_discover(self, target_range: str = None) -> List[Dict]:
        """Discover devices via SSDP/UPnP multicast M-SEARCH.

        Sends a single M-SEARCH request to the SSDP multicast address
        (239.255.255.250:1900) and listens for responses. This looks like
        normal UPnP client behavior and is very low-suspicion.

        Args:
            target_range: Ignored (SSDP is multicast-based). Accepted for
                          API compatibility with run_discovery.

        Returns:
            List of discovered host dicts.
        """
        hosts: List[Dict] = []
        discovered_ips: set = set()

        SSDP_ADDR = "239.255.255.250"
        SSDP_PORT = 1900
        LISTEN_DURATION = 10  # seconds to listen for responses

        # M-SEARCH request for all devices
        msearch = (
            "M-SEARCH * HTTP/1.1\r\n"
            f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n"
            'MAN: "ssdp:discover"\r\n'
            "MX: 5\r\n"
            "ST: ssdp:all\r\n"
            "\r\n"
        )

        logger.info("SSDP discovery: sending M-SEARCH multicast")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(2.0)

            # Set multicast TTL to 2 (local network only)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, struct.pack("b", 2))

            try:
                # Send M-SEARCH
                sock.sendto(msearch.encode("utf-8"), (SSDP_ADDR, SSDP_PORT))

                # Listen for responses
                deadline = time.time() + LISTEN_DURATION
                while time.time() < deadline:
                    try:
                        data, addr = sock.recvfrom(4096)
                        src_ip = addr[0]

                        if src_ip in discovered_ips:
                            continue
                        discovered_ips.add(src_ip)

                        # Parse SSDP response headers
                        response_text = data.decode("utf-8", errors="ignore")
                        device_info = self._parse_ssdp_response(response_text)

                        hostname = device_info.get("server") or device_info.get("location")

                        host_info = {
                            "ip": src_ip,
                            "mac": None,
                            "hostname": hostname,
                            "discovery_method": "ssdp",
                            "device_type": device_info.get("st"),
                            "location": device_info.get("location"),
                            "server": device_info.get("server"),
                        }
                        hosts.append(host_info)
                        self._store_host(ip=src_ip, hostname=hostname, method="ssdp")
                        logger.debug(
                            "SSDP: found %s (server='%s', location='%s')",
                            src_ip,
                            device_info.get("server"),
                            device_info.get("location"),
                        )

                    except socket.timeout:
                        continue
                    except Exception as exc:
                        logger.debug("SSDP recv error: %s", exc)
            finally:
                sock.close()

        except Exception as exc:
            logger.error("SSDP discovery failed: %s", exc, exc_info=True)

        # Post-discovery stealth delay
        time.sleep(self._apply_jitter(self._min_delay))

        logger.info("SSDP discovery found %d devices", len(hosts))
        return hosts

    def _parse_ssdp_response(self, response: str) -> Dict[str, str]:
        """Parse SSDP/HTTP response headers into a dictionary.

        Args:
            response: Raw HTTP response text.

        Returns:
            Dict with parsed header values (lowercased keys).
        """
        result: Dict[str, str] = {}

        try:
            lines = response.split("\r\n")
            for line in lines:
                if ":" in line:
                    key, _, value = line.partition(":")
                    key = key.strip().lower()
                    value = value.strip()
                    if key in ("location", "server", "st", "usn", "cache-control"):
                        result[key] = value
        except Exception:
            pass

        return result

    # ------------------------------------------------------------------
    # TCP SYN Discovery
    # ------------------------------------------------------------------

    def _tcp_syn_discover(self, target_range: str) -> List[Dict]:
        """Lightweight TCP SYN-based host discovery.

        Sends TCP SYN packets to common ports (80, 443, 22) just to check
        if a host is alive. This is NOT a port scan — only interested in
        whether the host responds (SYN-ACK or RST both mean alive).

        Uses scapy for raw SYN packets if available, otherwise falls back
        to a quick connect() attempt with a very short timeout.

        Much faster than ARP sweep for routed subnets where ARP won't work.

        Args:
            target_range: CIDR notation network.

        Returns:
            List of discovered host dicts.
        """
        hosts: List[Dict] = []
        PROBE_PORTS = [80, 443, 22]

        try:
            network = ipaddress.ip_network(target_range, strict=False)
        except ValueError as exc:
            logger.error("Invalid target range '%s': %s", target_range, exc)
            return []

        # Limit scope for very large networks
        if network.prefixlen < 20:
            logger.info("Network %s too large for TCP SYN discovery (prefix < /20), skipping", target_range)
            return []

        targets = [str(ip) for ip in network.hosts()]
        random.shuffle(targets)

        logger.info("TCP SYN discovery: %d targets in %s (ports=%s)", len(targets), target_range, PROBE_PORTS)

        discovered_ips: set = set()

        if SCAPY_AVAILABLE:
            hosts = self._tcp_syn_scapy(targets, PROBE_PORTS, discovered_ips)
        else:
            hosts = self._tcp_syn_connect_fallback(targets, PROBE_PORTS, discovered_ips)

        return hosts

    def _tcp_syn_scapy(self, targets: List[str], ports: List[int], discovered_ips: set) -> List[Dict]:
        """TCP SYN discovery using scapy raw packets.

        Args:
            targets: List of target IP addresses.
            ports: List of ports to probe.
            discovered_ips: Set to track already-discovered IPs.

        Returns:
            List of discovered host dicts.
        """
        hosts: List[Dict] = []

        try:
            from scapy.all import IP as ScapyIP
            from scapy.all import TCP
            from scapy.all import sr1 as scapy_sr1
        except ImportError:
            logger.warning("scapy TCP import failed, falling back to connect()")
            return self._tcp_syn_connect_fallback(targets, ports, discovered_ips)

        for target_ip in targets:
            if target_ip in discovered_ips:
                continue

            alive = False
            # Try each port until we get a response
            port = random.choice(ports)

            try:
                # Random source port
                sport = random.randint(1024, 65535)

                syn_pkt = ScapyIP(dst=target_ip) / TCP(sport=sport, dport=port, flags="S")
                resp = scapy_sr1(syn_pkt, timeout=2, verbose=0)

                if resp is not None:
                    # Any response (SYN-ACK, RST) means host is alive
                    alive = True

                    # Send RST to close the half-open connection
                    if resp.haslayer(TCP) and resp[TCP].flags & 0x12:  # SYN-ACK
                        from scapy.all import send as scapy_send

                        rst_pkt = ScapyIP(dst=target_ip) / TCP(sport=sport, dport=port, flags="R", seq=resp[TCP].ack)
                        scapy_send(rst_pkt, verbose=0)

            except Exception as exc:
                logger.debug("TCP SYN (scapy) to %s:%d failed: %s", target_ip, port, exc)

            if alive and target_ip not in discovered_ips:
                discovered_ips.add(target_ip)
                host_info = {
                    "ip": target_ip,
                    "mac": None,
                    "hostname": None,
                    "discovery_method": "tcp_syn",
                }
                hosts.append(host_info)
                self._store_host(ip=target_ip, method="tcp_syn")
                logger.debug("TCP SYN: found %s (port %d responded)", target_ip, port)

            # Stealth delay between probes
            time.sleep(self._apply_jitter(self._min_delay / 2))

        return hosts

    def _tcp_syn_connect_fallback(self, targets: List[str], ports: List[int], discovered_ips: set) -> List[Dict]:
        """TCP host discovery using connect() with very short timeout (fallback).

        Args:
            targets: List of target IP addresses.
            ports: List of ports to probe.
            discovered_ips: Set to track already-discovered IPs.

        Returns:
            List of discovered host dicts.
        """
        hosts: List[Dict] = []
        CONNECT_TIMEOUT = 0.5  # Very short timeout

        for target_ip in targets:
            if target_ip in discovered_ips:
                continue

            alive = False
            # Try a random port
            port = random.choice(ports)

            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(CONNECT_TIMEOUT)
                try:
                    result = sock.connect_ex((target_ip, port))

                    # connect_ex returns 0 on success, or errno
                    # Both connection success and connection refused mean host is alive
                    # Only timeout (errno 10060/110) means host is down
                    if result == 0 or result in (111, 10061):  # 111=ECONNREFUSED (Linux), 10061 (Windows)
                        alive = True
                finally:
                    sock.close()

            except socket.timeout:
                pass
            except OSError as exc:
                # Connection refused also means host is alive
                if exc.errno in (111, 10061):  # ECONNREFUSED
                    alive = True
                else:
                    logger.debug("TCP connect to %s:%d error: %s", target_ip, port, exc)

            if alive and target_ip not in discovered_ips:
                discovered_ips.add(target_ip)
                host_info = {
                    "ip": target_ip,
                    "mac": None,
                    "hostname": None,
                    "discovery_method": "tcp_syn",
                }
                hosts.append(host_info)
                self._store_host(ip=target_ip, method="tcp_syn")
                logger.debug("TCP SYN (connect): found %s (port %d)", target_ip, port)

            # Stealth delay between probes
            time.sleep(self._apply_jitter(self._min_delay / 2))

        return hosts

    # ------------------------------------------------------------------
    # DHCP Passive Sniff
    # ------------------------------------------------------------------

    def _dhcp_passive_sniff(self, target_range: str = None) -> List[Dict]:
        """Passively sniff DHCP traffic to discover hosts.

        Listens for DHCP Discover, Request, and ACK packets on
        UDP ports 67/68. Extracts client MAC address, requested IP,
        and hostname (option 12) from DHCP messages.

        This is pure passive — zero packets are sent on the network.

        Args:
            target_range: Ignored (passive technique). Accepted for
                          API compatibility with run_discovery.

        Returns:
            List of discovered host dicts.
        """
        hosts: List[Dict] = []

        if not SCAPY_AVAILABLE:
            logger.warning("DHCP passive sniff requires scapy - skipping")
            return []

        try:
            from scapy.all import BOOTP, DHCP
            from scapy.all import sniff as dhcp_sniff
        except ImportError as exc:
            logger.warning("Failed to import scapy DHCP modules: %s", exc)
            return []

        discovered: Dict[str, Dict] = {}
        discovered_lock = threading.Lock()

        SNIFF_DURATION = self._discovery_cfg.get("dhcp_sniff_duration", 300)

        logger.info("DHCP passive sniff: listening for %d seconds...", SNIFF_DURATION)

        def _dhcp_handler(pkt):
            """Process captured DHCP packets."""
            if not pkt.haslayer(DHCP) or not pkt.haslayer(BOOTP):
                return

            try:
                bootp = pkt[BOOTP]
                dhcp_options = pkt[DHCP].options

                # Extract client MAC from BOOTP header
                client_mac = bootp.chaddr[:6]
                mac_str = ":".join(f"{b:02x}" for b in client_mac)

                # Extract DHCP message type
                msg_type = None
                hostname = None
                for opt in dhcp_options:
                    if isinstance(opt, tuple):
                        if opt[0] == "message-type":
                            msg_type = opt[1]
                        elif opt[0] == "hostname":
                            hostname = opt[1] if isinstance(opt[1], str) else opt[1].decode("utf-8", errors="ignore")

                # Determine client IP
                client_ip = None

                # From DHCP ACK: yiaddr is the assigned IP
                if msg_type == 5:  # DHCP ACK
                    if bootp.yiaddr and bootp.yiaddr != "0.0.0.0":
                        client_ip = bootp.yiaddr

                # From DHCP Offer: yiaddr is the offered IP
                elif msg_type == 2:  # DHCP Offer
                    if bootp.yiaddr and bootp.yiaddr != "0.0.0.0":
                        client_ip = bootp.yiaddr

                # Skip DHCP Discover (1) and Request (3) — these contain
                # unconfirmed addresses that may never be assigned.

                if client_ip and client_ip != "0.0.0.0":
                    with discovered_lock:
                        if client_ip not in discovered:
                            discovered[client_ip] = {
                                "ip": client_ip,
                                "mac": mac_str,
                                "hostname": hostname,
                                "discovery_method": "dhcp_passive",
                            }
                            logger.debug(
                                "DHCP: found %s (mac=%s, hostname=%s, type=%s)", client_ip, mac_str, hostname, msg_type
                            )
                        else:
                            # Update hostname if we get it from a later packet
                            if hostname and not discovered[client_ip].get("hostname"):
                                discovered[client_ip]["hostname"] = hostname

            except Exception as exc:
                logger.debug("DHCP packet parse error: %s", exc)

        try:
            dhcp_sniff(
                prn=_dhcp_handler,
                filter="udp port 67 or udp port 68",
                timeout=SNIFF_DURATION,
                store=0,
                quiet=True,
            )
        except Exception as exc:
            logger.error("DHCP sniff error: %s", exc, exc_info=True)

        # Store all discovered hosts
        hosts = list(discovered.values())
        for host in hosts:
            self._store_host(ip=host["ip"], mac=host.get("mac"), hostname=host.get("hostname"), method="dhcp_passive")

        # Stealth delay after passive operation
        time.sleep(self._apply_jitter(self._min_delay))

        logger.info("DHCP passive sniff discovered %d hosts", len(hosts))
        return hosts
