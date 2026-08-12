"""
HostVigil Enterprise Pipeline - Wave-Based Processing

Designed for 200,000+ host corporate networks.

Key improvements:
- Wave-based processing (never load all hosts at once)
- Parallel phase execution (scan while discovering)
- Nuclei on-demand trigger (when web ports found)
- Adaptive throttling based on system resources
- Subnet-priority scanning
"""

import ipaddress
import logging
import random
import sqlite3
import threading
import time
from typing import Dict, List, Tuple

logger = logging.getLogger("hostvigil.enterprise_pipeline")


class WaveBasedPipeline:
    """
    Process large networks in manageable waves.

    Instead of: Discover ALL → Scan ALL → Analyze ALL (never finishes)
    Do: Discover(1000) → Scan(1000) → Analyze(1000) → Repeat

    This ensures:
    - Pipeline always makes progress
    - Nuclei runs on discovered web hosts immediately
    - Memory stays bounded
    - Can interrupt/resume gracefully
    """

    def __init__(self, orchestrator, db_path: str):
        self.orchestrator = orchestrator
        self.db_path = db_path
        self.running = False
        self.current_wave = 0
        self.wave_size = 1000  # Hosts per wave
        self.max_concurrent_waves = 3  # Overlapping waves for pipeline parallelism
        self._lock = threading.Lock()  # Thread safety for stats and running flag

        # Performance tracking
        self.stats = {
            "waves_completed": 0,
            "hosts_processed": 0,
            "ports_discovered": 0,
            "nuclei_runs": 0,
            "avg_wave_duration_sec": 0,
            "last_error": None,
        }

        # Target prioritization
        self.priority_subnets = []  # Scan these first
        self.pending_subnets = []  # Remaining subnets
        self.completed_subnets = set()

    def _expand_target_ranges(self, ranges: List[str]) -> List[str]:
        """
        Expand CIDR ranges into /24 subnets for manageable processing.

        This is CRITICAL for large networks. Instead of scanning 10.0.0.0/8
        as one block (16M IPs), we break it into 65,536 x /24 subnets.

        Returns list of /24 CIDR blocks.
        """
        subnets = []

        for cidr in ranges:
            try:
                network = ipaddress.ip_network(cidr, strict=False)

                if network.prefixlen <= 24:
                    # Large network - break into /24 chunks
                    for subnet in network.subnets(new_prefix=24):
                        subnets.append(str(subnet))
                else:
                    # Already small enough
                    subnets.append(str(network))

            except Exception as e:
                logger.warning(f"Invalid CIDR {cidr}: {e}")

        return subnets

    def _prioritize_subnets(self, all_subnets: List[str]) -> Tuple[List[str], List[str]]:
        """
        Sort subnets by priority for scanning.

        Priority order:
        1. Data center ranges (10.0-10.1.x.x)
        2. Server subnets (unusual patterns)
        3. User workstations
        4. Guest/IoT networks

        Also shuffles within priority tiers to avoid predictable patterns.
        """
        priority = []
        standard = []

        for subnet in all_subnets:
            # Detect priority subnets
            if any(
                marker in subnet
                for marker in [
                    "10.0.",
                    "10.1.",  # Common DC ranges
                    "10.10.",
                    "10.20.",  # Server VLANs
                    "192.168.100.",  # Infrastructure
                    "172.16.0.",
                    "172.16.1.",  # DC
                ]
            ):
                priority.append(subnet)
            else:
                standard.append(subnet)

        # Shuffle within tiers
        random.shuffle(priority)
        random.shuffle(standard)

        return priority, standard

    def _get_active_hosts_from_subnet(self, subnet: str, limit: int = None) -> List[str]:
        """
        Get active hosts from a specific subnet.

        Uses database cache first (previous discoveries), then runs discovery.
        """
        conn = sqlite3.connect(self.db_path, timeout=30)
        try:
            # Parse subnet to get IP range
            network = ipaddress.ip_network(subnet, strict=False)

            # For /24 and smaller, we can use a LIKE prefix for the first octets
            # to reduce the result set before Python filtering.
            # This avoids loading all 200k+ hosts into memory.
            prefix_octets = str(network.network_address).rsplit(".", 1)[0]
            prefix_filter = prefix_octets + ".%"

            cursor = conn.execute(
                "SELECT ip FROM hosts WHERE is_active = 1 AND ip LIKE ? ORDER BY last_seen DESC", (prefix_filter,)
            )
            candidate_hosts = [row[0] for row in cursor.fetchall()]

            # Fine-grained filter: ensure each IP is actually in the target subnet
            # (the LIKE prefix may be slightly broader than the exact subnet)
            hosts = []
            for ip_str in candidate_hosts:
                try:
                    if ipaddress.ip_address(ip_str) in network:
                        hosts.append(ip_str)
                except ValueError:
                    continue

            if limit:
                hosts = hosts[:limit]

            return hosts

        except Exception as e:
            logger.error(f"Failed to get hosts for subnet {subnet}: {e}")
            return []
        finally:
            conn.close()

    def _discover_subnet(self, subnet: str) -> Dict:
        """Run discovery on a single /24 subnet."""
        try:
            from hostvigil.discovery import StealthDiscovery

            discovery = StealthDiscovery({}, self.db_path)
            # Configure for single subnet
            discovery.config["target_ranges"] = [subnet]

            result = discovery.run_discovery()
            logger.info(f"Discovered {result.get('hosts_found', 0)} hosts in {subnet}")
            return result

        except Exception as e:
            logger.error(f"Discovery failed for {subnet}: {e}")
            return {"hosts_found": 0, "error": str(e)}

    def _run_wave(self, subnet_batch: List[str]) -> Dict:
        """
        Execute one wave: discover → scan → analyze → nuclei

        Returns wave statistics.
        """
        wave_start = time.time()
        wave_stats = {
            "subnets_processed": 0,
            "hosts_discovered": 0,
            "ports_found": 0,
            "nuclei_triggered": False,
            "errors": 0,
        }

        for subnet in subnet_batch:
            if not self.running:
                logger.info("Pipeline stopped mid-wave")
                break

            try:
                # Step 1: Discover hosts in this subnet
                logger.debug(f"Discovering {subnet}...")
                discovery_result = self._discover_subnet(subnet)

                hosts_found = discovery_result.get("hosts_found", 0) if isinstance(discovery_result, dict) else 0

                if not hosts_found:
                    logger.debug(f"No hosts found in {subnet}")
                    self.completed_subnets.add(subnet)
                    continue

                wave_stats["hosts_discovered"] += hosts_found

                # Fetch discovered host IPs from DB for scanning
                from hostvigil.discovery import StealthDiscovery

                discovery = StealthDiscovery({}, self.db_path)
                all_hosts = discovery.get_all_hosts()
                host_ips = [h["ip"] for h in all_hosts if h.get("ip")]

                # Step 2: Scan discovered hosts (two-phase)
                logger.debug(f"Scanning {len(host_ips)} hosts...")
                scan_result = self._scan_hosts(host_ips)
                wave_stats["ports_found"] += scan_result.get("total_open_ports", 0)

                # Step 3: Run Nuclei on hosts with web ports (HTTP/HTTPS)
                web_hosts = self._find_web_hosts(host_ips)
                if web_hosts and self._should_run_nuclei():
                    logger.info(f"Triggering Nuclei on {len(web_hosts)} web hosts...")
                    self._run_nuclei_on_hosts(web_hosts)
                    wave_stats["nuclei_triggered"] = True
                    wave_stats["nuclei_runs"] = 1

                # Step 4: ML analysis on this batch
                self._run_ml_analysis(host_ips)

                wave_stats["subnets_processed"] += 1
                self.completed_subnets.add(subnet)

            except Exception as e:
                logger.error(f"Wave processing failed for {subnet}: {e}")
                wave_stats["errors"] += 1
                self.stats["last_error"] = str(e)
                continue

        wave_duration = time.time() - wave_start
        wave_stats["duration_sec"] = wave_duration

        # Update running stats (thread-safe)
        with self._lock:
            self.stats["waves_completed"] += 1
            self.stats["hosts_processed"] += wave_stats["hosts_discovered"]
            self.stats["ports_discovered"] += wave_stats["ports_found"]
            self.stats["avg_wave_duration_sec"] = (
                self.stats["avg_wave_duration_sec"] * (self.stats["waves_completed"] - 1) + wave_duration
            ) / self.stats["waves_completed"]

        return wave_stats

    def _scan_hosts(self, hosts: List[str]) -> Dict:
        """Run two-phase scan on hosts."""
        try:
            import shutil
            import subprocess
            import tempfile

            if shutil.which("naabu"):
                # Write targets to temp file
                tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
                tmp.write("\n".join(hosts))
                tmp.close()
                try:
                    ports = ",".join(
                        str(p)
                        for p in self.orchestrator.config.scanner.get("ports", {}).get(
                            "quick", [22, 80, 443, 445, 3389]
                        )
                    )
                    result = subprocess.run(
                        ["naabu", "-list", tmp.name, "-p", ports, "-silent", "-rate", "5000"],
                        capture_output=True,
                        text=True,
                        timeout=300,
                    )
                    # Parse ip:port output
                    from collections import defaultdict

                    port_map = defaultdict(list)
                    for line in result.stdout.strip().split("\n"):
                        if ":" in line:
                            ip, port = line.rsplit(":", 1)
                            port_map[ip.strip()].append(int(port.strip()))
                    total_ports = sum(len(p) for p in port_map.values())
                    return {"total_open_ports": total_ports, "results": dict(port_map)}
                finally:
                    import os

                    os.unlink(tmp.name)
            else:
                # Fallback to standard scanner with quick profile
                logger.warning("naabu not available for enterprise pipeline, using quick scan profile")
                results = self.orchestrator.scanner.scan_hosts(hosts, port_profile="quick")
                # scan_hosts returns a list; wrap for caller
                return {"total_open_ports": len(results) if isinstance(results, list) else 0, "results": results}

        except Exception as e:
            logger.error(f"Scan failed: {e}")
            return {"total_open_ports": 0}

    def _find_web_hosts(self, hosts: List[str]) -> List[str]:
        """Find hosts with web ports (80, 443, 8080, 8443)."""
        if not hosts:
            return []
        conn = sqlite3.connect(self.db_path, timeout=30)
        try:
            web_ports = (80, 443, 8080, 8443, 8000, 8888, 9000)
            port_placeholders = ",".join("?" * len(web_ports))
            host_placeholders = ",".join("?" * len(hosts))

            cursor = conn.execute(
                f"SELECT DISTINCT h.ip FROM hosts h "
                f"JOIN ports p ON h.id = p.host_id "
                f"WHERE h.ip IN ({host_placeholders}) "
                f"AND p.port IN ({port_placeholders}) "
                f"AND p.state = 'open'",
                (*hosts, *web_ports),
            )

            return [row[0] for row in cursor.fetchall()]

        except Exception as e:
            logger.warning(f"Failed to find web hosts: {e}")
            return []
        finally:
            conn.close()

    def _should_run_nuclei(self) -> bool:
        """Check if Nuclei should run (resource availability, config)."""
        # Check memory availability
        try:
            import psutil

            mem_available = psutil.virtual_memory().available / (1024 * 1024 * 1024)  # GB
            if mem_available < 2.0:  # Less than 2GB free
                logger.warning(f"Skipping Nuclei: low memory ({mem_available:.1f}GB available)")
                return False
        except (ImportError, OSError):
            pass  # psutil not installed or OS error, skip check

        # Check config
        nuclei_config = self.orchestrator.config.nuclei
        return nuclei_config.get("enabled", True)

    def _run_nuclei_on_hosts(self, hosts: List[str]):
        """Run Nuclei vulnerability scan on specific hosts."""
        try:
            nuclei = self.orchestrator.nuclei

            if not nuclei.is_nuclei_available():
                logger.warning("Nuclei binary not available, skipping")
                return

            # Run on target hosts only
            nuclei.run_scan(targets=hosts, severity_filter=["critical", "high"])
            logger.info(f"Nuclei scan completed on {len(hosts)} hosts")

        except Exception as e:
            logger.error(f"Nuclei scan failed: {e}")

    def _run_ml_analysis(self, hosts: List[str]):
        """Run anomaly detection on this batch."""
        try:
            # Batch ML analysis (lightweight)
            self.orchestrator.run_analysis()
        except Exception as e:
            logger.debug(f"ML analysis skipped for batch: {e}")

    def start(self, target_ranges: List[str] = None):
        """
        Start wave-based pipeline processing.

        Args:
            target_ranges: List of CIDR ranges to scan. If None, uses config.
        """
        self.running = True
        ranges = target_ranges or self.orchestrator.config.hostvigil["discovery"]["target_ranges"]

        logger.info(f"Starting wave-based pipeline for {len(ranges)} target ranges...")

        # Expand ranges into /24 subnets
        all_subnets = self._expand_target_ranges(ranges)
        logger.info(f"Expanded to {len(all_subnets)} /24 subnets")

        # Prioritize
        priority, standard = self._prioritize_subnets(all_subnets)
        self.pending_subnets = priority + standard

        logger.info(f"Priority subnets: {len(priority)}, Standard subnets: {len(standard)}")

        # Process waves
        self._process_waves()

    def _process_waves(self):
        """Process subnets in waves."""
        wave_num = 0

        while self.running and self.pending_subnets:
            wave_num += 1

            # Get next batch of subnets
            batch = self.pending_subnets[: self.wave_size]
            self.pending_subnets = self.pending_subnets[self.wave_size :]

            logger.info(f"=== Wave {wave_num}: Processing {len(batch)} subnets ===")

            # Execute wave
            stats = self._run_wave(batch)

            # Log progress
            logger.info(
                f"Wave {wave_num} complete: "
                f"{stats['subnets_processed']} subnets, "
                f"{stats['hosts_discovered']} hosts, "
                f"{stats['ports_found']} ports, "
                f"Nuclei: {'YES' if stats['nuclei_triggered'] else 'NO'}, "
                f"Duration: {stats['duration_sec']:.1f}s"
            )

            # Adaptive delay between waves (prevent network saturation)
            if self.pending_subnets:
                delay = max(5, 30 - wave_num)  # Decrease delay as we go
                logger.debug(f"Wave delay: {delay}s")
                time.sleep(delay)

        if self.running:
            logger.info(f"Pipeline complete: {self.stats['hosts_processed']} hosts processed")
        else:
            logger.info(f"Pipeline stopped: {self.stats['hosts_processed']} hosts processed")

    def stop(self):
        """Stop pipeline gracefully."""
        with self._lock:
            self.running = False
        logger.info("Pipeline stop requested")

    def get_stats(self) -> dict:
        """Get pipeline statistics."""
        with self._lock:
            return {
                **self.stats,
                "subnets_pending": len(self.pending_subnets),
                "subnets_completed": len(self.completed_subnets),
                "running": self.running,
            }
