"""
OS Fingerprinting Module for HostVigil.

Uses TCP/IP stack characteristics to identify operating systems.
Prioritizes passive analysis of existing scan data, falls back to
active probing with stealth timing when needed.
"""

import json
import logging
import random
import sqlite3
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

try:
    from scapy.all import IP, TCP, conf, sr1

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

logger = logging.getLogger("hostvigil.scanner.os_fingerprint")

# ---------------------------------------------------------------------------
# OS Signature Database
# ---------------------------------------------------------------------------

OS_SIGNATURES = {
    "Windows 10/11/Server 2016+": {
        "ttl": 128,
        "window": [8192, 65535],
        "df": True,
        "tcp_options": ["MSS", "NOP", "WS", "NOP", "NOP", "SACK"],
    },
    "Windows 7/Server 2008": {
        "ttl": 128,
        "window": [8192, 65535],
        "df": True,
        "tcp_options": ["MSS", "NOP", "WS", "NOP", "NOP", "SACK"],
    },
    "Linux 4.x/5.x/6.x": {
        "ttl": 64,
        "window": [29200, 65535],
        "df": True,
        "tcp_options": ["MSS", "SACK", "Timestamp", "NOP", "WS"],
    },
    "Linux 2.6/3.x": {
        "ttl": 64,
        "window": [5840, 14600],
        "df": True,
        "tcp_options": ["MSS", "SACK", "Timestamp", "NOP", "WS"],
    },
    "macOS/iOS": {
        "ttl": 64,
        "window": [65535],
        "df": True,
        "tcp_options": ["MSS", "NOP", "WS", "NOP", "NOP", "Timestamp", "SACK", "EOL"],
    },
    "FreeBSD": {
        "ttl": 64,
        "window": [65535],
        "df": True,
        "tcp_options": ["MSS", "NOP", "WS", "SACK", "Timestamp"],
    },
    "Cisco IOS": {
        "ttl": 255,
        "window": [4128],
        "df": False,
        "tcp_options": ["MSS"],
    },
    "Cisco ASA": {
        "ttl": 255,
        "window": [8192, 16384],
        "df": True,
        "tcp_options": ["MSS", "SACK"],
    },
    "Solaris/SunOS": {
        "ttl": 255,
        "window": [49640, 49232],
        "df": True,
        "tcp_options": ["NOP", "NOP", "Timestamp", "MSS", "NOP", "WS", "SACK"],
    },
    "Embedded/IoT": {
        "ttl": 64,
        "window": [1024, 2048, 4096],
        "df": False,
        "tcp_options": ["MSS"],
    },
    "HP Printer": {
        "ttl": 60,
        "window": [16384],
        "df": True,
        "tcp_options": ["MSS"],
    },
    "VMware ESXi": {
        "ttl": 64,
        "window": [65535],
        "df": True,
        "tcp_options": ["MSS", "NOP", "WS", "SACK", "Timestamp"],
    },
}

# Banner keywords mapped to OS families
BANNER_OS_KEYWORDS = {
    "ubuntu": "Linux 4.x/5.x/6.x",
    "debian": "Linux 4.x/5.x/6.x",
    "centos": "Linux 4.x/5.x/6.x",
    "red hat": "Linux 4.x/5.x/6.x",
    "fedora": "Linux 4.x/5.x/6.x",
    "alpine": "Linux 4.x/5.x/6.x",
    "arch linux": "Linux 4.x/5.x/6.x",
    "opensuse": "Linux 4.x/5.x/6.x",
    "linux": "Linux 4.x/5.x/6.x",
    "windows server 2019": "Windows 10/11/Server 2016+",
    "windows server 2022": "Windows 10/11/Server 2016+",
    "windows server 2016": "Windows 10/11/Server 2016+",
    "windows server 2012": "Windows 7/Server 2008",
    "windows server 2008": "Windows 7/Server 2008",
    "microsoft": "Windows 10/11/Server 2016+",
    "windows": "Windows 10/11/Server 2016+",
    "freebsd": "FreeBSD",
    "macos": "macOS/iOS",
    "darwin": "macOS/iOS",
    "cisco": "Cisco IOS",
    "ios": "Cisco IOS",
    "adaptive security": "Cisco ASA",
    "sunos": "Solaris/SunOS",
    "solaris": "Solaris/SunOS",
    "esxi": "VMware ESXi",
    "vmware": "VMware ESXi",
    "hp jetdirect": "HP Printer",
    "printer": "HP Printer",
}


# ---------------------------------------------------------------------------
# OSFingerprinter Class
# ---------------------------------------------------------------------------


class OSFingerprinter:
    """
    OS fingerprinting engine that combines passive analysis of existing scan
    data with optional active TCP stack probing. Designed for stealth — uses
    jittered delays and prefers passive techniques.
    """

    def __init__(self, config: dict, db_path: str):
        self.config = config
        self.db_path = db_path
        self.min_delay = config.get("min_delay", 10.0)
        self.max_delay = config.get("max_delay", 45.0)
        self.jitter_factor = config.get("jitter_factor", 0.3)
        # 'active_probing' is the documented config key; 'active_fingerprint'
        # is accepted as a legacy alias.
        self.active_enabled = config.get("active_probing", config.get("active_fingerprint", True))
        self._ensure_db_columns()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def fingerprint_host(self, ip: str, open_ports: Optional[List[int]] = None) -> Dict:
        """
        Fingerprint a single host. Uses passive first, active if needed.

        Args:
            ip: Target IP address.
            open_ports: Known open ports (fetched from DB if None).

        Returns:
            Dict with keys: ip, os, confidence, method, details.
        """
        logger.info(f"Fingerprinting host: {ip}")

        # Fetch open ports from DB if not provided
        if open_ports is None:
            open_ports = self._get_ports_from_db(ip)

        # Phase 1: Passive fingerprint from existing data
        passive_result = self._passive_fingerprint(ip, open_ports)
        confidence = passive_result.get("confidence", 0.0)

        # Phase 2: Active fingerprint if passive confidence is low
        active_result = {}
        if confidence < 0.7 and self.active_enabled and SCAPY_AVAILABLE and open_ports:
            # Pick a common port for probing
            probe_port = self._select_probe_port(open_ports)
            if probe_port:
                self._stealth_delay()
                active_result = self._active_fingerprint(ip, probe_port)

        # Combine results
        combined = self._combine_results(passive_result, active_result)

        # Store in DB
        self._store_fingerprint(
            ip=ip,
            os_name=combined.get("os", "Unknown"),
            confidence=combined.get("confidence", 0.0),
            method=combined.get("method", "passive"),
            details=combined.get("details", {}),
        )

        logger.info(
            f"Fingerprint result for {ip}: {combined.get('os', 'Unknown')} "
            f"(confidence: {combined.get('confidence', 0.0):.2f})"
        )
        return combined

    def fingerprint_all(self) -> List[Dict]:
        """Fingerprint all active hosts in database."""
        results = []
        hosts = self._get_active_hosts()

        logger.info(f"Starting OS fingerprinting for {len(hosts)} active hosts")

        for i, (ip, ports_json) in enumerate(hosts):
            try:
                open_ports = json.loads(ports_json) if ports_json else []
            except (json.JSONDecodeError, TypeError):
                open_ports = []

            result = self.fingerprint_host(ip, open_ports)
            results.append(result)

            # Stealth delay between hosts (skip after last host)
            if i < len(hosts) - 1:
                self._stealth_delay()

        logger.info(f"Fingerprinting complete. {len(results)} hosts processed.")
        return results

    # ------------------------------------------------------------------
    # Passive Fingerprinting
    # ------------------------------------------------------------------

    def _passive_fingerprint(self, ip: str, open_ports: List[int]) -> Dict:
        """
        Infer OS from existing scan data (ports, banners, TTL from DB).
        No packets are sent — purely analyzes stored data.
        """
        signals = []
        details = {}

        # 1. Port-based hints
        port_hint = self._port_based_hints(open_ports)
        if port_hint.get("os"):
            signals.append(port_hint)
            details["port_hint"] = port_hint

        # 2. Banner-based hints
        banner_hint = self._banner_based_hints(ip)
        if banner_hint.get("os"):
            signals.append(banner_hint)
            details["banner_hint"] = banner_hint

        # 3. TTL from stored scan data
        ttl_hint = self._ttl_from_db(ip)
        if ttl_hint.get("os"):
            signals.append(ttl_hint)
            details["ttl_hint"] = ttl_hint

        # Combine passive signals
        if not signals:
            return {"ip": ip, "os": "Unknown", "confidence": 0.0, "method": "passive", "details": details}

        # Find consensus
        os_name, confidence = self._consensus_from_signals(signals)

        return {
            "ip": ip,
            "os": os_name,
            "confidence": confidence,
            "method": "passive",
            "details": details,
        }

    # ------------------------------------------------------------------
    # Active Fingerprinting
    # ------------------------------------------------------------------

    def _active_fingerprint(self, ip: str, open_port: int) -> Dict:
        """
        Active TCP stack probing using scapy. Sends crafted packets and
        analyzes response characteristics. Stealth-timed.

        Requires: scapy installed, raw socket privileges (admin/root).
        """
        if not SCAPY_AVAILABLE:
            logger.debug("Scapy not available, skipping active fingerprint")
            return {}

        logger.debug(f"Active fingerprinting {ip}:{open_port}")
        characteristics = {}

        try:
            # Suppress scapy verbosity
            conf.verb = 0

            # Probe 1: SYN to open port — analyze SYN/ACK
            syn_packet = IP(dst=ip) / TCP(
                dport=open_port,
                sport=random.randint(40000, 60000),
                flags="S",
                seq=random.randint(1000000, 9999999),
                window=1024,
                options=[("MSS", 1460), ("NOP", None), ("WScale", 2)],
            )

            response = sr1(syn_packet, timeout=5, verbose=0)

            if response and response.haslayer(TCP):
                tcp_layer = response.getlayer(TCP)
                ip_layer = response.getlayer(IP)

                # Extract characteristics
                characteristics["ttl"] = ip_layer.ttl
                characteristics["window"] = tcp_layer.window
                characteristics["df"] = bool(ip_layer.flags.DF)
                characteristics["tcp_options"] = self._parse_tcp_options(tcp_layer.options)
                characteristics["flags"] = str(tcp_layer.flags)

                # Send RST to clean up the half-open connection
                rst_packet = IP(dst=ip) / TCP(
                    dport=open_port,
                    sport=syn_packet[TCP].sport,
                    flags="R",
                    seq=syn_packet[TCP].seq + 1,
                )
                sr1(rst_packet, timeout=1, verbose=0)

            # Small delay before second probe
            time.sleep(self._apply_jitter(2.0))

            # Probe 2: SYN to likely closed port — analyze RST
            closed_port = self._find_closed_port(ip, open_port)
            if closed_port:
                syn_closed = IP(dst=ip) / TCP(
                    dport=closed_port,
                    sport=random.randint(40000, 60000),
                    flags="S",
                    seq=random.randint(1000000, 9999999),
                )

                rst_response = sr1(syn_closed, timeout=3, verbose=0)

                if rst_response and rst_response.haslayer(TCP):
                    rst_tcp = rst_response.getlayer(TCP)
                    rst_ip = rst_response.getlayer(IP)
                    # RST characteristics can help differentiate similar OSes
                    characteristics["rst_ttl"] = rst_ip.ttl
                    characteristics["rst_window"] = rst_tcp.window
                    characteristics["rst_df"] = bool(rst_ip.flags.DF)

        except PermissionError:
            logger.warning("Active fingerprinting requires admin/root privileges")
            return {}
        except OSError as e:
            logger.warning(f"Active fingerprinting failed for {ip}: {e}")
            return {}
        except Exception as e:
            logger.error(f"Unexpected error in active fingerprint for {ip}: {e}")
            return {}

        if not characteristics:
            return {}

        # Match against signature database
        os_name, confidence = self._match_signature(characteristics)

        return {
            "ip": ip,
            "os": os_name,
            "confidence": confidence,
            "method": "active",
            "details": {"characteristics": characteristics},
        }

    # ------------------------------------------------------------------
    # Signature Matching
    # ------------------------------------------------------------------

    def _match_signature(self, characteristics: Dict) -> Tuple[str, float]:
        """
        Match observed characteristics against OS signature database.
        Returns (os_name, confidence_score 0.0-1.0).
        """
        if not characteristics:
            return ("Unknown", 0.0)

        observed_ttl = characteristics.get("ttl", 0)
        observed_window = characteristics.get("window", 0)
        observed_df = characteristics.get("df")
        observed_options = characteristics.get("tcp_options", [])

        best_match = "Unknown"
        best_score = 0.0

        for os_name, sig in OS_SIGNATURES.items():
            score = 0.0
            max_possible = 0.0

            # TTL matching (normalize to initial TTL)
            initial_ttl = self._normalize_ttl(observed_ttl)
            max_possible += 0.35
            if initial_ttl == sig["ttl"]:
                score += 0.35
            elif abs(initial_ttl - sig["ttl"]) <= 5:
                score += 0.15

            # Window size matching
            max_possible += 0.25
            if observed_window in sig["window"]:
                score += 0.25
            else:
                # Check if within range for signatures with multiple windows
                if sig["window"]:
                    min_win = min(sig["window"])
                    max_win = max(sig["window"])
                    if min_win <= observed_window <= max_win:
                        score += 0.15

            # DF bit matching
            max_possible += 0.15
            if observed_df is not None and observed_df == sig["df"]:
                score += 0.15

            # TCP options ordering
            max_possible += 0.25
            if observed_options and sig["tcp_options"]:
                options_similarity = self._options_similarity(observed_options, sig["tcp_options"])
                score += 0.25 * options_similarity

            # Normalize score
            if max_possible > 0:
                normalized = score / max_possible
                # Scale to confidence range for active fingerprinting: 0.7-0.95
                confidence = 0.7 + (normalized * 0.25)
            else:
                confidence = 0.0

            if confidence > best_score:
                best_score = confidence
                best_match = os_name

        return (best_match, min(best_score, 0.95))

    def _options_similarity(self, observed: List[str], expected: List[str]) -> float:
        """
        Compare TCP options ordering. Returns similarity score 0.0-1.0.
        Considers both presence and ordering of options.
        """
        if not observed or not expected:
            return 0.0

        # Presence score: what fraction of expected options are present
        observed_set = set(observed)
        expected_set = set(expected)
        if not expected_set:
            return 0.0

        presence_score = len(observed_set & expected_set) / len(expected_set)

        # Order score: longest common subsequence ratio
        order_score = self._lcs_ratio(observed, expected)

        # Weighted combination (order matters more)
        return 0.4 * presence_score + 0.6 * order_score

    def _lcs_ratio(self, seq1: List[str], seq2: List[str]) -> float:
        """Longest common subsequence ratio."""
        if not seq1 or not seq2:
            return 0.0

        m, n = len(seq1), len(seq2)
        dp = [[0] * (n + 1) for _ in range(m + 1)]

        for i in range(1, m + 1):
            for j in range(1, n + 1):
                if seq1[i - 1] == seq2[j - 1]:
                    dp[i][j] = dp[i - 1][j - 1] + 1
                else:
                    dp[i][j] = max(dp[i - 1][j], dp[i][j - 1])

        lcs_len = dp[m][n]
        return lcs_len / max(m, n)

    # ------------------------------------------------------------------
    # Hint Extraction Methods
    # ------------------------------------------------------------------

    def _port_based_hints(self, open_ports: List[int]) -> Dict:
        """
        Infer OS from open port combinations.
        Returns dict with 'os' and 'confidence' keys.
        """
        if not open_ports:
            return {"os": None, "confidence": 0.0}

        port_set = set(open_ports)
        os_guess = None
        confidence = 0.0

        # Windows indicators
        windows_ports = {445, 135, 139, 3389}
        windows_match = port_set & windows_ports
        if len(windows_match) >= 3:
            os_guess = "Windows 10/11/Server 2016+"
            confidence = 0.5
        elif len(windows_match) >= 2:
            os_guess = "Windows 10/11/Server 2016+"
            confidence = 0.4

        # macOS indicators
        elif 548 in port_set and 5900 in port_set:
            os_guess = "macOS/iOS"
            confidence = 0.45

        # IPMI = server/BMC hardware
        elif 623 in port_set:
            os_guess = "Embedded/IoT"
            confidence = 0.35

        # Network device: SNMP + Telnet + very few ports
        elif 161 in port_set and 23 in port_set and len(open_ports) <= 5:
            os_guess = "Cisco IOS"
            confidence = 0.4

        # Printer indicators
        elif 9100 in port_set or 515 in port_set:
            if len(open_ports) <= 6:
                os_guess = "HP Printer"
                confidence = 0.35

        # Linux/Unix: SSH present, no Windows ports
        elif 22 in port_set and not (port_set & {445, 135, 139}):
            os_guess = "Linux 4.x/5.x/6.x"
            confidence = 0.35

        # ESXi indicators
        elif 902 in port_set and 443 in port_set:
            os_guess = "VMware ESXi"
            confidence = 0.4

        if os_guess:
            return {"os": os_guess, "confidence": confidence, "source": "ports"}
        return {"os": None, "confidence": 0.0}

    def _banner_based_hints(self, ip: str) -> Dict:
        """
        Extract OS hints from service banners stored in DB.
        Searches for OS-identifying keywords in banner text.
        """
        try:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.execute(
                    "SELECT p.banner FROM ports p "
                    "JOIN hosts h ON h.id = p.host_id "
                    "WHERE h.ip = ? AND p.banner IS NOT NULL AND p.banner != '' AND p.is_active = 1",
                    (ip,),
                )
                rows = cursor.fetchall()
            finally:
                conn.close()
        except sqlite3.Error as e:
            logger.debug(f"DB error fetching banners for {ip}: {e}")
            return {"os": None, "confidence": 0.0}

        if not rows:
            return {"os": None, "confidence": 0.0}

        # Search banners for OS keywords
        all_banners = " ".join(row[0].lower() for row in rows if row[0])

        for keyword, os_name in BANNER_OS_KEYWORDS.items():
            if keyword in all_banners:
                # More specific keywords get higher confidence
                if keyword in (
                    "ubuntu",
                    "debian",
                    "centos",
                    "red hat",
                    "freebsd",
                    "windows server 2019",
                    "windows server 2022",
                    "esxi",
                ):
                    confidence = 0.8
                elif keyword in ("linux", "windows", "cisco", "microsoft"):
                    confidence = 0.65
                else:
                    confidence = 0.6

                return {"os": os_name, "confidence": confidence, "source": "banner", "keyword": keyword}

        return {"os": None, "confidence": 0.0}

    def _ttl_from_db(self, ip: str) -> Dict:
        """
        Retrieve TTL values from stored scan data and infer OS family.
        """
        try:
            conn = sqlite3.connect(self.db_path)
            try:
                # TTL data may be stored if active probing was done; check ports table
                # for any TTL column or fall back gracefully
                try:
                    cursor = conn.execute(
                        "SELECT ttl FROM ports p JOIN hosts h ON h.id = p.host_id "
                        "WHERE h.ip = ? AND p.ttl IS NOT NULL ORDER BY p.last_seen DESC LIMIT 5",
                        (ip,),
                    )
                    rows = cursor.fetchall()
                except sqlite3.OperationalError:
                    # ttl column doesn't exist in ports table — that's OK
                    rows = []
            finally:
                conn.close()
        except sqlite3.Error as e:
            logger.debug(f"DB error fetching TTL for {ip}: {e}")
            return {"os": None, "confidence": 0.0}

        if not rows:
            return {"os": None, "confidence": 0.0}

        # Use median TTL to reduce noise
        ttl_values = [row[0] for row in rows if row[0]]
        if not ttl_values:
            return {"os": None, "confidence": 0.0}

        median_ttl = sorted(ttl_values)[len(ttl_values) // 2]
        initial_ttl = self._normalize_ttl(median_ttl)

        # Map initial TTL to OS family
        if initial_ttl == 128:
            return {"os": "Windows 10/11/Server 2016+", "confidence": 0.4, "source": "ttl", "ttl": median_ttl}
        elif initial_ttl == 64:
            return {"os": "Linux 4.x/5.x/6.x", "confidence": 0.3, "source": "ttl", "ttl": median_ttl}
        elif initial_ttl == 255:
            return {"os": "Cisco IOS", "confidence": 0.35, "source": "ttl", "ttl": median_ttl}
        elif initial_ttl == 60:
            return {"os": "HP Printer", "confidence": 0.3, "source": "ttl", "ttl": median_ttl}

        return {"os": None, "confidence": 0.0}

    # ------------------------------------------------------------------
    # Result Combination & Consensus
    # ------------------------------------------------------------------

    def _consensus_from_signals(self, signals: List[Dict]) -> Tuple[str, float]:
        """
        Build consensus from multiple passive signals.
        Boosts confidence when multiple sources agree.
        """
        if not signals:
            return ("Unknown", 0.0)

        # Group by OS guess
        os_votes: Dict[str, List[float]] = {}
        for signal in signals:
            os_name = signal.get("os")
            conf = signal.get("confidence", 0.0)
            if os_name:
                os_votes.setdefault(os_name, []).append(conf)

        if not os_votes:
            return ("Unknown", 0.0)

        # Find OS with highest combined confidence
        best_os = "Unknown"
        best_conf = 0.0

        for os_name, confidences in os_votes.items():
            # Base confidence: highest single signal
            base = max(confidences)

            # Boost for multiple agreeing signals
            if len(confidences) >= 3:
                boosted = min(base + 0.25, 0.95)
            elif len(confidences) >= 2:
                boosted = min(base + 0.15, 0.90)
            else:
                boosted = base

            if boosted > best_conf:
                best_conf = boosted
                best_os = os_name

        return (best_os, best_conf)

    def _combine_results(self, passive: Dict, active: Dict) -> Dict:
        """
        Combine passive and active fingerprinting results.
        Active results generally have higher confidence.
        """
        if not active or not active.get("os"):
            return passive

        if not passive or not passive.get("os") or passive.get("os") == "Unknown":
            return active

        # Both have results — check agreement
        passive_os = passive.get("os", "Unknown")
        active_os = active.get("os", "Unknown")
        passive_conf = passive.get("confidence", 0.0)
        active_conf = active.get("confidence", 0.0)

        if passive_os == active_os:
            # Agreement: boost confidence
            combined_conf = min(max(passive_conf, active_conf) + 0.15, 0.98)
            return {
                "ip": passive.get("ip", active.get("ip")),
                "os": active_os,
                "confidence": combined_conf,
                "method": "combined",
                "details": {
                    "passive": passive.get("details", {}),
                    "active": active.get("details", {}),
                },
            }
        else:
            # Disagreement: prefer higher confidence
            if active_conf >= passive_conf:
                winner = active
            else:
                winner = passive

            winner_copy = dict(winner)
            winner_copy["details"] = {
                "passive": passive.get("details", {}),
                "active": active.get("details", {}),
                "note": "passive/active disagreement",
            }
            return winner_copy

    # ------------------------------------------------------------------
    # Database Methods
    # ------------------------------------------------------------------

    def _ensure_db_columns(self):
        """Ensure os_fingerprint columns exist in hosts table."""
        try:
            conn = sqlite3.connect(self.db_path)
            try:
                try:
                    conn.execute("ALTER TABLE hosts ADD COLUMN os_fingerprint TEXT")
                except sqlite3.OperationalError:
                    pass  # Column already exists
                try:
                    conn.execute("ALTER TABLE hosts ADD COLUMN os_confidence REAL DEFAULT 0.0")
                except sqlite3.OperationalError:
                    pass  # Column already exists
                conn.commit()
            finally:
                conn.close()
        except sqlite3.Error as e:
            logger.warning(f"Could not ensure DB columns: {e}")

    def _store_fingerprint(self, ip: str, os_name: str, confidence: float, method: str, details: dict):
        """Store OS fingerprint result in the hosts table."""
        # Store plain OS name string for dashboard display
        display_name = os_name if os_name and os_name != "Unknown" else None

        try:
            conn = sqlite3.connect(self.db_path)
            try:
                conn.execute(
                    "UPDATE hosts SET os_fingerprint = ?, os_confidence = ?, last_seen = ? WHERE ip = ?",
                    (display_name, confidence, datetime.now(timezone.utc).isoformat(), ip),
                )
                conn.commit()
            finally:
                conn.close()
            logger.debug(f"Stored fingerprint for {ip}: {os_name} ({confidence:.2f})")
        except sqlite3.Error as e:
            logger.error(f"Failed to store fingerprint for {ip}: {e}")

    def _get_ports_from_db(self, ip: str) -> List[int]:
        """Retrieve open ports for a host from the database."""
        try:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.execute(
                    "SELECT p.port FROM ports p "
                    "JOIN hosts h ON h.id = p.host_id "
                    "WHERE h.ip = ? AND p.state = 'open' AND p.is_active = 1",
                    (ip,),
                )
                ports = [row[0] for row in cursor.fetchall()]
            finally:
                conn.close()
            return ports
        except sqlite3.Error as e:
            logger.debug(f"DB error fetching ports for {ip}: {e}")
            return []

    def _get_active_hosts(self) -> List[Tuple[str, Optional[str]]]:
        """Retrieve all active hosts with their open ports from the database."""
        try:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.execute(
                    "SELECT h.ip, GROUP_CONCAT(p.port) as ports "
                    "FROM hosts h "
                    "LEFT JOIN ports p ON p.host_id = h.id AND p.state = 'open' AND p.is_active = 1 "
                    "WHERE h.is_active = 1 "
                    "GROUP BY h.id"
                )
                # Return as list of (ip, json_ports_string)
                results = []
                for row in cursor.fetchall():
                    ip = row[0]
                    ports_csv = row[1]
                    if ports_csv:
                        ports_list = [int(p) for p in ports_csv.split(",")]
                        results.append((ip, json.dumps(ports_list)))
                    else:
                        results.append((ip, None))
            finally:
                conn.close()
            return results
        except sqlite3.Error as e:
            logger.error(f"DB error fetching active hosts: {e}")
            return []

    # ------------------------------------------------------------------
    # Utility Methods
    # ------------------------------------------------------------------

    def _stealth_delay(self):
        """Apply a randomized stealth delay between operations."""
        base_delay = random.uniform(self.min_delay, self.max_delay)
        actual_delay = self._apply_jitter(base_delay)
        logger.debug(f"Stealth delay: {actual_delay:.1f}s")
        time.sleep(actual_delay)

    def _apply_jitter(self, base_delay: float) -> float:
        """Apply random jitter to a base delay value."""
        jitter_range = base_delay * self.jitter_factor
        jitter = random.uniform(-jitter_range, jitter_range)
        return max(0.5, base_delay + jitter)

    def _normalize_ttl(self, observed_ttl: int) -> int:
        """
        Normalize an observed TTL to its likely initial value.
        Accounts for hops between source and target.
        """
        if observed_ttl <= 0:
            return 0
        elif observed_ttl <= 32:
            return 32
        elif observed_ttl <= 64:
            return 64
        elif observed_ttl <= 128:
            return 128
        elif observed_ttl <= 255:
            return 255
        return observed_ttl

    def _parse_tcp_options(self, options) -> List[str]:
        """
        Parse scapy TCP options into a list of option names.
        Scapy returns options as list of tuples: [(name, value), ...]
        """
        parsed = []
        if not options:
            return parsed

        for opt in options:
            if isinstance(opt, tuple) and len(opt) >= 1:
                name = opt[0]
                # Normalize option names
                name_map = {
                    "MSS": "MSS",
                    "NOP": "NOP",
                    "WScale": "WS",
                    "SAckOK": "SACK",
                    "Timestamp": "Timestamp",
                    "EOL": "EOL",
                }
                parsed.append(name_map.get(name, name))
            elif isinstance(opt, str):
                parsed.append(opt)

        return parsed

    def _select_probe_port(self, open_ports: List[int]) -> Optional[int]:
        """
        Select the best port for active probing.
        Prefers common ports that are less likely to trigger alerts.
        """
        # Preferred probe ports (common, less suspicious)
        preferred = [80, 443, 22, 25, 21, 8080, 8443]

        for port in preferred:
            if port in open_ports:
                return port

        # Fall back to first available port
        return open_ports[0] if open_ports else None

    def _find_closed_port(self, ip: str, known_open: int) -> Optional[int]:
        """
        Find a likely closed port for RST analysis.
        Uses a high ephemeral port that's probably not in use.
        """
        # Try a random high port that's unlikely to be open
        candidates = [39871, 41523, 43917, 47291, 49183, 51847]
        random.shuffle(candidates)

        for port in candidates:
            if port != known_open:
                return port

        return None
