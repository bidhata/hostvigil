"""
PCAP Export Module - Captures and saves interesting network traffic.

When passive sniffing or scanning detects anomalies, this module can
save raw packets for later forensic analysis.

Requires scapy for packet capture. Falls back gracefully if unavailable.
"""

import logging
import re
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import List, Optional

try:
    from scapy.all import sniff as scapy_sniff
    from scapy.all import wrpcap

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

logger = logging.getLogger("hostvigil.pcap_export")

# Regex for validating IP addresses (IPv4)
_IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def _validate_ip(ip: str) -> bool:
    """Validate an IPv4 address to prevent BPF filter injection."""
    if not _IP_RE.match(ip):
        return False
    parts = ip.split(".")
    return all(0 <= int(p) <= 255 for p in parts)


def _validate_port(port) -> bool:
    """Validate a port number."""
    try:
        p = int(port)
        return 1 <= p <= 65535
    except (TypeError, ValueError):
        return False


class PcapExporter:
    """Captures and exports interesting network traffic to PCAP files."""

    def __init__(self, config: dict = None):
        config = config or {}
        self.output_dir = Path(config.get("pcap_dir", "data/pcap"))
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.max_packets = config.get("max_packets_per_capture", 1000)
        self.max_file_size_mb = config.get("max_file_size_mb", 50)
        self._capture_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._packets: List = []
        self._lock = threading.Lock()

    def capture_traffic(self, filter_str: str = "", duration: int = 60, filename: str = None) -> Optional[str]:
        """Capture traffic matching filter for specified duration.

        Args:
            filter_str: BPF filter (e.g., 'host 10.0.0.1', 'port 4444')
            duration: Capture duration in seconds
            filename: Output filename (auto-generated if None)

        Returns:
            Path to saved PCAP file, or None if scapy unavailable.
        """
        if not SCAPY_AVAILABLE:
            logger.warning("PCAP export requires scapy - skipping")
            return None

        if not filename:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_filter = filter_str.replace(" ", "_")[:30] if filter_str else "all"
            # Remove any path separators from auto-generated filter portion
            safe_filter = safe_filter.replace("/", "").replace("\\", "").replace("..", "")
            filename = f"capture_{ts}_{safe_filter}.pcap"

        # Security: prevent path traversal in user-supplied filename
        # Only use the basename and ensure it stays within output_dir
        filename = Path(filename).name
        if not filename or filename.startswith("."):
            filename = f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        output_path = self.output_dir / filename

        logger.info(f"Starting PCAP capture: filter='{filter_str}', duration={duration}s")

        try:
            packets = scapy_sniff(
                filter=filter_str,
                timeout=duration,
                count=self.max_packets,
                store=True,
            )

            if packets:
                wrpcap(str(output_path), packets)
                logger.info(f"PCAP saved: {output_path} ({len(packets)} packets)")
                return str(output_path)
            else:
                logger.info("No packets captured")
                return None

        except PermissionError:
            logger.error("PCAP capture requires root/admin privileges")
            return None
        except Exception as e:
            logger.error(f"PCAP capture failed: {e}")
            return None

    def capture_host_traffic(self, ip: str, duration: int = 30) -> Optional[str]:
        """Capture all traffic to/from a specific host."""
        if not _validate_ip(ip):
            logger.error(f"Invalid IP address for PCAP capture: {ip!r}")
            return None
        return self.capture_traffic(filter_str=f"host {ip}", duration=duration)

    def capture_port_traffic(self, port: int, duration: int = 30) -> Optional[str]:
        """Capture traffic on a specific port."""
        if not _validate_port(port):
            logger.error(f"Invalid port for PCAP capture: {port!r}")
            return None
        return self.capture_traffic(filter_str=f"port {int(port)}", duration=duration)

    def capture_anomaly_traffic(self, ip: str, ports: List[int] = None, duration: int = 60) -> Optional[str]:
        """Capture traffic for a host flagged as anomalous.

        Called automatically when the ML engine flags a high-confidence anomaly.
        """
        if not _validate_ip(ip):
            logger.error(f"Invalid IP address for anomaly capture: {ip!r}")
            return None

        if ports:
            # Validate all ports before constructing filter
            valid_ports = [int(p) for p in ports[:5] if _validate_port(p)]
            if valid_ports:
                port_filter = " or ".join(f"port {p}" for p in valid_ports)
                filter_str = f"host {ip} and ({port_filter})"
            else:
                filter_str = f"host {ip}"
        else:
            filter_str = f"host {ip}"

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"anomaly_{ip}_{ts}.pcap"
        return self.capture_traffic(filter_str=filter_str, duration=duration, filename=filename)

    def start_background_capture(self, filter_str: str = "", filename: str = None) -> bool:
        """Start a background packet capture (non-blocking).

        Call stop_background_capture() to end and save.
        """
        if not SCAPY_AVAILABLE:
            logger.warning("PCAP export requires scapy")
            return False

        if self._capture_thread and self._capture_thread.is_alive():
            logger.warning("Background capture already running")
            return False

        self._stop_event.clear()
        self._packets = []

        if not filename:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"bg_capture_{ts}.pcap"

        # Security: prevent path traversal in filename
        filename = Path(filename).name
        if not filename or filename.startswith("."):
            filename = f"bg_capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"

        self._bg_filename = filename

        def _capture():
            try:
                packets = scapy_sniff(
                    filter=filter_str,
                    stop_filter=lambda p: self._stop_event.is_set(),
                    count=self.max_packets,
                    store=True,
                    timeout=3600,  # Max 1 hour
                )
                with self._lock:
                    self._packets = packets
            except Exception as e:
                logger.error(f"Background capture error: {e}")

        self._capture_thread = threading.Thread(target=_capture, daemon=True, name="pcap-capture")
        self._capture_thread.start()
        logger.info(f"Background PCAP capture started: filter='{filter_str}'")
        return True

    def stop_background_capture(self) -> Optional[str]:
        """Stop background capture and save PCAP file."""
        if not self._capture_thread or not self._capture_thread.is_alive():
            logger.warning("No background capture running")
            return None

        self._stop_event.set()
        self._capture_thread.join(timeout=5)

        with self._lock:
            packets = self._packets

        if packets:
            output_path = self.output_dir / self._bg_filename
            wrpcap(str(output_path), packets)
            logger.info(f"Background PCAP saved: {output_path} ({len(packets)} packets)")
            return str(output_path)

        return None

    def list_captures(self) -> List[dict]:
        """List all saved PCAP files."""
        captures = []
        for pcap_file in sorted(self.output_dir.glob("*.pcap"), reverse=True):
            stat = pcap_file.stat()
            captures.append(
                {
                    "filename": pcap_file.name,
                    "path": str(pcap_file),
                    "size_bytes": stat.st_size,
                    "size_mb": round(stat.st_size / 1024 / 1024, 2),
                    "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                }
            )
        return captures

    def cleanup_old_captures(self, max_age_days: int = 7, max_total_mb: int = 500):
        """Remove old PCAP files to manage disk space."""
        cutoff = time.time() - (max_age_days * 86400)
        total_size = 0
        files_by_age = []

        for pcap_file in self.output_dir.glob("*.pcap"):
            stat = pcap_file.stat()
            files_by_age.append((stat.st_ctime, stat.st_size, pcap_file))
            total_size += stat.st_size

        # Remove files older than max_age_days
        for ctime, size, path in files_by_age:
            if ctime < cutoff:
                path.unlink()
                total_size -= size
                logger.info(f"Cleaned old PCAP: {path.name}")

        # If still over size limit, remove oldest first
        files_by_age.sort()
        max_bytes = max_total_mb * 1024 * 1024
        while total_size > max_bytes and files_by_age:
            ctime, size, path = files_by_age.pop(0)
            if path.exists():
                path.unlink()
                total_size -= size
                logger.info(f"Cleaned PCAP (size limit): {path.name}")
