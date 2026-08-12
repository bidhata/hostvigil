"""
C2-Friendly Export Module - Export scan results for offensive tool integration.

Exports HostVigil reconnaissance data in formats compatible with popular
Command & Control frameworks and offensive security tools.

Supported formats:
- Cobalt Strike: Tab-separated target list
- Metasploit: XML workspace import (MetasploitV5 schema)
- Sliver: JSON implant target configuration
- Nmap XML: Standard nmap output format (compatible with many tools)
- Targets TXT: Simple ip:port list for piping

No external dependencies.
"""

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional
from xml.sax.saxutils import escape as xml_escape

logger = logging.getLogger("hostvigil.c2_export")
PROJECT_ROOT = Path(__file__).resolve().parent.parent


class C2Exporter:
    """Export scan results in C2 framework-compatible formats."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.output_dir = PROJECT_ROOT / "data" / "reports"
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _connect(self) -> sqlite3.Connection:
        """Create database connection with row factory."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _get_hosts_with_ports(self) -> List[Dict]:
        """Fetch all hosts with their open ports from the database."""
        conn = self._connect()
        hosts = {}

        try:
            # Fetch hosts
            host_cursor = conn.execute("""
                SELECT id, ip, mac, hostname, os_fingerprint, first_seen, last_seen
                FROM hosts WHERE is_active = 1
            """)

            for row in host_cursor:
                hosts[row["id"]] = {
                    "id": row["id"],
                    "ip": row["ip"],
                    "mac": row["mac"] or "",
                    "hostname": row["hostname"] or "",
                    "os": row["os_fingerprint"] or "",
                    "first_seen": row["first_seen"] or "",
                    "last_seen": row["last_seen"] or "",
                    "ports": [],
                }

            # Fetch ports
            port_cursor = conn.execute("""
                SELECT host_id, port, protocol, state, service, banner,
                       first_seen, last_seen
                FROM ports WHERE is_active = 1 AND state = 'open'
                ORDER BY host_id, port
            """)

            for row in port_cursor:
                host_id = row["host_id"]
                if host_id in hosts:
                    hosts[host_id]["ports"].append(
                        {
                            "port": row["port"],
                            "protocol": row["protocol"] or "tcp",
                            "state": row["state"],
                            "service": row["service"] or "",
                            "banner": row["banner"] or "",
                            "first_seen": row["first_seen"] or "",
                            "last_seen": row["last_seen"] or "",
                        }
                    )

        except Exception as e:
            logger.error(f"Failed to fetch hosts/ports: {e}")
        finally:
            conn.close()

        return list(hosts.values())

    def _get_vulnerabilities(self) -> List[Dict]:
        """Fetch vulnerabilities for enriching exports."""
        conn = self._connect()
        vulns = []

        try:
            cursor = conn.execute("""
                SELECT v.host_id, h.ip, v.name, v.severity, v.description,
                       v.template_id, p.port, p.protocol
                FROM vulnerabilities v
                JOIN hosts h ON h.id = v.host_id
                LEFT JOIN ports p ON p.id = v.port_id
                ORDER BY h.ip
            """)
            for row in cursor:
                vulns.append(dict(row))
        except Exception as e:
            logger.debug(f"Failed to fetch vulnerabilities: {e}")
        finally:
            conn.close()

        return vulns

    def _generate_filename(self, prefix: str, ext: str) -> Path:
        """Generate timestamped output filename."""
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        return self.output_dir / f"{prefix}_{ts}.{ext}"

    # =========================================================================
    # COBALT STRIKE EXPORT
    # =========================================================================

    def export_cobalt_strike(self, output_path: str = None) -> str:
        """Export as Cobalt Strike target list format.

        Format: ip\\tport\\tservice\\tos\\n
        Compatible with Cobalt Strike's target import feature.

        Args:
            output_path: Custom output path, or None for auto-generated.

        Returns:
            Path to the generated file.
        """
        hosts = self._get_hosts_with_ports()
        out_path = Path(output_path) if output_path else self._generate_filename("cs_targets", "tsv")

        lines = []
        for host in hosts:
            if host["ports"]:
                for port_info in host["ports"]:
                    line = "\t".join(
                        [
                            host["ip"],
                            str(port_info["port"]),
                            port_info["service"] or "unknown",
                            host["os"] or "unknown",
                        ]
                    )
                    lines.append(line)
            else:
                # Host with no ports still useful for CS targeting
                lines.append(f"{host['ip']}\t0\tunknown\t{host['os'] or 'unknown'}")

        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        logger.info(f"Cobalt Strike export: {len(lines)} entries -> {out_path}")
        return str(out_path)

    # =========================================================================
    # METASPLOIT EXPORT
    # =========================================================================

    def export_metasploit(self, output_path: str = None) -> str:
        """Export as Metasploit workspace XML import format.

        Generates valid MetasploitV5 XML that can be imported via:
            db_import <file.xml>

        Args:
            output_path: Custom output path, or None for auto-generated.

        Returns:
            Path to the generated file.
        """
        hosts = self._get_hosts_with_ports()
        vulns = self._get_vulnerabilities()
        out_path = Path(output_path) if output_path else self._generate_filename("msf_workspace", "xml")

        # Build vulnerability lookup by IP
        vuln_by_ip: Dict[str, List[Dict]] = {}
        for v in vulns:
            ip = v.get("ip", "")
            if ip not in vuln_by_ip:
                vuln_by_ip[ip] = []
            vuln_by_ip[ip].append(v)

        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        xml_parts = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            "<MetasploitV5>",
            f"  <generated_at>{now}</generated_at>",
            "  <hosts>",
        ]

        for host in hosts:
            ip = xml_escape(host["ip"])
            mac = xml_escape(host["mac"])
            hostname = xml_escape(host["hostname"])
            os_name = xml_escape(host["os"])

            # Determine OS flavor/family
            os_family = self._guess_os_family(host["os"])

            xml_parts.append("    <host>")
            xml_parts.append(f"      <address>{ip}</address>")
            xml_parts.append(f"      <mac>{mac}</mac>")
            xml_parts.append("      <state>alive</state>")
            xml_parts.append(f"      <name>{hostname}</name>")
            xml_parts.append(f"      <os-name>{os_name}</os-name>")
            xml_parts.append(f"      <os-family>{xml_escape(os_family)}</os-family>")
            xml_parts.append(f"      <created-at>{now}</created-at>")
            xml_parts.append(f"      <updated-at>{now}</updated-at>")

            # Services (ports)
            if host["ports"]:
                xml_parts.append("      <services>")
                for port_info in host["ports"]:
                    service = xml_escape(port_info["service"])
                    banner = xml_escape(port_info["banner"][:500]) if port_info["banner"] else ""
                    proto = xml_escape(port_info["protocol"])

                    xml_parts.append("        <service>")
                    xml_parts.append(f"          <port>{port_info['port']}</port>")
                    xml_parts.append(f"          <proto>{proto}</proto>")
                    xml_parts.append("          <state>open</state>")
                    xml_parts.append(f"          <name>{service}</name>")
                    xml_parts.append(f"          <info>{banner}</info>")
                    xml_parts.append(f"          <created-at>{now}</created-at>")
                    xml_parts.append(f"          <updated-at>{now}</updated-at>")
                    xml_parts.append("        </service>")
                xml_parts.append("      </services>")

            # Vulns for this host
            host_vulns = vuln_by_ip.get(host["ip"], [])
            if host_vulns:
                xml_parts.append("      <vulns>")
                for v in host_vulns:
                    vname = xml_escape(v.get("name", "Unknown"))
                    vdesc = xml_escape(v.get("description", "")[:1000])
                    vsev = xml_escape(v.get("severity", "info"))
                    vport = v.get("port", 0) or 0

                    xml_parts.append("        <vuln>")
                    xml_parts.append(f"          <name>{vname}</name>")
                    xml_parts.append(f"          <info>{vdesc}</info>")
                    xml_parts.append(f"          <severity>{vsev}</severity>")
                    xml_parts.append(f"          <port>{vport}</port>")
                    xml_parts.append(f"          <created-at>{now}</created-at>")
                    xml_parts.append(f"          <updated-at>{now}</updated-at>")
                    xml_parts.append("        </vuln>")
                xml_parts.append("      </vulns>")

            xml_parts.append("    </host>")

        xml_parts.append("  </hosts>")
        xml_parts.append("</MetasploitV5>")

        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text("\n".join(xml_parts) + "\n", encoding="utf-8")

        logger.info(f"Metasploit export: {len(hosts)} hosts -> {out_path}")
        return str(out_path)

    # =========================================================================
    # SLIVER EXPORT
    # =========================================================================

    def export_sliver(self, output_path: str = None) -> str:
        """Export as Sliver implant target configuration (JSON).

        Format:
        {
            "targets": [
                {"host": ip, "port": port, "os": os, "arch": arch,
                 "hostname": hostname, "services": [...]}
            ],
            "metadata": {...}
        }

        Args:
            output_path: Custom output path, or None for auto-generated.

        Returns:
            Path to the generated file.
        """
        hosts = self._get_hosts_with_ports()
        out_path = Path(output_path) if output_path else self._generate_filename("sliver_targets", "json")

        targets = []
        for host in hosts:
            os_name = host["os"].lower() if host["os"] else ""
            arch = self._guess_arch(os_name)
            os_type = self._guess_os_type(os_name)

            # Pick most interesting port for implant delivery
            implant_port = self._pick_implant_port(host["ports"])

            target = {
                "host": host["ip"],
                "port": implant_port,
                "hostname": host["hostname"],
                "os": os_type,
                "arch": arch,
                "services": [
                    {
                        "port": p["port"],
                        "protocol": p["protocol"],
                        "service": p["service"],
                    }
                    for p in host["ports"]
                ],
            }
            targets.append(target)

        export_data = {
            "targets": targets,
            "metadata": {
                "generated_by": "HostVigil",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "total_targets": len(targets),
                "format": "sliver_targets_v1",
            },
        }

        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(export_data, indent=2) + "\n", encoding="utf-8")

        logger.info(f"Sliver export: {len(targets)} targets -> {out_path}")
        return str(out_path)

    # =========================================================================
    # NMAP XML EXPORT
    # =========================================================================

    def export_nmap_xml(self, output_path: str = None) -> str:
        """Export in nmap XML format (compatible with many security tools).

        Generates valid nmap XML output that can be imported by:
        - Metasploit (db_import)
        - OpenVAS
        - Dradis
        - Faraday
        - Many other tools accepting nmap XML

        Args:
            output_path: Custom output path, or None for auto-generated.

        Returns:
            Path to the generated file.
        """
        hosts = self._get_hosts_with_ports()
        out_path = Path(output_path) if output_path else self._generate_filename("nmap_export", "xml")

        now = datetime.now(timezone.utc)
        start_ts = int(now.timestamp())
        start_str = now.strftime("%a %b %d %H:%M:%S %Y")

        total_up = len(hosts)
        total_ports = sum(len(h["ports"]) for h in hosts)

        xml_parts = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            "<!DOCTYPE nmaprun>",
            f'<nmaprun scanner="hostvigil" args="hostvigil stealth scan" '
            f'start="{start_ts}" startstr="{xml_escape(start_str)}" '
            f'version="1.0.0" xmloutputversion="1.05">',
            f'  <scaninfo type="connect" protocol="tcp" numservices="{total_ports}" services="1-65535"/>',
        ]

        for host in hosts:
            ip = xml_escape(host["ip"])
            hostname = xml_escape(host["hostname"])
            mac = xml_escape(host["mac"])

            xml_parts.append("  <host>")
            xml_parts.append('    <status state="up" reason="hostvigil-discovery"/>')
            xml_parts.append(f'    <address addr="{ip}" addrtype="ipv4"/>')

            if mac:
                xml_parts.append(f'    <address addr="{mac}" addrtype="mac"/>')

            if hostname:
                xml_parts.append("    <hostnames>")
                xml_parts.append(f'      <hostname name="{hostname}" type="PTR"/>')
                xml_parts.append("    </hostnames>")
            else:
                xml_parts.append("    <hostnames/>")

            # Ports
            if host["ports"]:
                xml_parts.append("    <ports>")
                for port_info in host["ports"]:
                    port_num = port_info["port"]
                    proto = xml_escape(port_info["protocol"])
                    service = xml_escape(port_info["service"])
                    banner = xml_escape(port_info["banner"][:200]) if port_info["banner"] else ""

                    xml_parts.append(f'      <port protocol="{proto}" portid="{port_num}">')
                    xml_parts.append('        <state state="open" reason="syn-ack" reason_ttl="64"/>')

                    # Service info
                    svc_attrs = f'name="{service}"' if service else 'name="unknown"'
                    if banner:
                        svc_attrs += f' product="{banner}"'

                    # Try to extract version from banner
                    version = self._extract_version(port_info["banner"])
                    if version:
                        svc_attrs += f' version="{xml_escape(version)}"'

                    xml_parts.append(f'        <service {svc_attrs} method="probed" conf="8"/>')
                    xml_parts.append("      </port>")
                xml_parts.append("    </ports>")

            # OS detection
            if host["os"]:
                os_name = xml_escape(host["os"])
                os_family = xml_escape(self._guess_os_family(host["os"]))
                xml_parts.append("    <os>")
                xml_parts.append(f'      <osmatch name="{os_name}" accuracy="85">')
                xml_parts.append(
                    f'        <osclass type="general purpose" '
                    f'vendor="{os_family}" osfamily="{os_family}" '
                    f'osgen="" accuracy="85"/>'
                )
                xml_parts.append("      </osmatch>")
                xml_parts.append("    </os>")

            xml_parts.append("  </host>")

        # Run stats
        xml_parts.append("  <runstats>")
        xml_parts.append(f'    <finished time="{start_ts}" timestr="{xml_escape(start_str)}" exit="success"/>')
        xml_parts.append(f'    <hosts up="{total_up}" down="0" total="{total_up}"/>')
        xml_parts.append("  </runstats>")
        xml_parts.append("</nmaprun>")

        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text("\n".join(xml_parts) + "\n", encoding="utf-8")

        logger.info(f"Nmap XML export: {total_up} hosts, {total_ports} ports -> {out_path}")
        return str(out_path)

    # =========================================================================
    # SIMPLE TARGETS TXT
    # =========================================================================

    def export_targets_txt(self, output_path: str = None, protocol: str = None) -> str:
        """Simple ip:port list for piping to other tools.

        Format: ip:port (one per line)
        Useful for: masscan, httpx, nuclei, ffuf, etc.

        Args:
            output_path: Custom output path, or None for auto-generated.
            protocol: Filter by protocol ('tcp' or 'udp'), or None for all.

        Returns:
            Path to the generated file.
        """
        hosts = self._get_hosts_with_ports()
        out_path = Path(output_path) if output_path else self._generate_filename("targets", "txt")

        lines = []
        for host in hosts:
            for port_info in host["ports"]:
                if protocol and port_info["protocol"] != protocol:
                    continue
                lines.append(f"{host['ip']}:{port_info['port']}")

        # Deduplicate and sort
        lines = sorted(set(lines))

        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        logger.info(f"Targets TXT export: {len(lines)} entries -> {out_path}")
        return str(out_path)

    def export_urls(self, output_path: str = None) -> str:
        """Export HTTP/HTTPS URLs for web scanning tools (httpx, nuclei, etc.).

        Args:
            output_path: Custom output path, or None for auto-generated.

        Returns:
            Path to the generated file.
        """
        hosts = self._get_hosts_with_ports()
        out_path = Path(output_path) if output_path else self._generate_filename("urls", "txt")

        http_ports = {80, 8080, 8000, 8888, 3000, 5000, 9090}
        https_ports = {443, 8443, 9443, 4443}

        urls = []
        for host in hosts:
            for port_info in host["ports"]:
                port = port_info["port"]
                service = (port_info["service"] or "").lower()

                if port in https_ports or "https" in service or "ssl" in service:
                    urls.append(f"https://{host['ip']}:{port}")
                elif port in http_ports or "http" in service:
                    urls.append(f"http://{host['ip']}:{port}")
                elif port_info["banner"] and ("HTTP" in port_info["banner"]):
                    urls.append(f"http://{host['ip']}:{port}")

        urls = sorted(set(urls))

        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text("\n".join(urls) + "\n", encoding="utf-8")

        logger.info(f"URLs export: {len(urls)} entries -> {out_path}")
        return str(out_path)

    def export_all(self, output_dir: str = None) -> Dict[str, str]:
        """Export in all formats at once.

        Args:
            output_dir: Custom output directory, or None for default.

        Returns:
            Dict mapping format name to output file path.
        """
        if output_dir:
            self.output_dir = Path(output_dir)
            self.output_dir.mkdir(parents=True, exist_ok=True)

        results = {}
        try:
            results["cobalt_strike"] = self.export_cobalt_strike()
        except Exception as e:
            logger.error(f"Cobalt Strike export failed: {e}")

        try:
            results["metasploit"] = self.export_metasploit()
        except Exception as e:
            logger.error(f"Metasploit export failed: {e}")

        try:
            results["sliver"] = self.export_sliver()
        except Exception as e:
            logger.error(f"Sliver export failed: {e}")

        try:
            results["nmap_xml"] = self.export_nmap_xml()
        except Exception as e:
            logger.error(f"Nmap XML export failed: {e}")

        try:
            results["targets_txt"] = self.export_targets_txt()
        except Exception as e:
            logger.error(f"Targets TXT export failed: {e}")

        try:
            results["urls"] = self.export_urls()
        except Exception as e:
            logger.error(f"URLs export failed: {e}")

        try:
            results["ips_only"] = self.export_ips_only()
        except Exception as e:
            logger.error(f"IPs-only export failed: {e}")

        logger.info(f"All exports complete: {len(results)} formats generated")
        return results

    def export_ips_only(self, output_path: str = None, active_only: bool = True) -> str:
        """Export plain IP list (one per line) for feeding into other tools.

        Useful for: nmap, masscan, zmap, naabu, ping sweep, etc.

        Args:
            output_path: Custom output path, or None for auto-generated.
            active_only: Only export active/alive hosts.

        Returns:
            Path to the generated file.
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            if active_only:
                rows = conn.execute("SELECT DISTINCT ip FROM hosts WHERE is_active = 1 ORDER BY ip").fetchall()
            else:
                rows = conn.execute("SELECT DISTINCT ip FROM hosts ORDER BY ip").fetchall()
        finally:
            conn.close()

        ips = [row["ip"] for row in rows]
        out_path = Path(output_path) if output_path else self._generate_filename("ips_alive", "txt")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text("\n".join(ips) + "\n", encoding="utf-8")

        logger.info(f"IPs-only export: {len(ips)} IPs -> {out_path}")
        return str(out_path)

    def export_by_port(self, port: int, output_path: str = None) -> str:
        """Export IPs that have a specific port open.

        E.g., export all hosts with port 445 open for SMB testing.

        Args:
            port: Port number to filter by.
            output_path: Custom output path.

        Returns:
            Path to the generated file.
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                "SELECT DISTINCT h.ip FROM hosts h JOIN ports p ON p.host_id = h.id "
                "WHERE p.port = ? AND p.is_active = 1 AND h.is_active = 1 ORDER BY h.ip",
                (port,),
            ).fetchall()
        finally:
            conn.close()

        ips = [row["ip"] for row in rows]
        out_path = Path(output_path) if output_path else self._generate_filename(f"port_{port}_hosts", "txt")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text("\n".join(ips) + "\n", encoding="utf-8")

        logger.info(f"Port {port} hosts export: {len(ips)} IPs -> {out_path}")
        return str(out_path)

    def export_by_service(self, service: str, output_path: str = None) -> str:
        """Export ip:port pairs for a specific service (e.g., 'SSH', 'HTTP', 'SMB').

        Args:
            service: Service name to filter by.
            output_path: Custom output path.

        Returns:
            Path to the generated file.
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                "SELECT DISTINCT h.ip, p.port FROM hosts h JOIN ports p ON p.host_id = h.id "
                "WHERE LOWER(p.service) = LOWER(?) AND p.is_active = 1 AND h.is_active = 1 ORDER BY h.ip",
                (service,),
            ).fetchall()
        finally:
            conn.close()

        lines = [f"{row['ip']}:{row['port']}" for row in rows]
        out_path = Path(output_path) if output_path else self._generate_filename(f"service_{service.lower()}", "txt")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        logger.info(f"Service '{service}' export: {len(lines)} targets -> {out_path}")
        return str(out_path)

    # =========================================================================
    # HELPER METHODS
    # =========================================================================

    @staticmethod
    def _guess_os_family(os_str: str) -> str:
        """Guess OS family from fingerprint string."""
        if not os_str:
            return "Unknown"
        os_lower = os_str.lower()
        if "windows" in os_lower:
            return "Windows"
        elif "linux" in os_lower or "ubuntu" in os_lower or "debian" in os_lower or "centos" in os_lower:
            return "Linux"
        elif "mac" in os_lower or "darwin" in os_lower or "ios" in os_lower:
            return "macOS"
        elif "freebsd" in os_lower or "openbsd" in os_lower:
            return "BSD"
        elif "cisco" in os_lower:
            return "Cisco"
        elif "juniper" in os_lower or "junos" in os_lower:
            return "Juniper"
        return "Unknown"

    @staticmethod
    def _guess_os_type(os_str: str) -> str:
        """Guess OS type for Sliver (windows/linux/darwin)."""
        if not os_str:
            return "linux"
        os_lower = os_str.lower()
        if "windows" in os_lower:
            return "windows"
        elif "mac" in os_lower or "darwin" in os_lower:
            return "darwin"
        return "linux"

    @staticmethod
    def _guess_arch(os_str: str) -> str:
        """Guess architecture from OS string."""
        if not os_str:
            return "amd64"
        if "arm" in os_str or "aarch64" in os_str:
            return "arm64"
        if "32-bit" in os_str or "i386" in os_str or "i686" in os_str:
            return "386"
        return "amd64"

    @staticmethod
    def _pick_implant_port(ports: List[Dict]) -> int:
        """Pick the best port for implant delivery from available ports."""
        # Prefer common implant delivery ports
        preferred = [443, 8443, 80, 8080, 445, 5985, 22, 3389]
        port_numbers = {p["port"] for p in ports}

        for pref in preferred:
            if pref in port_numbers:
                return pref

        # Return first port or default
        if ports:
            return ports[0]["port"]
        return 443

    @staticmethod
    def _extract_version(banner: str) -> Optional[str]:
        """Try to extract version info from service banner."""
        if not banner:
            return None
        # Common patterns: "Server: Apache/2.4.41", "OpenSSH_8.2p1"
        import re

        version_pattern = re.compile(r"[\d]+\.[\d]+[\.\d]*")
        match = version_pattern.search(banner)
        if match:
            return match.group(0)
        return None
