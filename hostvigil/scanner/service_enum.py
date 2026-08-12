"""
Service Enumeration Module - Deep intelligence gathering on network services.

Goes beyond port scanning to extract actual service data from SMB, LDAP,
Redis, Elasticsearch, Docker, and WinRM services.

Dependency-light: uses raw socket + struct for protocol interactions.
"""

import json
import logging
import random
import socket
import sqlite3
import ssl
import struct
import time
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("hostvigil.scanner.service_enum")

ATTACK_TAG_RULES = {
    "smb": {
        "relay-risk": "SMB relay path",
        "pivot-node": "SMB reachable pivot",
        "lateral-movement": "SMB lateral movement candidate",
    },
    "ldap": {
        "domain-enum": "LDAP domain enumeration",
        "credential-harvest": "LDAP context for account discovery",
        "pivot-node": "LDAP pivot node",
    },
    "ldaps": {
        "domain-enum": "LDAPS domain enumeration",
        "credential-harvest": "LDAPS context for account discovery",
        "pivot-node": "LDAPS pivot node",
    },
    "redis": {
        "host-takeover": "Redis unauthenticated access",
        "pivot-node": "Redis pivot node",
        "credential-harvest": "Redis key/value exposure",
    },
    "docker": {
        "host-takeover": "Docker API exposure",
        "pivot-node": "Docker pivot node",
        "admin-plane": "Container admin plane exposure",
    },
    "elasticsearch": {
        "data-exposure": "Elasticsearch data exposure",
        "pivot-node": "Elasticsearch pivot node",
        "credential-harvest": "Searchable internal data",
    },
    "winrm": {
        "lateral-movement": "WinRM lateral movement",
        "admin-plane": "Windows remote admin plane",
    },
    "ssh": {
        "lateral-movement": "SSH lateral movement",
        "admin-plane": "Remote admin plane",
    },
    "rdp": {
        "lateral-movement": "RDP lateral movement",
        "admin-plane": "Remote desktop admin plane",
    },
}

ATTACK_SEVERITY_TAGS = {
    "critical": {"host-takeover", "pivot-node"},
    "high": {"pivot-node", "lateral-movement"},
    "medium": {"lateral-movement"},
}

# SMB2 Constants
SMB2_MAGIC = b"\xfeSMB"
SMB1_MAGIC = b"\xffSMB"
SMB2_NEGOTIATE = 0x0000
SMB2_SESSION_SETUP = 0x0001
SMB2_TREE_CONNECT = 0x0003

# SMB2 Dialects
SMB_DIALECTS = [0x0202, 0x0210, 0x0300, 0x0302, 0x0311]

# SMB2 Security Mode flags
SMB2_NEGOTIATE_SIGNING_ENABLED = 0x0001
SMB2_NEGOTIATE_SIGNING_REQUIRED = 0x0002

# SMB2 Capabilities
SMB2_CAP_DFS = 0x00000001
SMB2_CAP_LEASING = 0x00000002
SMB2_CAP_LARGE_MTU = 0x00000004
SMB2_CAP_MULTI_CHANNEL = 0x00000008
SMB2_CAP_PERSISTENT_HANDLES = 0x00000010
SMB2_CAP_DIRECTORY_LEASING = 0x00000020
SMB2_CAP_ENCRYPTION = 0x00000040

DIALECT_NAMES = {
    0x0202: "SMB 2.0.2",
    0x0210: "SMB 2.1",
    0x0300: "SMB 3.0",
    0x0302: "SMB 3.0.2",
    0x0311: "SMB 3.1.1",
    0x00FF: "SMB 1.x (legacy)",
}


class ServiceEnumerator:
    """Deep service enumeration for intel gathering."""

    def __init__(self, config: dict, db_path: str):
        self.config = config
        self.db_path = db_path
        self.min_delay = config.get("min_delay", 10.0)
        self.max_delay = config.get("max_delay", 45.0)
        self.jitter_factor = config.get("jitter_factor", 0.3)
        self.timeout = config.get("timeout", 5.0)
        self._ensure_table()

    def _ensure_table(self):
        """Create/migrate service_enumeration table for compatibility."""
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("""CREATE TABLE IF NOT EXISTS service_enumeration (
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
                FOREIGN KEY (host_id) REFERENCES hosts(id)
            )""")

            cols = {row[1] for row in conn.execute("PRAGMA table_info(service_enumeration)").fetchall()}
            # Add compatibility columns when table was created by another module.
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
                if col_name not in cols:
                    conn.execute(f"ALTER TABLE service_enumeration ADD COLUMN {col_def}")

            conn.commit()
        finally:
            conn.close()

    def enumerate_all(self) -> List[Dict]:
        """Enumerate all hosts with enumerable services from the database."""
        results = []
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row

        # Find hosts with ports we can enumerate
        enumerable_ports = {445, 389, 636, 5985, 5986, 6379, 9200, 2375}
        try:
            cursor = conn.execute(
                "SELECT DISTINCT h.ip, p.port FROM ports p JOIN hosts h ON h.id = p.host_id WHERE p.port IN ({}) AND p.state = ? AND p.is_active = 1 AND h.is_active = 1".format(
                    ",".join("?" * len(enumerable_ports))
                ),
                list(enumerable_ports) + ["open"],
            )
        except sqlite3.OperationalError as e:
            logger.error(f"Failed to query enumerable ports: {e}")
            conn.close()
            return results

        host_ports: Dict[str, List[int]] = {}
        for row in cursor:
            ip = row["ip"]
            port = row["port"]
            if ip not in host_ports:
                host_ports[ip] = []
            host_ports[ip].append(port)

        conn.close()

        for ip, ports in host_ports.items():
            try:
                host_results = self.enumerate_host(ip, ports)
                results.extend(host_results)
            except Exception as e:
                logger.error(f"Failed to enumerate {ip}: {e}")

            # Stealth delay between hosts
            delay = random.uniform(self.min_delay, self.max_delay)
            delay = self._apply_jitter(delay)
            logger.debug(f"Stealth delay: {delay:.1f}s before next host")
            time.sleep(delay)

        return results

    def enumerate_host(self, ip: str, ports: List[int]) -> List[Dict]:
        """Enumerate services on a single host."""
        results = []

        # Silent credential audit (F5): use minimal single-packet probes for
        # Redis/ES so the operator detects password-less access with the smallest
        # footprint. Disable to fall back to the deeper enumeration.
        silent_audit = self.config.get("silent_credential_audit", default={}).get("enabled", True)
        redis_enum = self._silent_redis_audit if silent_audit else self._enum_redis
        es_enum = self._silent_es_audit if silent_audit else self._enum_elasticsearch

        service_map = {
            445: ("smb", self._enum_smb),
            389: ("ldap", lambda host: self._enum_ldap(host, 389)),
            636: ("ldaps", lambda host: self._enum_ldap(host, 636)),
            5985: ("winrm", self._enum_winrm),
            5986: ("winrm", self._enum_winrm),
            6379: ("redis", redis_enum),
            9200: ("elasticsearch", es_enum),
            2375: ("docker", self._enum_docker),
        }

        for port in ports:
            if port not in service_map:
                continue

            service_type, enum_func = service_map[port]
            logger.info(f"Enumerating {service_type} on {ip}:{port}")

            try:
                result = enum_func(ip)
                if result:
                    results.append(result)
            except Exception as e:
                logger.debug(f"Enumeration failed for {service_type} on {ip}:{port}: {e}")

            # Inter-service delay
            if port != ports[-1]:
                delay = self._apply_jitter(random.uniform(2.0, 5.0))
                time.sleep(delay)

        return results

    # =========================================================================
    # SMB ENUMERATION
    # =========================================================================

    def _enum_smb(self, ip: str) -> Dict:
        """SMB enumeration via raw SMB negotiate + session setup."""
        result = {
            "ip": ip,
            "port": 445,
            "service": "smb",
            "dialect": None,
            "dialect_name": None,
            "server_guid": None,
            "signing_enabled": False,
            "signing_required": False,
            "capabilities": [],
            "server_time": None,
            "os_info": None,
            "null_session": False,
            "shares": [],
            "workgroup": None,
            "findings": [],
            "risk_level": "info",
        }

        try:
            # Phase 1: SMB2 Negotiate
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, 445))

            negotiate_result = self._smb_negotiate(sock)
            result.update(negotiate_result)

            # Determine risk from signing
            if not result["signing_required"]:
                result["findings"].append("SMB signing not required - relay attacks possible")
                result["risk_level"] = "high"

            sock.close()

            # Phase 2: Null session attempt
            null_result = self._smb_null_session(ip)
            result["null_session"] = null_result.get("success", False)
            if result["null_session"]:
                result["findings"].append("Null session authentication successful")
                result["risk_level"] = "high"
                result["workgroup"] = null_result.get("workgroup")

                # Phase 3: Try to list shares
                shares = self._smb_list_shares(ip)
                result["shares"] = shares
                if shares:
                    result["findings"].append(f"Shares accessible via null session: {shares}")

        except socket.timeout:
            logger.debug(f"SMB timeout connecting to {ip}:445")
            result["findings"].append("Connection timed out")
        except ConnectionRefusedError:
            logger.debug(f"SMB connection refused on {ip}:445")
            result["findings"].append("Connection refused")
        except Exception as e:
            logger.debug(f"SMB enumeration error on {ip}: {e}")
            result["findings"].append(f"Error: {str(e)}")

        # Store result
        self._store_result(
            ip=ip,
            port=445,
            service_type="smb",
            enum_data=result,
            findings=result["findings"],
            risk_level=result["risk_level"],
        )

        return result

    def _smb_negotiate(self, sock: socket.socket) -> Dict:
        """Send SMB2 negotiate request, parse response for version/OS/signing."""
        result = {}

        # Build SMB2 Negotiate Request
        # Header (64 bytes)
        header = bytearray(64)
        header[0:4] = SMB2_MAGIC  # Protocol ID
        struct.pack_into("<H", header, 4, 64)  # Structure Size (header)
        struct.pack_into("<H", header, 6, 0)  # Credit Charge
        struct.pack_into("<I", header, 8, 0)  # Status
        struct.pack_into("<H", header, 12, SMB2_NEGOTIATE)  # Command
        struct.pack_into("<H", header, 14, 1)  # Credit Request
        struct.pack_into("<I", header, 16, 0)  # Flags
        struct.pack_into("<I", header, 20, 0)  # Next Command
        struct.pack_into("<Q", header, 24, 1)  # Message ID
        # Reserved (4 bytes at offset 32)
        struct.pack_into("<I", header, 36, 0)  # Tree ID
        struct.pack_into("<Q", header, 40, 0)  # Session ID
        # Signature (16 bytes at offset 48) - zeros

        # Negotiate Request body
        dialect_count = len(SMB_DIALECTS)
        # Structure size (36) + SecurityMode + Reserved + Capabilities + ClientGUID + Dialects
        negotiate_body = bytearray(36 + dialect_count * 2)
        struct.pack_into("<H", negotiate_body, 0, 36)  # Structure Size
        struct.pack_into("<H", negotiate_body, 2, dialect_count)  # Dialect Count
        struct.pack_into("<H", negotiate_body, 4, SMB2_NEGOTIATE_SIGNING_ENABLED)  # Security Mode
        struct.pack_into("<H", negotiate_body, 6, 0)  # Reserved
        struct.pack_into("<I", negotiate_body, 8, 0)  # Capabilities
        # Client GUID (16 bytes at offset 12)
        client_guid = uuid.uuid4().bytes
        negotiate_body[12:28] = client_guid
        # NegotiateContextOffset/Count/Reserved2 (for SMB 3.1.1) at offset 28
        struct.pack_into("<I", negotiate_body, 28, 0)  # NegotiateContextOffset
        struct.pack_into("<H", negotiate_body, 32, 0)  # NegotiateContextCount
        struct.pack_into("<H", negotiate_body, 34, 0)  # Reserved2

        # Dialect list
        for i, dialect in enumerate(SMB_DIALECTS):
            struct.pack_into("<H", negotiate_body, 36 + i * 2, dialect)

        # Combine and prepend NetBIOS session header
        smb_packet = bytes(header) + bytes(negotiate_body)
        netbios_header = struct.pack(">I", len(smb_packet))
        # NetBIOS: first byte is type (0x00 = session message), next 3 bytes are length
        netbios_header = b"\x00" + struct.pack(">I", len(smb_packet))[1:]

        sock.send(netbios_header + smb_packet)

        # Receive response
        resp_header = sock.recv(4)
        if len(resp_header) < 4:
            return result

        resp_length = struct.unpack(">I", b"\x00" + resp_header[1:])[0]
        response = b""
        while len(response) < resp_length:
            chunk = sock.recv(resp_length - len(response))
            if not chunk:
                break
            response += chunk

        if len(response) < 64:
            return result

        # Verify SMB2 magic
        if response[0:4] != SMB2_MAGIC:
            # Might be SMB1 response
            if response[0:4] == SMB1_MAGIC:
                result["dialect"] = 0x00FF
                result["dialect_name"] = "SMB 1.x (legacy)"
                result["findings"] = ["SMBv1 detected - known vulnerabilities (EternalBlue)"]
                result["risk_level"] = "critical"
            return result

        # Parse SMB2 Negotiate Response (starts at offset 64 in response)
        if len(response) < 128:
            return result

        resp_body = response[64:]

        # Structure Size at offset 0 (should be 65)
        security_mode = struct.unpack_from("<H", resp_body, 2)[0]
        dialect_revision = struct.unpack_from("<H", resp_body, 4)[0]
        # NegotiateContextCount at offset 6
        server_guid = resp_body[8:24]
        capabilities = struct.unpack_from("<I", resp_body, 24)[0]
        system_time = struct.unpack_from("<Q", resp_body, 40)[0]

        result["dialect"] = dialect_revision
        result["dialect_name"] = DIALECT_NAMES.get(dialect_revision, f"Unknown (0x{dialect_revision:04x})")
        result["server_guid"] = str(uuid.UUID(bytes_le=server_guid))
        result["signing_enabled"] = bool(security_mode & SMB2_NEGOTIATE_SIGNING_ENABLED)
        result["signing_required"] = bool(security_mode & SMB2_NEGOTIATE_SIGNING_REQUIRED)

        # Parse capabilities
        cap_list = []
        if capabilities & SMB2_CAP_DFS:
            cap_list.append("DFS")
        if capabilities & SMB2_CAP_LEASING:
            cap_list.append("Leasing")
        if capabilities & SMB2_CAP_LARGE_MTU:
            cap_list.append("Large MTU")
        if capabilities & SMB2_CAP_MULTI_CHANNEL:
            cap_list.append("Multi-Channel")
        if capabilities & SMB2_CAP_PERSISTENT_HANDLES:
            cap_list.append("Persistent Handles")
        if capabilities & SMB2_CAP_DIRECTORY_LEASING:
            cap_list.append("Directory Leasing")
        if capabilities & SMB2_CAP_ENCRYPTION:
            cap_list.append("Encryption")
        result["capabilities"] = cap_list

        # Convert FILETIME to readable timestamp
        if system_time > 0:
            # Windows FILETIME: 100ns intervals since 1601-01-01
            unix_ts = (system_time - 116444736000000000) / 10000000
            try:
                result["server_time"] = datetime.fromtimestamp(unix_ts, tz=timezone.utc).isoformat()
            except (OSError, ValueError):
                result["server_time"] = None

        return result

    def _smb_null_session(self, ip: str) -> Dict:
        """Attempt anonymous SMB session using SMB2 Session Setup with NTLMSSP."""
        result = {"success": False, "workgroup": None}

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, 445))

            # First, negotiate
            self._smb_negotiate(sock)
            sock.close()

            # New connection for session setup with NTLMSSP Negotiate
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, 445))

            # Re-negotiate
            self._smb_negotiate(sock)

            # Build Session Setup Request with NTLMSSP NEGOTIATE_MESSAGE
            ntlmssp_negotiate = self._build_ntlmssp_negotiate()

            # GSS-API wrapper (simplified SPNEGO)
            spnego_token = self._build_spnego_init(ntlmssp_negotiate)

            # SMB2 Session Setup Request
            header = bytearray(64)
            header[0:4] = SMB2_MAGIC
            struct.pack_into("<H", header, 4, 64)
            struct.pack_into("<H", header, 6, 0)
            struct.pack_into("<I", header, 8, 0)
            struct.pack_into("<H", header, 12, SMB2_SESSION_SETUP)
            struct.pack_into("<H", header, 14, 1)
            struct.pack_into("<I", header, 16, 0)
            struct.pack_into("<I", header, 20, 0)
            struct.pack_into("<Q", header, 24, 2)  # Message ID
            struct.pack_into("<I", header, 36, 0)
            struct.pack_into("<Q", header, 40, 0)

            # Session Setup body
            body = bytearray(24)
            struct.pack_into("<H", body, 0, 25)  # Structure Size
            struct.pack_into("<B", body, 2, 0)  # Flags
            struct.pack_into("<B", body, 3, SMB2_NEGOTIATE_SIGNING_ENABLED)  # Security Mode
            struct.pack_into("<I", body, 4, 0)  # Capabilities
            struct.pack_into("<I", body, 8, 0)  # Channel
            # Security Buffer Offset (header 64 + body fixed 24 = 88)
            struct.pack_into("<H", body, 12, 88)
            struct.pack_into("<H", body, 14, len(spnego_token))  # Security Buffer Length
            struct.pack_into("<Q", body, 16, 0)  # PreviousSessionId

            smb_packet = bytes(header) + bytes(body) + spnego_token
            netbios_header = b"\x00" + struct.pack(">I", len(smb_packet))[1:]

            sock.send(netbios_header + smb_packet)

            # Receive response
            resp_hdr = sock.recv(4)
            if len(resp_hdr) < 4:
                sock.close()
                return result

            resp_len = struct.unpack(">I", b"\x00" + resp_hdr[1:])[0]
            response = b""
            while len(response) < resp_len:
                chunk = sock.recv(resp_len - len(response))
                if not chunk:
                    break
                response += chunk

            sock.close()

            if len(response) < 64:
                return result

            # Check status - STATUS_MORE_PROCESSING_REQUIRED (0xC0000016) means
            # the server is willing to negotiate (null session likely possible)
            status = struct.unpack_from("<I", response, 8)[0]

            # STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016
            if status == 0xC0000016:
                result["success"] = True
                # Try to extract workgroup from NTLMSSP Challenge
                challenge_offset = response.find(b"NTLMSSP\x00\x02\x00\x00\x00")
                if challenge_offset >= 0:
                    workgroup = self._parse_ntlmssp_challenge_workgroup(response[challenge_offset:])
                    result["workgroup"] = workgroup
            elif status == 0x00000000:
                # Immediate success - very permissive
                result["success"] = True

        except Exception as e:
            logger.debug(f"Null session attempt failed on {ip}: {e}")

        return result

    def _build_ntlmssp_negotiate(self) -> bytes:
        """Build NTLMSSP Negotiate message for anonymous auth."""
        # NTLMSSP Signature + Message Type (Negotiate = 1)
        msg = b"NTLMSSP\x00"
        msg += struct.pack("<I", 1)  # Type 1 = Negotiate

        # Negotiate Flags
        flags = (
            0x00000001  # NEGOTIATE_UNICODE
            | 0x00000002  # NEGOTIATE_OEM
            | 0x00000004  # REQUEST_TARGET
            | 0x00000200  # NEGOTIATE_NTLM
            | 0x00008000  # NEGOTIATE_ALWAYS_SIGN
            | 0x00080000  # NEGOTIATE_NTLM2
            | 0x20000000  # NEGOTIATE_128
        )
        msg += struct.pack("<I", flags)

        # Domain Name Fields (empty)
        msg += struct.pack("<HHI", 0, 0, 0)  # DomainNameLen, MaxLen, Offset
        # Workstation Fields (empty)
        msg += struct.pack("<HHI", 0, 0, 0)  # WorkstationLen, MaxLen, Offset

        return msg

    def _build_spnego_init(self, ntlmssp_token: bytes) -> bytes:
        """Build simplified SPNEGO initToken wrapping NTLMSSP."""
        # OID for NTLMSSP: 1.3.6.1.4.1.311.2.2.10
        ntlmssp_oid = b"\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"

        # MechType sequence
        mech_types = self._asn1_sequence(ntlmssp_oid)

        # mechToken [2]
        mech_token = (
            b"\xa2"
            + self._asn1_length(len(ntlmssp_token) + 2)
            + b"\x04"
            + self._asn1_length(len(ntlmssp_token))
            + ntlmssp_token
        )

        # NegTokenInit sequence
        neg_token_init = b"\xa0" + self._asn1_length(len(mech_types)) + mech_types + mech_token
        neg_token_init_seq = self._asn1_sequence(neg_token_init)

        # Application [0] wrapper
        spnego_oid = b"\x06\x06\x2b\x06\x01\x05\x05\x02"  # 1.3.6.1.5.5.2
        inner = spnego_oid + b"\xa0" + self._asn1_length(len(neg_token_init_seq)) + neg_token_init_seq
        token = b"\x60" + self._asn1_length(len(inner)) + inner

        return token

    def _parse_ntlmssp_challenge_workgroup(self, data: bytes) -> Optional[str]:
        """Extract workgroup/domain from NTLMSSP Challenge message."""
        try:
            if len(data) < 32:
                return None
            # Target Name at offset 12: Length(2), MaxLength(2), Offset(4)
            target_len = struct.unpack_from("<H", data, 12)[0]
            target_offset = struct.unpack_from("<I", data, 16)[0]
            if target_offset + target_len <= len(data):
                workgroup = data[target_offset : target_offset + target_len]
                return workgroup.decode("utf-16-le", errors="ignore").strip("\x00")
        except Exception:
            pass
        return None

    def _smb_list_shares(self, ip: str) -> List[str]:
        """Try to list shares via null session using Tree Connect to IPC$."""
        shares = []
        try:
            # Connect and negotiate
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, 445))

            self._smb_negotiate(sock)
            sock.close()
            sock = None

            # For share listing, we'd need a full session + tree connect to IPC$
            # + SRVSVC named pipe interaction. This is complex without impacket.
            # We attempt a basic Tree Connect to IPC$ to verify access.

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, 445))
            self._smb_negotiate(sock)

            # Build Tree Connect to \\ip\IPC$
            tree_path = f"\\\\{ip}\\IPC$".encode("utf-16-le") + b"\x00\x00"

            header = bytearray(64)
            header[0:4] = SMB2_MAGIC
            struct.pack_into("<H", header, 4, 64)
            struct.pack_into("<H", header, 12, SMB2_TREE_CONNECT)
            struct.pack_into("<H", header, 14, 1)
            struct.pack_into("<Q", header, 24, 3)  # Message ID

            # Tree Connect body
            body = bytearray(8)
            struct.pack_into("<H", body, 0, 9)  # Structure Size
            struct.pack_into("<H", body, 2, 0)  # Reserved/Flags
            # Path Offset (64 header + 8 body = 72)
            struct.pack_into("<H", body, 4, 72)
            struct.pack_into("<H", body, 6, len(tree_path))  # Path Length

            smb_packet = bytes(header) + bytes(body) + tree_path
            netbios_header = b"\x00" + struct.pack(">I", len(smb_packet))[1:]

            sock.send(netbios_header + smb_packet)

            resp_hdr = sock.recv(4)
            if len(resp_hdr) >= 4:
                resp_len = struct.unpack(">I", b"\x00" + resp_hdr[1:])[0]
                response = b""
                while len(response) < resp_len:
                    chunk = sock.recv(resp_len - len(response))
                    if not chunk:
                        break
                    response += chunk

                if len(response) >= 64:
                    status = struct.unpack_from("<I", response, 8)[0]
                    if status == 0x00000000:
                        shares.append("IPC$")
                        logger.info(f"IPC$ accessible on {ip} via anonymous")

            sock.close()

        except Exception as e:
            logger.debug(f"Share listing failed on {ip}: {e}")
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass
        return shares

    # =========================================================================
    # LDAP ENUMERATION
    # =========================================================================

    def _enum_ldap(self, ip: str, port: int = 389) -> Dict:
        """LDAP anonymous bind and root DSE query."""
        result = {
            "ip": ip,
            "port": port,
            "service": "ldap" if port == 389 else "ldaps",
            "anonymous_bind": False,
            "naming_contexts": [],
            "base_dn": None,
            "supported_ldap_versions": [],
            "domain_functionality": None,
            "supported_sasl_mechanisms": [],
            "is_global_catalog": None,
            "server_name": None,
            "findings": [],
            "risk_level": "info",
        }

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))

            # Wrap with TLS for LDAPS (636)
            if port == 636:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                try:
                    sock = context.wrap_socket(sock, server_hostname=ip)
                except (ssl.SSLError, OSError):
                    sock.close()
                    raise

            # Phase 1: Anonymous Bind
            bind_success = self._ldap_anonymous_bind(sock)
            result["anonymous_bind"] = bind_success

            if bind_success:
                result["findings"].append("Anonymous LDAP bind successful")
                result["risk_level"] = "medium"

                # Phase 2: Root DSE Query
                dse_data = self._ldap_root_dse(sock)
                if dse_data:
                    result["naming_contexts"] = dse_data.get("namingContexts", [])
                    result["supported_ldap_versions"] = dse_data.get("supportedLDAPVersion", [])
                    result["domain_functionality"] = dse_data.get("domainFunctionality")
                    result["supported_sasl_mechanisms"] = dse_data.get("supportedSASLMechanisms", [])
                    result["is_global_catalog"] = dse_data.get("isGlobalCatalogReady")
                    result["server_name"] = dse_data.get("serverName")

                    # Extract base DN from naming contexts
                    for nc in result["naming_contexts"]:
                        if "DC=" in nc.upper() or "dc=" in nc:
                            result["base_dn"] = nc
                            break

                    if result["base_dn"]:
                        result["findings"].append(f"Base DN: {result['base_dn']}")

                    if result["domain_functionality"]:
                        result["findings"].append(f"Domain functional level: {result['domain_functionality']}")

            sock.close()

        except socket.timeout:
            logger.debug(f"LDAP timeout connecting to {ip}:{port}")
        except ConnectionRefusedError:
            logger.debug(f"LDAP connection refused on {ip}:{port}")
        except Exception as e:
            logger.debug(f"LDAP enumeration error on {ip}:{port}: {e}")
            result["findings"].append(f"Error: {str(e)}")

        self._store_result(
            ip=ip,
            port=port,
            service_type=result["service"],
            enum_data=result,
            findings=result["findings"],
            risk_level=result["risk_level"],
        )

        return result

    def _ldap_anonymous_bind(self, sock: socket.socket) -> bool:
        """Send LDAP anonymous simple bind request."""
        # LDAP Bind Request:
        # MessageID: 1
        # BindRequest (application 0):
        #   version: 3
        #   name: "" (empty DN)
        #   authentication: simple "" (empty password)

        # BER encoding
        msg_id = self._ber_integer(1)
        version = self._ber_integer(3)
        name = self._ber_octet_string(b"")  # Empty DN
        auth = b"\x80\x00"  # Context [0] primitive, empty (simple bind, no password)

        bind_request = version + name + auth
        # Application [0] constructed = 0x60
        bind_req_tlv = b"\x60" + self._asn1_length(len(bind_request)) + bind_request

        # LDAPMessage sequence
        message = msg_id + bind_req_tlv
        ldap_message = b"\x30" + self._asn1_length(len(message)) + message

        sock.send(ldap_message)

        # Receive response
        response = self._recv_ldap_response(sock)
        if not response:
            return False

        # Parse bind response - look for resultCode = 0 (success)
        # The result code is in the BindResponse (application 1)
        # Simple check: look for success result code
        try:
            result_code = self._parse_ldap_bind_response(response)
            return result_code == 0
        except Exception:
            return False

    def _ldap_root_dse(self, sock: socket.socket) -> Dict:
        """Query root DSE for naming contexts and capabilities."""
        # LDAP Search Request:
        # MessageID: 2
        # SearchRequest (application 3):
        #   baseObject: "" (root DSE)
        #   scope: baseObject (0)
        #   derefAliases: neverDerefAliases (0)
        #   sizeLimit: 0
        #   timeLimit: 30
        #   typesOnly: FALSE
        #   filter: (objectClass=*) = present filter
        #   attributes: list of desired attributes

        attributes = [
            "namingContexts",
            "supportedLDAPVersion",
            "domainFunctionality",
            "supportedSASLMechanisms",
            "isGlobalCatalogReady",
            "serverName",
            "dnsHostName",
            "defaultNamingContext",
        ]

        msg_id = self._ber_integer(2)

        # SearchRequest body
        base_object = self._ber_octet_string(b"")  # Root DSE
        scope = self._ber_enumerated(0)  # baseObject
        deref = self._ber_enumerated(0)  # neverDerefAliases
        size_limit = self._ber_integer(0)
        time_limit = self._ber_integer(30)
        types_only = self._ber_boolean(False)

        # Filter: present (objectClass) = context [7] primitive
        filter_val = b"\x87" + self._asn1_length(len(b"objectClass")) + b"objectClass"

        # Attributes sequence
        attr_items = b""
        for attr in attributes:
            attr_items += self._ber_octet_string(attr.encode("utf-8"))
        attr_seq = b"\x30" + self._asn1_length(len(attr_items)) + attr_items

        search_body = base_object + scope + deref + size_limit + time_limit + types_only + filter_val + attr_seq

        # Application [3] constructed = 0x63
        search_req = b"\x63" + self._asn1_length(len(search_body)) + search_body

        message = msg_id + search_req
        ldap_message = b"\x30" + self._asn1_length(len(message)) + message

        sock.send(ldap_message)

        # Receive and parse response entries
        result = {}
        max_reads = 10  # Safety limit

        for _ in range(max_reads):
            response = self._recv_ldap_response(sock)
            if not response:
                break

            # Check if this is a SearchResultEntry (application 4 = 0x64)
            # or SearchResultDone (application 5 = 0x65)
            parsed = self._parse_ldap_search_response(response)
            if parsed is None:
                break  # SearchResultDone or error
            if parsed:
                result.update(parsed)

        return result

    def _recv_ldap_response(self, sock: socket.socket) -> Optional[bytes]:
        """Receive a complete LDAP message from socket."""
        try:
            # Read the initial bytes to determine message length
            initial = sock.recv(2)
            if len(initial) < 2:
                return None

            # First byte should be 0x30 (SEQUENCE)
            if initial[0] != 0x30:
                # Try to read more and find sequence start
                return None

            # Parse length
            length_byte = initial[1]
            if length_byte < 0x80:
                # Short form
                total_length = length_byte
                header_bytes = initial
            elif length_byte == 0x81:
                # One byte length
                len_data = sock.recv(1)
                if not len_data:
                    return None
                total_length = len_data[0]
                header_bytes = initial + len_data
            elif length_byte == 0x82:
                # Two byte length
                len_data = sock.recv(2)
                if len(len_data) < 2:
                    return None
                total_length = struct.unpack(">H", len_data)[0]
                header_bytes = initial + len_data
            elif length_byte == 0x83:
                # Three byte length
                len_data = sock.recv(3)
                if len(len_data) < 3:
                    return None
                total_length = struct.unpack(">I", b"\x00" + len_data)[0]
                header_bytes = initial + len_data
            else:
                return None

            # Read the body
            body = b""
            while len(body) < total_length:
                chunk = sock.recv(total_length - len(body))
                if not chunk:
                    break
                body += chunk

            return header_bytes + body

        except socket.timeout:
            return None
        except Exception:
            return None

    def _parse_ldap_bind_response(self, data: bytes) -> int:
        """Parse LDAP BindResponse to extract resultCode."""
        # Skip outer SEQUENCE tag+length
        offset = 0
        if data[offset] != 0x30:
            return -1
        offset += 1
        offset, _ = self._parse_asn1_length(data, offset)

        # Skip MessageID (INTEGER)
        if data[offset] != 0x02:
            return -1
        offset += 1
        offset, msg_id_len = self._parse_asn1_length(data, offset)
        offset += msg_id_len

        # BindResponse: application [1] constructed = 0x61
        if data[offset] != 0x61:
            return -1
        offset += 1
        offset, _ = self._parse_asn1_length(data, offset)

        # resultCode (ENUMERATED)
        if data[offset] != 0x0A:
            return -1
        offset += 1
        offset, rc_len = self._parse_asn1_length(data, offset)
        result_code = int.from_bytes(data[offset : offset + rc_len], "big")

        return result_code

    def _parse_ldap_search_response(self, data: bytes) -> Optional[Dict]:
        """Parse LDAP SearchResultEntry, return None if SearchResultDone."""
        try:
            offset = 0
            if data[offset] != 0x30:
                return None
            offset += 1
            offset, _ = self._parse_asn1_length(data, offset)

            # Skip MessageID
            if data[offset] != 0x02:
                return None
            offset += 1
            offset, msg_id_len = self._parse_asn1_length(data, offset)
            offset += msg_id_len

            # Check application tag
            tag = data[offset]
            if tag == 0x65:  # SearchResultDone
                return None
            if tag != 0x64:  # Not SearchResultEntry
                return None

            offset += 1
            offset, entry_len = self._parse_asn1_length(data, offset)

            # Object Name (OCTET STRING)
            if data[offset] != 0x04:
                return None
            offset += 1
            offset, name_len = self._parse_asn1_length(data, offset)
            offset += name_len  # Skip the DN

            # Attributes (SEQUENCE)
            if data[offset] != 0x30:
                return {}
            offset += 1
            offset, attrs_len = self._parse_asn1_length(data, offset)
            attrs_end = offset + attrs_len

            result = {}

            while offset < attrs_end and offset < len(data):
                # Each attribute is a SEQUENCE
                if data[offset] != 0x30:
                    break
                offset += 1
                offset, attr_seq_len = self._parse_asn1_length(data, offset)
                attr_seq_end = offset + attr_seq_len

                # Attribute type (OCTET STRING)
                if offset >= len(data) or data[offset] != 0x04:
                    offset = attr_seq_end
                    continue
                offset += 1
                offset, type_len = self._parse_asn1_length(data, offset)
                attr_type = data[offset : offset + type_len].decode("utf-8", errors="ignore")
                offset += type_len

                # Attribute values (SET)
                if offset >= len(data) or data[offset] != 0x31:
                    offset = attr_seq_end
                    continue
                offset += 1
                offset, values_len = self._parse_asn1_length(data, offset)
                values_end = offset + values_len

                values = []
                while offset < values_end and offset < len(data):
                    if data[offset] != 0x04:
                        break
                    offset += 1
                    offset, val_len = self._parse_asn1_length(data, offset)
                    val = data[offset : offset + val_len].decode("utf-8", errors="ignore")
                    values.append(val)
                    offset += val_len

                if len(values) == 1:
                    result[attr_type] = values[0]
                else:
                    result[attr_type] = values

                offset = attr_seq_end

            return result

        except (IndexError, struct.error):
            return {}

    # =========================================================================
    # OTHER SERVICE ENUMERATION
    # =========================================================================

    def _enum_redis(self, ip: str) -> Dict:
        """Check Redis for unauthenticated access."""
        result = {
            "ip": ip,
            "port": 6379,
            "service": "redis",
            "no_auth": False,
            "version": None,
            "os": None,
            "keys_count": None,
            "findings": [],
            "risk_level": "info",
        }

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, 6379))

            # Send INFO command (no auth)
            sock.send(b"*1\r\n$4\r\nINFO\r\n")

            response = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    # Redis bulk string response starts with $<length>\r\n
                    if b"\r\n" in response and len(response) > 100:
                        break
            except socket.timeout:
                pass

            sock.close()

            resp_str = response.decode("utf-8", errors="ignore")

            if resp_str.startswith("-NOAUTH") or resp_str.startswith("-ERR"):
                # Authentication required - good
                result["findings"].append("Redis requires authentication")
                result["risk_level"] = "info"
            elif resp_str.startswith("$") or "redis_version" in resp_str:
                # No auth required!
                result["no_auth"] = True
                result["findings"].append("Redis accessible without authentication")
                result["risk_level"] = "critical"

                # Parse INFO response
                for line in resp_str.split("\r\n"):
                    if line.startswith("redis_version:"):
                        result["version"] = line.split(":", 1)[1].strip()
                    elif line.startswith("os:"):
                        result["os"] = line.split(":", 1)[1].strip()
                    elif line.startswith("db0:keys="):
                        try:
                            keys_part = line.split("keys=")[1].split(",")[0]
                            result["keys_count"] = int(keys_part)
                        except (ValueError, IndexError):
                            pass

                if result["version"]:
                    result["findings"].append(f"Redis version: {result['version']}")

        except socket.timeout:
            logger.debug(f"Redis timeout on {ip}:6379")
        except ConnectionRefusedError:
            logger.debug(f"Redis connection refused on {ip}:6379")
        except Exception as e:
            logger.debug(f"Redis enumeration error on {ip}: {e}")

        self._store_result(
            ip=ip,
            port=6379,
            service_type="redis",
            enum_data=result,
            findings=result["findings"],
            risk_level=result["risk_level"],
        )

        return result

    def _silent_redis_audit(self, ip: str) -> Dict:
        """Silent credential audit for Redis (F5): minimal single-packet probe.

        Never guesses credentials — only verifies whether an unauthenticated
        connection is accepted, then walks away. Lower footprint than the full
        INFO-dump enumeration used elsewhere.
        """
        result = {
            "ip": ip,
            "port": 6379,
            "service": "redis",
            "no_auth": False,
            "auth_required": False,
            "findings": [],
            "risk_level": "info",
        }

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(min(self.timeout, 2.0))
            sock.connect((ip, 6379))
            # Single PING — no auth, no INFO, no key access.
            sock.send(b"PING\r\n")

            response = b""
            try:
                response = sock.recv(128)
            except socket.timeout:
                pass
            sock.close()

            resp_str = response.decode("utf-8", errors="ignore").strip()
            if resp_str.startswith("+PONG"):
                result["no_auth"] = True
                result["findings"].append("Redis accepts unauthenticated connections (silent audit)")
                result["risk_level"] = "critical"
            elif resp_str.startswith("-NOAUTH") or resp_str.startswith("-ERR"):
                result["auth_required"] = True
                result["findings"].append("Redis requires authentication (silent audit)")
            else:
                result["findings"].append("Redis silent audit: inconclusive response")
        except socket.timeout:
            logger.debug(f"Redis silent audit timeout on {ip}:6379")
        except ConnectionRefusedError:
            logger.debug(f"Redis silent audit connection refused on {ip}:6379")
        except Exception as e:
            logger.debug(f"Redis silent audit error on {ip}: {e}")

        self._store_result(
            ip=ip,
            port=6379,
            service_type="redis",
            enum_data=result,
            findings=result["findings"],
            risk_level=result["risk_level"],
        )

        return result

    def _silent_es_audit(self, ip: str) -> Dict:
        """Silent credential audit for Elasticsearch (F5): single minimal probe.

        Sends one `GET /` request and classifies auth posture from the HTTP status.
        No index listing, no cluster stats, no credential attempts.
        """
        result = {
            "ip": ip,
            "port": 9200,
            "service": "elasticsearch",
            "no_auth": False,
            "auth_required": False,
            "findings": [],
            "risk_level": "info",
        }

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(min(self.timeout, 2.0))
            sock.connect((ip, 9200))

            request = (
                f"GET / HTTP/1.0\r\nHost: {ip}:9200\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n\r\n"
            )
            sock.send(request.encode())

            response = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if b"\r\n\r\n" in response:
                        break
            except socket.timeout:
                pass
            sock.close()

            status_line = response.decode("utf-8", errors="ignore").split("\r\n", 1)[0]
            if "200" in status_line:
                result["no_auth"] = True
                result["findings"].append("Elasticsearch accepts unauthenticated access (silent audit)")
                result["risk_level"] = "critical"
            elif "401" in status_line or "403" in status_line:
                result["auth_required"] = True
                result["findings"].append("Elasticsearch requires authentication (silent audit)")
            else:
                result["findings"].append("Elasticsearch silent audit: inconclusive response")
        except socket.timeout:
            logger.debug(f"Elasticsearch silent audit timeout on {ip}:9200")
        except ConnectionRefusedError:
            logger.debug(f"Elasticsearch silent audit connection refused on {ip}:9200")
        except Exception as e:
            logger.debug(f"Elasticsearch silent audit error on {ip}: {e}")

        self._store_result(
            ip=ip,
            port=9200,
            service_type="elasticsearch",
            enum_data=result,
            findings=result["findings"],
            risk_level=result["risk_level"],
        )

        return result

    def _enum_elasticsearch(self, ip: str) -> Dict:
        """Check Elasticsearch for open access (no authentication)."""
        result = {
            "ip": ip,
            "port": 9200,
            "service": "elasticsearch",
            "no_auth": False,
            "version": None,
            "cluster_name": None,
            "node_name": None,
            "indices_count": None,
            "findings": [],
            "risk_level": "info",
        }

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, 9200))

            # Send HTTP GET /
            request = (
                "GET / HTTP/1.1\r\n"
                f"Host: {ip}:9200\r\n"
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
                "Accept: application/json\r\n"
                "Connection: close\r\n"
                "\r\n"
            )
            sock.send(request.encode())

            response = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                pass

            sock.close()

            resp_str = response.decode("utf-8", errors="ignore")

            if "200 OK" in resp_str and "cluster_name" in resp_str:
                result["no_auth"] = True
                result["findings"].append("Elasticsearch accessible without authentication")
                result["risk_level"] = "high"

                # Parse JSON body
                try:
                    body_start = resp_str.find("{")
                    if body_start >= 0:
                        body_json = json.loads(resp_str[body_start:])
                        result["cluster_name"] = body_json.get("cluster_name")
                        result["node_name"] = body_json.get("name")
                        version_info = body_json.get("version", {})
                        result["version"] = version_info.get("number")

                        if result["version"]:
                            result["findings"].append(f"ES version: {result['version']}")
                        if result["cluster_name"]:
                            result["findings"].append(f"Cluster: {result['cluster_name']}")
                except (json.JSONDecodeError, ValueError):
                    pass

                # Try to get index count
                self._es_get_indices_count(ip, result)

            elif "401" in resp_str or "403" in resp_str:
                result["findings"].append("Elasticsearch requires authentication")

        except socket.timeout:
            logger.debug(f"Elasticsearch timeout on {ip}:9200")
        except ConnectionRefusedError:
            logger.debug(f"Elasticsearch connection refused on {ip}:9200")
        except Exception as e:
            logger.debug(f"Elasticsearch enumeration error on {ip}: {e}")

        self._store_result(
            ip=ip,
            port=9200,
            service_type="elasticsearch",
            enum_data=result,
            findings=result["findings"],
            risk_level=result["risk_level"],
        )

        return result

    def _es_get_indices_count(self, ip: str, result: Dict):
        """Try to get Elasticsearch indices count."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, 9200))

            request = (
                "GET /_cat/indices?format=json HTTP/1.1\r\n"
                f"Host: {ip}:9200\r\n"
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
                "Accept: application/json\r\n"
                "Connection: close\r\n"
                "\r\n"
            )
            sock.send(request.encode())

            response = b""
            try:
                while True:
                    chunk = sock.recv(8192)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                pass

            sock.close()

            resp_str = response.decode("utf-8", errors="ignore")
            if "200 OK" in resp_str:
                body_start = resp_str.find("[")
                if body_start >= 0:
                    try:
                        indices = json.loads(resp_str[body_start:])
                        result["indices_count"] = len(indices)
                        result["findings"].append(f"Indices accessible: {len(indices)}")
                    except (json.JSONDecodeError, ValueError):
                        pass

        except Exception:
            pass

    def _enum_docker(self, ip: str) -> Dict:
        """Check Docker API for unauthenticated access."""
        result = {
            "ip": ip,
            "port": 2375,
            "service": "docker",
            "no_auth": False,
            "version": None,
            "api_version": None,
            "os": None,
            "containers_count": None,
            "findings": [],
            "risk_level": "info",
        }

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, 2375))

            # Send HTTP GET /version
            request = (
                "GET /version HTTP/1.1\r\n"
                f"Host: {ip}:2375\r\n"
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
                "Accept: application/json\r\n"
                "Connection: close\r\n"
                "\r\n"
            )
            sock.send(request.encode())

            response = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                pass

            sock.close()

            resp_str = response.decode("utf-8", errors="ignore")

            if "200 OK" in resp_str and ("ApiVersion" in resp_str or "Version" in resp_str):
                result["no_auth"] = True
                result["findings"].append("Docker API accessible without authentication")
                result["risk_level"] = "critical"

                try:
                    body_start = resp_str.find("{")
                    if body_start >= 0:
                        body_json = json.loads(resp_str[body_start:])
                        result["version"] = body_json.get("Version")
                        result["api_version"] = body_json.get("ApiVersion")
                        result["os"] = body_json.get("Os")

                        if result["version"]:
                            result["findings"].append(f"Docker version: {result['version']}")
                        if result["os"]:
                            result["findings"].append(f"Host OS: {result['os']}")
                except (json.JSONDecodeError, ValueError):
                    pass

                # Try to get container count
                self._docker_get_containers(ip, result)

            elif "401" in resp_str or "403" in resp_str:
                result["findings"].append("Docker API requires authentication")

        except socket.timeout:
            logger.debug(f"Docker timeout on {ip}:2375")
        except ConnectionRefusedError:
            logger.debug(f"Docker connection refused on {ip}:2375")
        except Exception as e:
            logger.debug(f"Docker enumeration error on {ip}: {e}")

        self._store_result(
            ip=ip,
            port=2375,
            service_type="docker",
            enum_data=result,
            findings=result["findings"],
            risk_level=result["risk_level"],
        )

        return result

    def _docker_get_containers(self, ip: str, result: Dict):
        """Try to list Docker containers."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, 2375))

            request = (
                "GET /containers/json?all=true HTTP/1.1\r\n"
                f"Host: {ip}:2375\r\n"
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
                "Accept: application/json\r\n"
                "Connection: close\r\n"
                "\r\n"
            )
            sock.send(request.encode())

            response = b""
            try:
                while True:
                    chunk = sock.recv(8192)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                pass

            sock.close()

            resp_str = response.decode("utf-8", errors="ignore")
            if "200 OK" in resp_str:
                body_start = resp_str.find("[")
                if body_start >= 0:
                    try:
                        containers = json.loads(resp_str[body_start:])
                        result["containers_count"] = len(containers)
                        result["findings"].append(f"Containers accessible: {len(containers)}")
                    except (json.JSONDecodeError, ValueError):
                        pass

        except Exception:
            pass

    def _enum_winrm(self, ip: str) -> Dict:
        """Check WinRM accessibility (HTTP on 5985, HTTPS on 5986)."""
        result = {
            "ip": ip,
            "port": 5985,
            "service": "winrm",
            "accessible": False,
            "auth_required": True,
            "http_port_open": False,
            "https_port_open": False,
            "findings": [],
            "risk_level": "info",
        }

        # Check HTTP (5985)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, 5985))

            request = (
                "POST /wsman HTTP/1.1\r\n"
                f"Host: {ip}:5985\r\n"
                "User-Agent: Microsoft WinRM Client\r\n"
                "Content-Type: application/soap+xml;charset=UTF-8\r\n"
                "Content-Length: 0\r\n"
                "Connection: close\r\n"
                "\r\n"
            )
            sock.send(request.encode())

            response = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                pass

            sock.close()

            resp_str = response.decode("utf-8", errors="ignore")

            if resp_str:
                result["http_port_open"] = True
                result["accessible"] = True
                result["findings"].append("WinRM HTTP (5985) is accessible")

                if "401" in resp_str:
                    result["auth_required"] = True
                    result["findings"].append("WinRM requires authentication (401)")
                    result["risk_level"] = "low"
                elif "200" in resp_str:
                    result["auth_required"] = False
                    result["findings"].append("WinRM responded without auth challenge")
                    result["risk_level"] = "medium"

        except (socket.timeout, ConnectionRefusedError, OSError):
            pass

        # Check HTTPS (5986)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, 5986))

            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            ssl_sock = context.wrap_socket(sock, server_hostname=ip)

            request = (
                "POST /wsman HTTP/1.1\r\n"
                f"Host: {ip}:5986\r\n"
                "User-Agent: Microsoft WinRM Client\r\n"
                "Content-Type: application/soap+xml;charset=UTF-8\r\n"
                "Content-Length: 0\r\n"
                "Connection: close\r\n"
                "\r\n"
            )
            ssl_sock.send(request.encode())

            response = b""
            try:
                while True:
                    chunk = ssl_sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                pass

            ssl_sock.close()

            if response:
                result["https_port_open"] = True
                result["accessible"] = True
                result["findings"].append("WinRM HTTPS (5986) is accessible")

        except (socket.timeout, ConnectionRefusedError, OSError, ssl.SSLError):
            pass

        if result["accessible"]:
            self._store_result(
                ip=ip,
                port=5985,
                service_type="winrm",
                enum_data=result,
                findings=result["findings"],
                risk_level=result["risk_level"],
            )

        return result

    # =========================================================================
    # HELPER METHODS
    # =========================================================================

    def _store_result(self, ip: str, port: int, service_type: str, enum_data: dict, findings: list, risk_level: str):
        """Store enumeration result in database."""
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute("PRAGMA journal_mode=WAL")

            # Try to find host_id
            host_id = None
            try:
                cursor = conn.execute("SELECT id FROM hosts WHERE ip = ?", (ip,))
                row = cursor.fetchone()
                if row:
                    host_id = row[0]
            except sqlite3.OperationalError:
                pass  # hosts table may not exist yet

            if host_id is None:
                logger.warning(f"Skipping service enumeration save for {ip}:{port} (host not in DB)")
                return

            now = datetime.now(timezone.utc).isoformat()
            attack_tags = self._derive_attack_tags(service_type, enum_data, findings, risk_level)
            if attack_tags:
                enum_data = dict(enum_data)
                enum_data["attack_tags"] = sorted(attack_tags)
                enum_data["attack_summary"] = self._attack_summary(service_type, attack_tags)
            details_text = json.dumps(
                {
                    "enum_data": enum_data,
                    "findings": findings,
                    "risk_level": risk_level,
                },
                default=str,
            )
            title = findings[0] if findings else f"{service_type} enumeration"
            severity = risk_level if risk_level in {"critical", "high", "medium", "low", "info"} else "info"

            cols = {row[1] for row in conn.execute("PRAGMA table_info(service_enumeration)").fetchall()}
            payload = {
                "host_id": host_id,
                "ip": ip,
                "port": port,
                "service_type": service_type,
                "finding_type": "enumeration",
                "severity": severity,
                "risk_level": risk_level,
                "title": title,
                "details": details_text,
                "findings": json.dumps(findings),
                "enum_data": json.dumps(enum_data, default=str),
                "discovered_at": now,
                "enumerated_at": now,
            }
            existing = conn.execute(
                "SELECT id FROM service_enumeration WHERE host_id = ? AND port = ? AND service_type = ?",
                (host_id, port, service_type),
            ).fetchone()
            if existing:
                conn.execute(
                    "UPDATE service_enumeration SET enum_data = ?, findings = ?, risk_level = ?, "
                    "enumerated_at = ?, details = ?, title = ? WHERE id = ?",
                    (
                        json.dumps(enum_data, default=str),
                        json.dumps(findings),
                        risk_level,
                        now,
                        details_text,
                        title,
                        existing[0],
                    ),
                )
                conn.commit()
                return

            insert_cols = [c for c in payload.keys() if c in cols]
            placeholders = ", ".join("?" for _ in insert_cols)
            conn.execute(
                f"INSERT INTO service_enumeration ({', '.join(insert_cols)}) VALUES ({placeholders})",
                tuple(payload[c] for c in insert_cols),
            )

            if attack_tags:
                host_tags = [
                    ("pivot-node", "Service exposure suggests pivot value")
                    if tag == "pivot-node"
                    else ("relay-risk", "Unsigned SMB or relay-prone service")
                    if tag == "relay-risk"
                    else (tag, f"{service_type} red-team primitive")
                    for tag in sorted(attack_tags)
                ]
                for tag, _reason in host_tags:
                    try:
                        conn.execute(
                            "INSERT OR IGNORE INTO host_tags (host_id, tag, added_at) VALUES (?, ?, ?)",
                            (host_id, tag, now),
                        )
                    except sqlite3.OperationalError:
                        break

            conn.commit()
            logger.debug(f"Stored {service_type} enumeration for {ip}:{port} [{risk_level}]")
        except Exception as e:
            logger.error(f"Failed to store result for {ip}:{port}: {e}")
            if conn:
                try:
                    conn.rollback()
                except Exception:
                    pass
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    def _derive_attack_tags(self, service_type: str, enum_data: Dict, findings: List[str], risk_level: str) -> set[str]:
        """Convert service findings into red-team attack primitives."""
        tags: set[str] = set()
        normalized = (service_type or "").lower()
        tag_rules = ATTACK_TAG_RULES.get(normalized, {})

        for tag in tag_rules:
            tags.add(tag)

        if normalized == "smb":
            if enum_data.get("signing_required") is False:
                tags.add("relay-risk")
            if enum_data.get("null_session"):
                tags.add("domain-enum")
                tags.add("credential-harvest")
        elif normalized in ("ldap", "ldaps"):
            if enum_data.get("anonymous_bind"):
                tags.add("domain-enum")
                tags.add("credential-harvest")
        elif normalized == "redis":
            if enum_data.get("no_auth"):
                tags.add("host-takeover")
                tags.add("pivot-node")
        elif normalized == "docker":
            if enum_data.get("no_auth"):
                tags.add("host-takeover")
                tags.add("admin-plane")
        elif normalized == "elasticsearch":
            if enum_data.get("no_auth"):
                tags.add("data-exposure")
                tags.add("pivot-node")
        elif normalized == "winrm":
            if enum_data.get("accessible"):
                tags.add("lateral-movement")
                tags.add("admin-plane")
        elif normalized == "ssh":
            tags.add("lateral-movement")

        if risk_level in ATTACK_SEVERITY_TAGS:
            tags.update(ATTACK_SEVERITY_TAGS[risk_level])

        for finding in findings or []:
            text = str(finding).lower()
            if "relay" in text:
                tags.add("relay-risk")
            if "null session" in text or "anonymous ldap bind" in text:
                tags.add("domain-enum")
            if "unauthenticated" in text or "without authentication" in text:
                tags.add("host-takeover")
            if "admin" in text or "privilege" in text:
                tags.add("admin-plane")

        return tags

    def _attack_summary(self, service_type: str, tags: set[str]) -> str:
        """Generate a short red-team oriented summary for a service."""
        service_label = (service_type or "service").upper()
        focus = []
        if "host-takeover" in tags:
            focus.append("host takeover")
        if "relay-risk" in tags:
            focus.append("relay risk")
        if "domain-enum" in tags:
            focus.append("domain enumeration")
        if "lateral-movement" in tags:
            focus.append("lateral movement")
        if "data-exposure" in tags:
            focus.append("data exposure")
        if "admin-plane" in tags:
            focus.append("admin plane access")
        if not focus:
            focus.append("pivot value")
        return f"{service_label}: {', '.join(focus)}"

    def _apply_jitter(self, base_delay: float) -> float:
        """Apply randomized jitter to a delay value."""
        jitter = base_delay * self.jitter_factor * random.uniform(-1.0, 1.0)
        return max(1.0, base_delay + jitter)

    # =========================================================================
    # ASN.1 / BER ENCODING HELPERS
    # =========================================================================

    @staticmethod
    def _asn1_length(length: int) -> bytes:
        """Encode ASN.1 length field."""
        if length < 0x80:
            return struct.pack("B", length)
        elif length < 0x100:
            return b"\x81" + struct.pack("B", length)
        elif length < 0x10000:
            return b"\x82" + struct.pack(">H", length)
        else:
            return b"\x83" + struct.pack(">I", length)[1:]

    @staticmethod
    def _asn1_sequence(data: bytes) -> bytes:
        """Wrap data in ASN.1 SEQUENCE."""
        return b"\x30" + ServiceEnumerator._asn1_length(len(data)) + data

    @staticmethod
    def _ber_integer(value: int) -> bytes:
        """Encode BER INTEGER."""
        if value == 0:
            return b"\x02\x01\x00"
        # Determine minimum bytes needed
        if value < 0:
            # Negative values need special handling
            byte_len = (value.bit_length() + 8) // 8
        else:
            byte_len = (value.bit_length() + 8) // 8
        encoded = value.to_bytes(byte_len, byteorder="big", signed=(value < 0))
        # Strip leading zero bytes (but keep one if high bit is set for positive)
        while len(encoded) > 1 and encoded[0] == 0 and not (encoded[1] & 0x80):
            encoded = encoded[1:]
        return b"\x02" + ServiceEnumerator._asn1_length(len(encoded)) + encoded

    @staticmethod
    def _ber_octet_string(data: bytes) -> bytes:
        """Encode BER OCTET STRING."""
        return b"\x04" + ServiceEnumerator._asn1_length(len(data)) + data

    @staticmethod
    def _ber_enumerated(value: int) -> bytes:
        """Encode BER ENUMERATED."""
        encoded = value.to_bytes(1, byteorder="big")
        return b"\x0a" + ServiceEnumerator._asn1_length(len(encoded)) + encoded

    @staticmethod
    def _ber_boolean(value: bool) -> bytes:
        """Encode BER BOOLEAN."""
        return b"\x01\x01" + (b"\xff" if value else b"\x00")

    @staticmethod
    def _parse_asn1_length(data: bytes, offset: int) -> Tuple[int, int]:
        """Parse ASN.1 length at offset, return (new_offset, length)."""
        if offset >= len(data):
            return offset, 0

        length_byte = data[offset]
        offset += 1

        if length_byte < 0x80:
            return offset, length_byte
        elif length_byte == 0x81:
            if offset >= len(data):
                return offset, 0
            return offset + 1, data[offset]
        elif length_byte == 0x82:
            if offset + 1 >= len(data):
                return offset, 0
            length = struct.unpack(">H", data[offset : offset + 2])[0]
            return offset + 2, length
        elif length_byte == 0x83:
            if offset + 2 >= len(data):
                return offset, 0
            length = struct.unpack(">I", b"\x00" + data[offset : offset + 3])[0]
            return offset + 3, length
        else:
            return offset, 0
