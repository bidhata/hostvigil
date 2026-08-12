"""
SSL/TLS Inspection Module for HostVigil.

Connects to TLS-enabled services to extract security-relevant information
including certificates, cipher suites, protocol versions, and weaknesses.

Stealth principles:
- Standard TLS handshakes indistinguishable from normal HTTPS clients
- Randomized delays between inspections
- No aggressive cipher probing
- All results stored in SQLite
"""

import hashlib
import json
import logging
import random
import socket
import sqlite3
import ssl
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

logger = logging.getLogger("hostvigil.scanner.tls_inspector")

# Common TLS ports to inspect
TLS_PORTS = [443, 636, 993, 995, 465, 8443, 5986, 2376, 9443, 3389]

# Weak cipher patterns
WEAK_CIPHERS = [
    "RC4",
    "DES",
    "MD5",
    "NULL",
    "EXPORT",
    "anon",
    "RC2",
    "IDEA",
    "SEED",
    "CAMELLIA128",
]

# Deprecated protocol versions
DEPRECATED_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]


class TLSInspector:
    """SSL/TLS inspection for security assessment of encrypted services."""

    def __init__(self, config: dict, db_path: str):
        self.config = config
        self.db_path = db_path
        self.min_delay = config.get("min_delay", 10.0)
        self.max_delay = config.get("max_delay", 45.0)
        self.jitter_factor = config.get("jitter_factor", 0.3)
        self.timeout = config.get("timeout", 5.0)
        self._ensure_table()

    def _ensure_table(self):
        """Create/migrate tls_certificates table for schema compatibility."""
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("""CREATE TABLE IF NOT EXISTS tls_certificates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER,
                ip TEXT,
                port INTEGER NOT NULL,
                subject TEXT,
                issuer TEXT,
                serial_number TEXT,
                not_before TEXT,
                not_after TEXT,
                is_expired INTEGER DEFAULT 0,
                is_self_signed INTEGER DEFAULT 0,
                signature_algorithm TEXT,
                key_type TEXT,
                key_size INTEGER,
                key_bits INTEGER,
                san_names TEXT,
                san_domains TEXT,
                protocol_version TEXT,
                cipher_suite TEXT,
                cipher_bits INTEGER,
                weaknesses TEXT,
                fingerprint_sha256 TEXT,
                cert_fingerprint_sha256 TEXT,
                inspected_at TEXT,
                FOREIGN KEY (host_id) REFERENCES hosts(id)
            )""")

            cols = {row[1] for row in conn.execute("PRAGMA table_info(tls_certificates)").fetchall()}
            for col_def in (
                "ip TEXT",
                "signature_algorithm TEXT",
                "key_size INTEGER",
                "key_bits INTEGER",
                "san_names TEXT",
                "san_domains TEXT",
                "cipher_bits INTEGER",
                "weaknesses TEXT",
                "fingerprint_sha256 TEXT",
                "cert_fingerprint_sha256 TEXT",
            ):
                col_name = col_def.split()[0]
                if col_name not in cols:
                    conn.execute(f"ALTER TABLE tls_certificates ADD COLUMN {col_def}")

            # Backfill compatibility fields if one naming set exists but the other does not.
            if "fingerprint_sha256" in cols and "cert_fingerprint_sha256" in cols:
                conn.execute(
                    "UPDATE tls_certificates SET cert_fingerprint_sha256 = fingerprint_sha256 "
                    "WHERE (cert_fingerprint_sha256 IS NULL OR cert_fingerprint_sha256 = '') "
                    "AND fingerprint_sha256 IS NOT NULL AND fingerprint_sha256 != ''"
                )
                conn.execute(
                    "UPDATE tls_certificates SET fingerprint_sha256 = cert_fingerprint_sha256 "
                    "WHERE (fingerprint_sha256 IS NULL OR fingerprint_sha256 = '') "
                    "AND cert_fingerprint_sha256 IS NOT NULL AND cert_fingerprint_sha256 != ''"
                )
            if "key_bits" in cols and "key_size" in cols:
                conn.execute(
                    "UPDATE tls_certificates SET key_size = key_bits "
                    "WHERE (key_size IS NULL OR key_size = 0) AND key_bits IS NOT NULL AND key_bits > 0"
                )
                conn.execute(
                    "UPDATE tls_certificates SET key_bits = key_size "
                    "WHERE (key_bits IS NULL OR key_bits = 0) AND key_size IS NOT NULL AND key_size > 0"
                )
            if "san_domains" in cols and "san_names" in cols:
                conn.execute(
                    "UPDATE tls_certificates SET san_names = san_domains "
                    "WHERE (san_names IS NULL OR san_names = '') AND san_domains IS NOT NULL AND san_domains != ''"
                )
                conn.execute(
                    "UPDATE tls_certificates SET san_domains = san_names "
                    "WHERE (san_domains IS NULL OR san_domains = '') AND san_names IS NOT NULL AND san_names != ''"
                )

            conn.commit()
        finally:
            conn.close()

    def inspect_all(self) -> List[Dict]:
        """Inspect all hosts with TLS ports open in the database."""
        results = []
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row

        # Query hosts that have TLS-capable ports open
        port_placeholders = ",".join("?" for _ in TLS_PORTS)
        query = f"""
            SELECT DISTINCT h.id as host_id, h.ip, p.port
            FROM hosts h
            JOIN ports p ON h.id = p.host_id
            WHERE p.port IN ({port_placeholders})
            AND p.state = 'open' AND p.is_active = 1
            AND h.is_active = 1
        """

        try:
            rows = conn.execute(query, TLS_PORTS).fetchall()
        except sqlite3.OperationalError as e:
            logger.warning("Failed to query ports table: %s", e)
            rows = []
        finally:
            conn.close()

        total = len(rows)
        logger.info(f"TLS inspection starting for {total} host:port combinations")

        for idx, row in enumerate(rows):
            if isinstance(row, dict):
                ip = row["ip"]
                port = row["port"]
            else:
                ip = row["ip"]
                port = row["port"]

            logger.debug(f"Inspecting {ip}:{port} ({idx + 1}/{total})")
            try:
                result = self.inspect_host(ip, port)
                if result:
                    results.append(result)
            except Exception as e:
                logger.error(f"TLS inspection failed for {ip}:{port}: {e}")

            # Apply stealth delay between inspections (skip after last)
            if idx < total - 1:
                delay = random.uniform(self.min_delay, self.max_delay)
                delay = self._apply_jitter(delay)
                logger.debug(f"Stealth delay: {delay:.1f}s")
                time.sleep(delay)

        logger.info(f"TLS inspection complete: {len(results)}/{total} successful")
        return results

    def inspect_host(self, ip: str, port: int) -> Optional[Dict]:
        """Inspect a single host:port TLS connection."""
        logger.debug(f"TLS inspecting {ip}:{port}")

        tls_info = self._connect_tls(ip, port)
        if tls_info is None:
            logger.debug(f"TLS connection failed for {ip}:{port}")
            return None

        # Check for weaknesses
        weaknesses = self._check_weaknesses(tls_info)
        tls_info["weaknesses"] = weaknesses

        # Check protocol support (stealthy - one connection per protocol)
        supported_protocols = self._check_protocol_support(ip, port)
        tls_info["supported_protocols"] = supported_protocols

        # Flag deprecated protocols in weaknesses
        for proto in supported_protocols:
            if proto in DEPRECATED_PROTOCOLS:
                weakness = f"deprecated_protocol:{proto}"
                if weakness not in weaknesses:
                    weaknesses.append(weakness)

        # Store result
        self._store_result(ip, port, tls_info)

        logger.info(
            f"TLS inspection {ip}:{port} - "
            f"{tls_info.get('protocol_version', 'unknown')} "
            f"{'[WEAK]' if weaknesses else '[OK]'}"
        )
        return tls_info

    def _connect_tls(self, ip: str, port: int) -> Optional[Dict]:
        """Perform TLS handshake and extract certificate info."""
        try:
            # Create permissive SSL context (connect even to self-signed)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            # Set reasonable ciphers (mimics modern browser)
            try:
                ctx.set_ciphers("DEFAULT:!aNULL:!eNULL")
            except ssl.SSLError:
                pass  # Use whatever default is available

            # Connect with timeout
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.settimeout(self.timeout)
            raw_sock.connect((ip, port))

            # Wrap with TLS
            try:
                tls_sock = ctx.wrap_socket(raw_sock, server_hostname=ip)
            except Exception:
                raw_sock.close()
                raise

            try:
                # Get certificate in dict form (requires CERT_NONE workaround)
                binary_cert = tls_sock.getpeercert(binary_form=True)
                cert_dict = tls_sock.getpeercert()

                # If cert_dict is empty (CERT_NONE doesn't validate),
                # decode from binary using ssl helper
                if not cert_dict and binary_cert:
                    cert_dict = (
                        ssl._ssl._test_decode_cert(  # noqa: SLF001
                            ssl.DER_cert_to_PEM_cert(binary_cert)
                        )
                        if hasattr(ssl._ssl, "_test_decode_cert")
                        else {}
                    )

                # Get cipher info
                cipher_info = tls_sock.cipher()
                cipher_name = cipher_info[0] if cipher_info else None
                cipher_version = cipher_info[1] if cipher_info else None
                cipher_bits = cipher_info[2] if cipher_info else None

                # Get protocol version
                protocol_version = tls_sock.version()

                # Compute SHA-256 fingerprint
                fingerprint = hashlib.sha256(binary_cert).hexdigest() if binary_cert else None

                # Extract structured cert info
                cert_info = self._extract_cert_info(cert_dict, binary_cert)
                cert_info["protocol_version"] = protocol_version
                cert_info["cipher_suite"] = cipher_name
                cert_info["cipher_version"] = cipher_version
                cert_info["cipher_bits"] = cipher_bits
                cert_info["cert_fingerprint_sha256"] = fingerprint
                cert_info["ip"] = ip
                cert_info["port"] = port

                return cert_info

            finally:
                tls_sock.close()

        except ssl.SSLError as e:
            logger.debug(f"SSL error connecting to {ip}:{port}: {e}")
            return None
        except socket.timeout:
            logger.debug(f"Timeout connecting to {ip}:{port}")
            return None
        except ConnectionRefusedError:
            logger.debug(f"Connection refused: {ip}:{port}")
            return None
        except OSError as e:
            logger.debug(f"OS error connecting to {ip}:{port}: {e}")
            return None

    def _extract_cert_info(self, cert: dict, binary_cert: bytes) -> Dict:
        """Parse certificate dictionary into structured info."""
        info = {}

        # Subject - flatten RDN sequence
        subject_parts = []
        for rdn in cert.get("subject", ()):
            for attr_type, attr_value in rdn:
                subject_parts.append(f"{attr_type}={attr_value}")
        info["subject"] = ", ".join(subject_parts)

        # Issuer - flatten RDN sequence
        issuer_parts = []
        for rdn in cert.get("issuer", ()):
            for attr_type, attr_value in rdn:
                issuer_parts.append(f"{attr_type}={attr_value}")
        info["issuer"] = ", ".join(issuer_parts)

        # Check self-signed (subject == issuer)
        info["is_self_signed"] = info["subject"] == info["issuer"]

        # Serial number
        info["serial_number"] = cert.get("serialNumber", "")

        # Validity dates
        not_before_str = cert.get("notBefore", "")
        not_after_str = cert.get("notAfter", "")
        info["not_before"] = not_before_str
        info["not_after"] = not_after_str

        # Parse dates for expiry check
        date_formats = [
            "%b %d %H:%M:%S %Y %Z",
            "%b  %d %H:%M:%S %Y %Z",
            "%Y%m%d%H%M%SZ",
        ]
        info["is_expired"] = False
        info["expires_soon"] = False

        if not_after_str:
            for fmt in date_formats:
                try:
                    not_after_dt = datetime.strptime(not_after_str, fmt)
                    not_after_dt = not_after_dt.replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    info["is_expired"] = now > not_after_dt
                    info["expires_soon"] = not info["is_expired"] and (not_after_dt - now) < timedelta(days=30)
                    break
                except ValueError:
                    continue

        # Subject Alternative Names (SANs)
        san_entries = []
        for san_type, san_value in cert.get("subjectAltName", ()):
            san_entries.append(f"{san_type}:{san_value}")
        info["san_names"] = san_entries

        # Signature algorithm (from OCSP or parsed from binary)
        # Python's ssl module doesn't expose this directly in all versions
        # Try to get it from the cert dict
        info["signature_algorithm"] = cert.get("signatureAlgorithm", "")

        # If not available, attempt to detect from binary cert
        if not info["signature_algorithm"] and binary_cert:
            info["signature_algorithm"] = self._detect_sig_algorithm(binary_cert)

        # Key info - attempt to extract from cert
        # Python ssl doesn't always expose key details directly
        info["key_type"] = ""
        info["key_size"] = 0

        # Try to determine key info from the certificate
        if binary_cert:
            key_info = self._extract_key_info(binary_cert)
            info["key_type"] = key_info.get("type", "")
            info["key_size"] = key_info.get("size", 0)

        return info

    def _detect_sig_algorithm(self, binary_cert: bytes) -> str:
        """Attempt to detect signature algorithm from DER certificate bytes."""
        # Look for common OID patterns in the binary cert
        # SHA-256 with RSA: 1.2.840.113549.1.1.11
        # SHA-1 with RSA: 1.2.840.113549.1.1.5
        # MD5 with RSA: 1.2.840.113549.1.1.4
        # SHA-384 with RSA: 1.2.840.113549.1.1.12
        # SHA-512 with RSA: 1.2.840.113549.1.1.13

        oid_map = {
            b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b": "sha256WithRSAEncryption",
            b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x05": "sha1WithRSAEncryption",
            b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x04": "md5WithRSAEncryption",
            b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0c": "sha384WithRSAEncryption",
            b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0d": "sha512WithRSAEncryption",
            b"\x2a\x86\x48\xce\x3d\x04\x03\x02": "ecdsa-with-SHA256",
            b"\x2a\x86\x48\xce\x3d\x04\x03\x03": "ecdsa-with-SHA384",
        }

        for oid_bytes, algo_name in oid_map.items():
            if oid_bytes in binary_cert:
                return algo_name

        return "unknown"

    def _extract_key_info(self, binary_cert: bytes) -> Dict:
        """Extract public key type and size from DER certificate."""
        # RSA key OID: 1.2.840.113549.1.1.1
        rsa_oid = b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"
        # EC key OID: 1.2.840.10045.2.1
        ec_oid = b"\x2a\x86\x48\xce\x3d\x02\x01"

        if rsa_oid in binary_cert:
            key_type = "RSA"
            # Attempt to find key size from modulus length
            # The modulus is in a BIT STRING after the algorithm identifier
            # Common sizes map to specific byte lengths in the cert
            cert_len = len(binary_cert)
            if cert_len > 1000:
                # Heuristic: larger certs typically have larger keys
                # Look for the RSA modulus marker (INTEGER with long length)
                key_size = self._find_rsa_key_size(binary_cert)
            else:
                key_size = 0
            return {"type": key_type, "size": key_size}
        elif ec_oid in binary_cert:
            return {"type": "EC", "size": 256}  # Default EC assumption
        else:
            return {"type": "unknown", "size": 0}

    def _find_rsa_key_size(self, binary_cert: bytes) -> int:
        """Heuristically determine RSA key size from DER certificate."""
        # Look for INTEGER tags (0x02) with long-form lengths
        # indicating the RSA modulus
        # RSA modulus for 2048-bit key is ~257 bytes (256 + leading zero)
        # RSA modulus for 4096-bit key is ~513 bytes
        # RSA modulus for 1024-bit key is ~129 bytes

        i = 0
        largest_integer = 0
        while i < len(binary_cert) - 4:
            if binary_cert[i] == 0x02:  # INTEGER tag
                i += 1
                # Parse length
                length = 0
                if binary_cert[i] & 0x80:
                    # Long form
                    num_bytes = binary_cert[i] & 0x7F
                    i += 1
                    for _ in range(num_bytes):
                        if i < len(binary_cert):
                            length = (length << 8) | binary_cert[i]
                            i += 1
                else:
                    length = binary_cert[i]
                    i += 1

                if length > largest_integer and length < 1024:
                    largest_integer = length
                i += max(length, 1)
            else:
                i += 1

        # Convert byte length to bit size (subtract 1 for leading zero byte)
        if largest_integer >= 512:
            return 4096
        elif largest_integer >= 256:
            return 2048
        elif largest_integer >= 128:
            return 1024
        elif largest_integer >= 64:
            return 512
        else:
            return 0

    def _check_weaknesses(self, cert_info: Dict) -> List[str]:
        """Identify security weaknesses in the certificate/connection."""
        weaknesses = []

        # Check: expired
        if cert_info.get("is_expired"):
            weaknesses.append("expired_certificate")

        # Check: expiring within 30 days
        if cert_info.get("expires_soon"):
            weaknesses.append("expires_within_30_days")

        # Check: self-signed
        if cert_info.get("is_self_signed"):
            weaknesses.append("self_signed_certificate")

        # Check: weak key size (RSA < 2048)
        key_type = cert_info.get("key_type", "")
        key_size = cert_info.get("key_size", 0)
        if key_type == "RSA" and 0 < key_size < 2048:
            weaknesses.append(f"weak_key_size:RSA-{key_size}")

        # Check: SHA-1 or MD5 signature algorithm
        sig_algo = cert_info.get("signature_algorithm", "").lower()
        if "sha1" in sig_algo or "sha-1" in sig_algo:
            weaknesses.append("sha1_signature")
        if "md5" in sig_algo:
            weaknesses.append("md5_signature")

        # Check: deprecated TLS protocol version
        protocol = cert_info.get("protocol_version", "")
        if protocol in DEPRECATED_PROTOCOLS:
            weaknesses.append(f"deprecated_protocol:{protocol}")

        # Check: weak cipher suite
        cipher = cert_info.get("cipher_suite", "") or ""
        for weak_pattern in WEAK_CIPHERS:
            if weak_pattern.upper() in cipher.upper():
                weaknesses.append(f"weak_cipher:{cipher}")
                break

        # Check: weak cipher bits
        cipher_bits = cert_info.get("cipher_bits", 0) or 0
        if 0 < cipher_bits < 128:
            weaknesses.append(f"weak_cipher_bits:{cipher_bits}")

        # Check: wildcard certificate
        san_names = cert_info.get("san_names", [])
        subject = cert_info.get("subject", "")
        has_wildcard = False
        if "*." in subject:
            has_wildcard = True
        for san in san_names:
            if "*." in san:
                has_wildcard = True
                break
        if has_wildcard:
            weaknesses.append("wildcard_certificate")

        # Check: no SAN entries
        if not san_names:
            weaknesses.append("no_san_entries")

        return weaknesses

    def _check_protocol_support(self, ip: str, port: int) -> List[str]:
        """Test which TLS protocol versions are supported (stealthy)."""
        supported = []

        # Protocol versions to test with their ssl constants
        protocols_to_test = []

        # TLS 1.2 - use TLS_CLIENT with max version set
        protocols_to_test.append(("TLSv1.2", ssl.TLSVersion.TLSv1_2))

        # TLS 1.3
        if hasattr(ssl.TLSVersion, "TLSv1_3"):
            protocols_to_test.append(("TLSv1.3", ssl.TLSVersion.TLSv1_3))

        # TLS 1.1 (deprecated but we want to detect if server supports it)
        if hasattr(ssl.TLSVersion, "TLSv1_1"):
            protocols_to_test.append(("TLSv1.1", ssl.TLSVersion.TLSv1_1))

        # TLS 1.0
        if hasattr(ssl.TLSVersion, "TLSv1"):
            protocols_to_test.append(("TLSv1", ssl.TLSVersion.TLSv1))

        for proto_name, proto_version in protocols_to_test:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

                # Pin to specific version
                ctx.minimum_version = proto_version
                ctx.maximum_version = proto_version

                raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                raw_sock.settimeout(self.timeout)
                try:
                    raw_sock.connect((ip, port))
                    tls_sock = ctx.wrap_socket(raw_sock, server_hostname=ip)
                    supported.append(proto_name)
                    tls_sock.close()
                except (ssl.SSLError, OSError, socket.timeout):
                    pass
                finally:
                    try:
                        raw_sock.close()
                    except OSError:
                        pass

            except (ssl.SSLError, ValueError):
                # Protocol version not supported by local ssl library
                continue
            except (socket.timeout, ConnectionRefusedError, OSError):
                # Connection issue - don't mark protocol as unsupported
                # just because we can't reach the host
                break

            # Small stealth delay between protocol tests (1-3 seconds)
            time.sleep(random.uniform(1.0, 3.0))

        return supported

    def _store_result(self, ip: str, port: int, cert_info: Dict):
        """Store TLS inspection result in database. Deduplicates by fingerprint."""
        fingerprint = cert_info.get("cert_fingerprint_sha256", "")
        san_names = cert_info.get("san_names", [])
        san_domains = cert_info.get("san_domains", "")
        if not san_domains:
            san_domains = ",".join(s.split(":", 1)[1] for s in san_names if isinstance(s, str) and s.startswith("DNS:"))
        key_size = cert_info.get("key_size", 0)
        key_bits = cert_info.get("key_bits", key_size)
        now = datetime.now(timezone.utc).isoformat()

        conn = sqlite3.connect(self.db_path)
        try:
            # Resolve host_id if possible
            host_id = None
            try:
                row = conn.execute("SELECT id FROM hosts WHERE ip = ?", (ip,)).fetchone()
                if row:
                    host_id = row[0]
            except sqlite3.OperationalError:
                pass

            if host_id is None:
                logger.warning(f"Skipping TLS result storage for {ip}:{port} (host not in DB)")
                return

            # Check for existing entry with same fingerprint.
            existing = conn.execute(
                """SELECT id FROM tls_certificates
                   WHERE ip = ? AND port = ?
                   AND (cert_fingerprint_sha256 = ? OR fingerprint_sha256 = ?)""",
                (ip, port, fingerprint, fingerprint),
            ).fetchone()

            if existing:
                # Update existing record
                conn.execute(
                    """UPDATE tls_certificates SET
                        protocol_version = ?,
                        cipher_suite = ?,
                        cipher_bits = ?,
                        weaknesses = ?,
                        is_expired = ?,
                        is_self_signed = ?,
                        key_type = ?,
                        key_size = ?,
                        key_bits = ?,
                        san_names = ?,
                        san_domains = ?,
                        signature_algorithm = ?,
                        fingerprint_sha256 = ?,
                        cert_fingerprint_sha256 = ?,
                        inspected_at = ?
                       WHERE id = ?""",
                    (
                        cert_info.get("protocol_version", ""),
                        cert_info.get("cipher_suite", ""),
                        cert_info.get("cipher_bits", 0),
                        json.dumps(cert_info.get("weaknesses", [])),
                        1 if cert_info.get("is_expired") else 0,
                        1 if cert_info.get("is_self_signed") else 0,
                        cert_info.get("key_type", ""),
                        key_size,
                        key_bits,
                        json.dumps(san_names),
                        san_domains,
                        cert_info.get("signature_algorithm", ""),
                        fingerprint,
                        fingerprint,
                        now,
                        existing[0],
                    ),
                )
            else:
                # Insert new record
                conn.execute(
                    """INSERT INTO tls_certificates (
                        host_id, ip, port, subject, issuer, serial_number,
                        not_before, not_after, is_expired, is_self_signed,
                        signature_algorithm, key_type, key_size, key_bits,
                        san_names, san_domains,
                        protocol_version, cipher_suite, cipher_bits,
                        weaknesses, fingerprint_sha256, cert_fingerprint_sha256, inspected_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        host_id,
                        ip,
                        port,
                        cert_info.get("subject", ""),
                        cert_info.get("issuer", ""),
                        cert_info.get("serial_number", ""),
                        cert_info.get("not_before", ""),
                        cert_info.get("not_after", ""),
                        1 if cert_info.get("is_expired") else 0,
                        1 if cert_info.get("is_self_signed") else 0,
                        cert_info.get("signature_algorithm", ""),
                        cert_info.get("key_type", ""),
                        key_size,
                        key_bits,
                        json.dumps(san_names),
                        san_domains,
                        cert_info.get("protocol_version", ""),
                        cert_info.get("cipher_suite", ""),
                        cert_info.get("cipher_bits", 0),
                        json.dumps(cert_info.get("weaknesses", [])),
                        fingerprint,
                        fingerprint,
                        now,
                    ),
                )

            conn.commit()
        finally:
            conn.close()

    def get_expired_certs(self) -> List[Dict]:
        """Get all hosts with expired certificates."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """SELECT * FROM tls_certificates WHERE is_expired = 1
               ORDER BY inspected_at DESC"""
        ).fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def get_weak_tls(self) -> List[Dict]:
        """Get all hosts with TLS weaknesses."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """SELECT * FROM tls_certificates
               WHERE weaknesses IS NOT NULL AND weaknesses != '[]'
               ORDER BY inspected_at DESC"""
        ).fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def get_self_signed(self) -> List[Dict]:
        """Get all hosts with self-signed certificates."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """SELECT * FROM tls_certificates WHERE is_self_signed = 1
               ORDER BY inspected_at DESC"""
        ).fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def _apply_jitter(self, base_delay: float) -> float:
        """Apply random jitter to delay."""
        jitter = base_delay * self.jitter_factor * random.uniform(-1.0, 1.0)
        return max(1.0, base_delay + jitter)
