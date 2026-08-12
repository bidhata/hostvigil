"""
Active Directory Integration Module - Deep AD enumeration via raw LDAP.

Enhances existing LDAP enumeration with AD-specific queries when anonymous
or authenticated LDAP access is available on domain controllers.

Capabilities:
- Domain users with group membership and logon timestamps
- Domain groups with members
- Domain computers with OS versions
- Privileged account identification (Domain Admins, Enterprise Admins)
- Kerberoastable accounts (servicePrincipalName set)
- AS-REP roastable accounts (DONT_REQUIRE_PREAUTH flag)
- Domain trust relationships
- Password policy extraction

Dependency-light: uses raw socket + BER/ASN.1 encoding for LDAP protocol.
"""

import json
import logging
import socket
import sqlite3
import ssl
import struct
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("hostvigil.scanner.ad_integration")

# LDAP protocol constants
LDAP_SCOPE_BASE = 0
LDAP_SCOPE_ONELEVEL = 1
LDAP_SCOPE_SUBTREE = 2

# UserAccountControl flags
UAC_ACCOUNTDISABLE = 0x0002
UAC_DONT_REQUIRE_PREAUTH = 0x400000
UAC_TRUSTED_FOR_DELEGATION = 0x80000
UAC_PASSWORD_NOT_REQUIRED = 0x0020

# Well-known SIDs for privileged groups
PRIVILEGED_GROUPS = [
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Account Operators",
    "Backup Operators",
    "Server Operators",
    "DnsAdmins",
]


class ADIntegration:
    """Active Directory enumeration via raw LDAP socket operations."""

    def __init__(self, config: dict, db_path: str):
        self.db_path = db_path
        self.timeout = config.get("timeout", 10.0)
        self.size_limit = config.get("size_limit", 1000)
        self._msg_counter = 0
        self._ensure_table()

    def _ensure_table(self):
        """Create ad_objects table if not exists."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("""CREATE TABLE IF NOT EXISTS ad_objects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            object_type TEXT NOT NULL,
            name TEXT NOT NULL,
            dn TEXT,
            attributes_json TEXT,
            discovered_at TEXT NOT NULL
        )""")
        conn.execute("""CREATE INDEX IF NOT EXISTS idx_ad_objects_domain
            ON ad_objects(domain)""")
        conn.execute("""CREATE INDEX IF NOT EXISTS idx_ad_objects_type
            ON ad_objects(domain, object_type)""")
        conn.commit()
        conn.close()

    # =========================================================================
    # BER / ASN.1 ENCODING HELPERS
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
    def _ber_integer(value: int) -> bytes:
        """Encode BER INTEGER."""
        if value == 0:
            return b"\x02\x01\x00"
        byte_len = (value.bit_length() + 8) // 8
        encoded = value.to_bytes(byte_len, byteorder="big", signed=(value < 0))
        while len(encoded) > 1 and encoded[0] == 0 and not (encoded[1] & 0x80):
            encoded = encoded[1:]
        return b"\x02" + ADIntegration._asn1_length(len(encoded)) + encoded

    @staticmethod
    def _ber_octet_string(data: bytes) -> bytes:
        """Encode BER OCTET STRING."""
        return b"\x04" + ADIntegration._asn1_length(len(data)) + data

    @staticmethod
    def _ber_enumerated(value: int) -> bytes:
        """Encode BER ENUMERATED."""
        encoded = value.to_bytes(1, byteorder="big")
        return b"\x0a" + ADIntegration._asn1_length(len(encoded)) + encoded

    @staticmethod
    def _ber_boolean(value: bool) -> bytes:
        """Encode BER BOOLEAN."""
        return b"\x01\x01" + (b"\xff" if value else b"\x00")

    @staticmethod
    def _ber_sequence(data: bytes) -> bytes:
        """Wrap data in ASN.1 SEQUENCE."""
        return b"\x30" + ADIntegration._asn1_length(len(data)) + data

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
        return offset, 0

    def _next_msg_id(self) -> int:
        """Get next LDAP message ID."""
        self._msg_counter += 1
        return self._msg_counter

    # =========================================================================
    # LDAP FILTER ENCODING
    # =========================================================================

    def _encode_filter(self, filter_str: str) -> bytes:
        """Encode an LDAP filter string to BER.

        Supports: (attr=val), (attr=*), (&(...)(...)...), (|(...)(...)...),
        and extensible match (attr:oid:=val).
        """
        filter_str = filter_str.strip()
        if not filter_str.startswith("(") or not filter_str.endswith(")"):
            filter_str = f"({filter_str})"

        return self._parse_filter(filter_str)

    def _parse_filter(self, f: str) -> bytes:
        """Recursively parse LDAP filter string into BER."""
        f = f.strip()
        if f.startswith("(") and f.endswith(")"):
            f = f[1:-1]

        # AND filter: &(...)(...)
        if f.startswith("&"):
            components = self._split_filter_components(f[1:])
            encoded_parts = b"".join(self._parse_filter(c) for c in components)
            return b"\xa0" + self._asn1_length(len(encoded_parts)) + encoded_parts

        # OR filter: |(...)(...)
        if f.startswith("|"):
            components = self._split_filter_components(f[1:])
            encoded_parts = b"".join(self._parse_filter(c) for c in components)
            return b"\xa1" + self._asn1_length(len(encoded_parts)) + encoded_parts

        # NOT filter: !(...)
        if f.startswith("!"):
            inner = self._parse_filter(f[1:])
            return b"\xa2" + self._asn1_length(len(inner)) + inner

        # Extensible match: attr:oid:=value
        if ":=" in f:
            return self._encode_extensible_match(f)

        # Presence filter: attr=*
        if f.endswith("=*"):
            attr = f[:-2].encode("utf-8")
            return b"\x87" + self._asn1_length(len(attr)) + attr

        # Equality filter: attr=value
        if "=" in f:
            attr, value = f.split("=", 1)
            attr_bytes = self._ber_octet_string(attr.encode("utf-8"))
            value_bytes = self._ber_octet_string(value.encode("utf-8"))
            content = attr_bytes + value_bytes
            return b"\xa3" + self._asn1_length(len(content)) + content

        # Fallback: treat as present
        attr = f.encode("utf-8")
        return b"\x87" + self._asn1_length(len(attr)) + attr

    def _encode_extensible_match(self, f: str) -> bytes:
        """Encode extensible match filter (attr:oid:=value)."""
        # Format: attr:matchingRule:=value or attr:dn:matchingRule:=value
        parts_before, value = f.split(":=", 1)
        segments = parts_before.split(":")

        attr = segments[0] if segments[0] else None
        matching_rule = None
        for seg in segments[1:]:
            if seg and seg.lower() != "dn":
                matching_rule = seg

        content = b""
        # matchingRule [1]
        if matching_rule:
            mr_bytes = matching_rule.encode("utf-8")
            content += b"\x81" + self._asn1_length(len(mr_bytes)) + mr_bytes
        # type [2]
        if attr:
            attr_bytes = attr.encode("utf-8")
            content += b"\x82" + self._asn1_length(len(attr_bytes)) + attr_bytes
        # matchValue [3]
        val_bytes = value.encode("utf-8")
        content += b"\x83" + self._asn1_length(len(val_bytes)) + val_bytes

        # ExtensibleMatch = context [9] constructed
        return b"\xa9" + self._asn1_length(len(content)) + content

    def _split_filter_components(self, s: str) -> List[str]:
        """Split compound filter into individual filter components."""
        components = []
        depth = 0
        start = None
        for i, c in enumerate(s):
            if c == "(":
                if depth == 0:
                    start = i
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0 and start is not None:
                    components.append(s[start : i + 1])
                    start = None
        return components

    # =========================================================================
    # LDAP PROTOCOL OPERATIONS
    # =========================================================================

    def _build_search_request(
        self, base_dn: str, scope: int, filter_str: str, attributes: List[str], size_limit: int = 0
    ) -> bytes:
        """Build a complete LDAP SearchRequest message."""
        msg_id = self._ber_integer(self._next_msg_id())

        base = self._ber_octet_string(base_dn.encode("utf-8"))
        scope_enc = self._ber_enumerated(scope)
        deref = self._ber_enumerated(0)  # neverDerefAliases
        size = self._ber_integer(size_limit or self.size_limit)
        time_limit = self._ber_integer(60)
        types_only = self._ber_boolean(False)

        filter_enc = self._encode_filter(filter_str)

        # Attributes sequence
        attr_items = b""
        for attr in attributes:
            attr_items += self._ber_octet_string(attr.encode("utf-8"))
        attr_seq = b"\x30" + self._asn1_length(len(attr_items)) + attr_items

        search_body = base + scope_enc + deref + size + time_limit + types_only + filter_enc + attr_seq
        # Application [3] constructed = 0x63
        search_req = b"\x63" + self._asn1_length(len(search_body)) + search_body

        message = msg_id + search_req
        return b"\x30" + self._asn1_length(len(message)) + message

    def _build_bind_request(self, dn: str = "", password: str = "") -> bytes:
        """Build LDAP simple bind request."""
        msg_id = self._ber_integer(self._next_msg_id())
        version = self._ber_integer(3)
        name = self._ber_octet_string(dn.encode("utf-8"))
        # Simple authentication: context [0] primitive
        pwd_bytes = password.encode("utf-8")
        auth = b"\x80" + self._asn1_length(len(pwd_bytes)) + pwd_bytes

        bind_body = version + name + auth
        bind_req = b"\x60" + self._asn1_length(len(bind_body)) + bind_body

        message = msg_id + bind_req
        return b"\x30" + self._asn1_length(len(message)) + message

    def _recv_ldap_message(self, sock: socket.socket) -> Optional[bytes]:
        """Receive a complete LDAP message from socket."""
        try:
            initial = sock.recv(2)
            if len(initial) < 2:
                return None
            if initial[0] != 0x30:
                return None

            length_byte = initial[1]
            if length_byte < 0x80:
                total_length = length_byte
                header_bytes = initial
            elif length_byte == 0x81:
                len_data = sock.recv(1)
                if not len_data:
                    return None
                total_length = len_data[0]
                header_bytes = initial + len_data
            elif length_byte == 0x82:
                len_data = sock.recv(2)
                if len(len_data) < 2:
                    return None
                total_length = struct.unpack(">H", len_data)[0]
                header_bytes = initial + len_data
            elif length_byte == 0x83:
                len_data = sock.recv(3)
                if len(len_data) < 3:
                    return None
                total_length = struct.unpack(">I", b"\x00" + len_data)[0]
                header_bytes = initial + len_data
            else:
                return None

            body = b""
            while len(body) < total_length:
                chunk = sock.recv(min(4096, total_length - len(body)))
                if not chunk:
                    break
                body += chunk

            return header_bytes + body
        except socket.timeout:
            return None
        except Exception:
            return None

    def _parse_bind_response(self, data: bytes) -> int:
        """Parse LDAP BindResponse, return resultCode."""
        try:
            offset = 0
            if data[offset] != 0x30:
                return -1
            offset += 1
            offset, _ = self._parse_asn1_length(data, offset)

            # Skip MessageID
            if data[offset] != 0x02:
                return -1
            offset += 1
            offset, id_len = self._parse_asn1_length(data, offset)
            offset += id_len

            # BindResponse: application [1] = 0x61
            if data[offset] != 0x61:
                return -1
            offset += 1
            offset, _ = self._parse_asn1_length(data, offset)

            # resultCode (ENUMERATED)
            if data[offset] != 0x0A:
                return -1
            offset += 1
            offset, rc_len = self._parse_asn1_length(data, offset)
            return int.from_bytes(data[offset : offset + rc_len], "big")
        except (IndexError, struct.error):
            return -1

    def _parse_search_entries(self, sock: socket.socket) -> List[Dict]:
        """Read all SearchResultEntry messages until SearchResultDone."""
        entries = []
        max_messages = self.size_limit + 10

        for _ in range(max_messages):
            msg = self._recv_ldap_message(sock)
            if not msg:
                break

            parsed = self._parse_search_entry(msg)
            if parsed is None:
                # SearchResultDone or error
                break
            if parsed:
                entries.append(parsed)

        return entries

    def _parse_search_entry(self, data: bytes) -> Optional[Dict]:
        """Parse a single SearchResultEntry. Returns None on Done/error."""
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
            offset, id_len = self._parse_asn1_length(data, offset)
            offset += id_len

            tag = data[offset]
            if tag == 0x65:  # SearchResultDone
                return None
            if tag != 0x64:  # Not SearchResultEntry
                return None

            offset += 1
            offset, entry_len = self._parse_asn1_length(data, offset)

            # Object DN (OCTET STRING)
            if data[offset] != 0x04:
                return None
            offset += 1
            offset, dn_len = self._parse_asn1_length(data, offset)
            dn = data[offset : offset + dn_len].decode("utf-8", errors="ignore")
            offset += dn_len

            # Attributes (SEQUENCE)
            if offset >= len(data) or data[offset] != 0x30:
                return {"dn": dn, "attributes": {}}
            offset += 1
            offset, attrs_len = self._parse_asn1_length(data, offset)
            attrs_end = offset + attrs_len

            attributes = {}
            while offset < attrs_end and offset < len(data):
                if data[offset] != 0x30:
                    break
                offset += 1
                offset, attr_seq_len = self._parse_asn1_length(data, offset)
                attr_seq_end = offset + attr_seq_len

                # Attribute type
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
                        # Skip non-octet-string values
                        offset += 1
                        offset, skip_len = self._parse_asn1_length(data, offset)
                        offset += skip_len
                        continue
                    offset += 1
                    offset, val_len = self._parse_asn1_length(data, offset)
                    val = data[offset : offset + val_len]
                    # Try UTF-8 decode, fall back to hex for binary
                    try:
                        values.append(val.decode("utf-8"))
                    except UnicodeDecodeError:
                        values.append(val.hex())
                    offset += val_len

                if len(values) == 1:
                    attributes[attr_type] = values[0]
                elif len(values) > 1:
                    attributes[attr_type] = values

                offset = attr_seq_end

            return {"dn": dn, "attributes": attributes}

        except (IndexError, struct.error):
            return None

    def _ldap_search(
        self, sock: socket.socket, base_dn: str, filter_str: str, attributes: List[str], scope: int = LDAP_SCOPE_SUBTREE
    ) -> List[Dict]:
        """Execute LDAP search and return parsed entries."""
        request = self._build_search_request(base_dn, scope, filter_str, attributes)
        sock.send(request)
        return self._parse_search_entries(sock)

    # =========================================================================
    # CONNECTION & BIND
    # =========================================================================

    def _connect(self, dc_ip: str, port: int = 389) -> Optional[socket.socket]:
        """Connect to DC on LDAP/LDAPS port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((dc_ip, port))

            if port == 636:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                try:
                    sock = context.wrap_socket(sock, server_hostname=dc_ip)
                except (ssl.SSLError, OSError):
                    sock.close()
                    raise

            return sock
        except Exception as e:
            logger.debug(f"Failed to connect to {dc_ip}:{port}: {e}")
            return None

    def _bind_anonymous(self, sock: socket.socket) -> bool:
        """Perform anonymous LDAP bind."""
        bind_req = self._build_bind_request()
        sock.send(bind_req)
        response = self._recv_ldap_message(sock)
        if not response:
            return False
        return self._parse_bind_response(response) == 0

    def _detect_base_dn(self, sock: socket.socket) -> Optional[str]:
        """Query Root DSE to detect the default naming context."""
        msg_id = self._ber_integer(self._next_msg_id())
        base = self._ber_octet_string(b"")
        scope_enc = self._ber_enumerated(LDAP_SCOPE_BASE)
        deref = self._ber_enumerated(0)
        size = self._ber_integer(0)
        time_limit = self._ber_integer(30)
        types_only = self._ber_boolean(False)
        # Present filter on objectClass
        filter_enc = b"\x87" + self._asn1_length(11) + b"objectClass"

        attrs_list = [b"defaultNamingContext", b"namingContexts"]
        attr_items = b""
        for a in attrs_list:
            attr_items += self._ber_octet_string(a)
        attr_seq = b"\x30" + self._asn1_length(len(attr_items)) + attr_items

        search_body = base + scope_enc + deref + size + time_limit + types_only + filter_enc + attr_seq
        search_req = b"\x63" + self._asn1_length(len(search_body)) + search_body
        message = msg_id + search_req
        ldap_msg = b"\x30" + self._asn1_length(len(message)) + message

        sock.send(ldap_msg)

        # Read entries
        for _ in range(5):
            resp = self._recv_ldap_message(sock)
            if not resp:
                break
            entry = self._parse_search_entry(resp)
            if entry is None:
                break
            if entry:
                attrs = entry.get("attributes", {})
                if "defaultNamingContext" in attrs:
                    return attrs["defaultNamingContext"]
                if "namingContexts" in attrs:
                    ncs = attrs["namingContexts"]
                    if isinstance(ncs, list):
                        for nc in ncs:
                            if "DC=" in nc.upper():
                                return nc
                    elif "DC=" in ncs.upper():
                        return ncs
        return None

    # =========================================================================
    # MAIN ENUMERATION ENTRY POINT
    # =========================================================================

    def enumerate_domain(self, dc_ip: str, base_dn: str = None, port: int = 389) -> Dict:
        """Full AD enumeration from a domain controller IP.

        Args:
            dc_ip: IP address of the domain controller.
            base_dn: LDAP base DN (auto-detected if None).
            port: LDAP port (389 or 636 for LDAPS).

        Returns:
            Dictionary with all enumerated AD objects and summary.
        """
        results = {
            "dc_ip": dc_ip,
            "base_dn": None,
            "domain": None,
            "bind_success": False,
            "users": [],
            "groups": [],
            "computers": [],
            "privileged_accounts": [],
            "kerberoastable": [],
            "asrep_roastable": [],
            "trusts": [],
            "password_policy": {},
            "errors": [],
        }

        logger.info(f"Starting AD enumeration against {dc_ip}:{port}")

        sock = self._connect(dc_ip, port)
        if not sock:
            results["errors"].append(f"Failed to connect to {dc_ip}:{port}")
            return results

        try:
            # Anonymous bind
            if not self._bind_anonymous(sock):
                results["errors"].append("Anonymous bind failed")
                sock.close()
                return results

            results["bind_success"] = True
            logger.info(f"Anonymous bind successful on {dc_ip}")

            # Detect base DN
            if not base_dn:
                base_dn = self._detect_base_dn(sock)
                if not base_dn:
                    results["errors"].append("Could not detect base DN")
                    sock.close()
                    return results

            results["base_dn"] = base_dn
            # Extract domain name from base DN (DC=corp,DC=local -> corp.local)
            domain_parts = []
            for part in base_dn.split(","):
                part = part.strip()
                if part.upper().startswith("DC="):
                    domain_parts.append(part[3:])
            results["domain"] = ".".join(domain_parts) if domain_parts else base_dn

            logger.info(f"Base DN: {base_dn}, Domain: {results['domain']}")

            # Reconnect for each query to reset message state cleanly
            sock.close()

            # Enumerate users
            results["users"] = self._get_domain_users(dc_ip, port, base_dn)
            logger.info(f"Found {len(results['users'])} domain users")

            # Enumerate groups
            results["groups"] = self._get_domain_groups(dc_ip, port, base_dn)
            logger.info(f"Found {len(results['groups'])} domain groups")

            # Enumerate computers
            results["computers"] = self._get_domain_computers(dc_ip, port, base_dn)
            logger.info(f"Found {len(results['computers'])} domain computers")

            # Privileged accounts
            results["privileged_accounts"] = self._get_privileged_accounts(dc_ip, port, base_dn)
            logger.info(f"Found {len(results['privileged_accounts'])} privileged accounts")

            # Kerberoastable
            results["kerberoastable"] = self._get_kerberoastable(dc_ip, port, base_dn)
            logger.info(f"Found {len(results['kerberoastable'])} Kerberoastable accounts")

            # AS-REP roastable
            results["asrep_roastable"] = self._get_asrep_roastable(dc_ip, port, base_dn)
            logger.info(f"Found {len(results['asrep_roastable'])} AS-REP roastable accounts")

            # Domain trusts
            results["trusts"] = self._get_domain_trusts(dc_ip, port, base_dn)
            logger.info(f"Found {len(results['trusts'])} domain trusts")

            # Password policy
            results["password_policy"] = self._get_password_policy(dc_ip, port, base_dn)
            logger.info(f"Password policy retrieved: {bool(results['password_policy'])}")

            # Store everything
            self._store_results(results["domain"], results)

        except Exception as e:
            logger.error(f"AD enumeration error: {e}")
            results["errors"].append(str(e))
        finally:
            try:
                sock.close()
            except Exception:
                pass

        return results

    def _query_with_connection(
        self, dc_ip: str, port: int, base_dn: str, filter_str: str, attributes: List[str]
    ) -> List[Dict]:
        """Open connection, bind, search, close. Isolates each query."""
        sock = self._connect(dc_ip, port)
        if not sock:
            return []
        try:
            if not self._bind_anonymous(sock):
                return []
            entries = self._ldap_search(sock, base_dn, filter_str, attributes)
            return entries
        except Exception as e:
            logger.debug(f"Query failed ({filter_str[:50]}): {e}")
            return []
        finally:
            try:
                sock.close()
            except Exception:
                pass

    # =========================================================================
    # AD-SPECIFIC QUERIES
    # =========================================================================

    def _get_domain_users(self, dc_ip: str, port: int, base_dn: str) -> List[Dict]:
        """Pull domain users with key attributes."""
        filter_str = "(&(objectClass=user)(objectCategory=person))"
        attributes = [
            "sAMAccountName",
            "distinguishedName",
            "memberOf",
            "lastLogon",
            "lastLogonTimestamp",
            "whenCreated",
            "userAccountControl",
            "description",
            "mail",
            "pwdLastSet",
            "adminCount",
        ]

        entries = self._query_with_connection(dc_ip, port, base_dn, filter_str, attributes)

        users = []
        for entry in entries:
            attrs = entry.get("attributes", {})
            user = {
                "dn": entry.get("dn", ""),
                "sAMAccountName": attrs.get("sAMAccountName", ""),
                "memberOf": attrs.get("memberOf", []),
                "lastLogon": self._filetime_to_iso(attrs.get("lastLogon")),
                "lastLogonTimestamp": self._filetime_to_iso(attrs.get("lastLogonTimestamp")),
                "whenCreated": attrs.get("whenCreated", ""),
                "userAccountControl": attrs.get("userAccountControl", ""),
                "description": attrs.get("description", ""),
                "mail": attrs.get("mail", ""),
                "pwdLastSet": self._filetime_to_iso(attrs.get("pwdLastSet")),
                "adminCount": attrs.get("adminCount", "0"),
                "disabled": self._is_disabled(attrs.get("userAccountControl", "0")),
            }
            if isinstance(user["memberOf"], str):
                user["memberOf"] = [user["memberOf"]]
            users.append(user)

        return users

    def _get_domain_groups(self, dc_ip: str, port: int, base_dn: str) -> List[Dict]:
        """Pull domain groups with members."""
        filter_str = "(objectClass=group)"
        attributes = [
            "sAMAccountName",
            "distinguishedName",
            "member",
            "description",
            "adminCount",
            "groupType",
        ]

        entries = self._query_with_connection(dc_ip, port, base_dn, filter_str, attributes)

        groups = []
        for entry in entries:
            attrs = entry.get("attributes", {})
            group = {
                "dn": entry.get("dn", ""),
                "sAMAccountName": attrs.get("sAMAccountName", ""),
                "description": attrs.get("description", ""),
                "members": attrs.get("member", []),
                "adminCount": attrs.get("adminCount", "0"),
                "groupType": attrs.get("groupType", ""),
            }
            if isinstance(group["members"], str):
                group["members"] = [group["members"]]
            groups.append(group)

        return groups

    def _get_domain_computers(self, dc_ip: str, port: int, base_dn: str) -> List[Dict]:
        """Pull domain computers with OS info."""
        filter_str = "(objectClass=computer)"
        attributes = [
            "sAMAccountName",
            "distinguishedName",
            "dNSHostName",
            "operatingSystem",
            "operatingSystemVersion",
            "operatingSystemServicePack",
            "lastLogon",
            "lastLogonTimestamp",
            "userAccountControl",
        ]

        entries = self._query_with_connection(dc_ip, port, base_dn, filter_str, attributes)

        computers = []
        for entry in entries:
            attrs = entry.get("attributes", {})
            computer = {
                "dn": entry.get("dn", ""),
                "sAMAccountName": attrs.get("sAMAccountName", ""),
                "dNSHostName": attrs.get("dNSHostName", ""),
                "operatingSystem": attrs.get("operatingSystem", ""),
                "operatingSystemVersion": attrs.get("operatingSystemVersion", ""),
                "operatingSystemServicePack": attrs.get("operatingSystemServicePack", ""),
                "lastLogon": self._filetime_to_iso(attrs.get("lastLogon")),
                "lastLogonTimestamp": self._filetime_to_iso(attrs.get("lastLogonTimestamp")),
                "disabled": self._is_disabled(attrs.get("userAccountControl", "0")),
            }
            computers.append(computer)

        return computers

    def _get_privileged_accounts(self, dc_ip: str, port: int, base_dn: str) -> List[Dict]:
        """Find accounts in privileged groups (Domain Admins, Enterprise Admins, etc.)."""
        privileged = []

        for group_name in PRIVILEGED_GROUPS:
            filter_str = f"(&(objectClass=group)(sAMAccountName={group_name}))"
            attributes = ["member", "distinguishedName", "sAMAccountName"]

            entries = self._query_with_connection(dc_ip, port, base_dn, filter_str, attributes)

            for entry in entries:
                attrs = entry.get("attributes", {})
                members = attrs.get("member", [])
                if isinstance(members, str):
                    members = [members]

                for member_dn in members:
                    privileged.append(
                        {
                            "group": group_name,
                            "member_dn": member_dn,
                            "member_name": self._extract_cn(member_dn),
                        }
                    )

        # Deduplicate by member_dn
        seen = set()
        unique = []
        for p in privileged:
            key = (p["group"], p["member_dn"])
            if key not in seen:
                seen.add(key)
                unique.append(p)

        return unique

    def _get_kerberoastable(self, dc_ip: str, port: int, base_dn: str) -> List[Dict]:
        """Find accounts with servicePrincipalName set (Kerberoastable)."""
        filter_str = "(&(objectClass=user)(servicePrincipalName=*)(!(objectClass=computer)))"
        attributes = [
            "sAMAccountName",
            "distinguishedName",
            "servicePrincipalName",
            "memberOf",
            "adminCount",
            "userAccountControl",
        ]

        entries = self._query_with_connection(dc_ip, port, base_dn, filter_str, attributes)

        accounts = []
        for entry in entries:
            attrs = entry.get("attributes", {})
            spns = attrs.get("servicePrincipalName", [])
            if isinstance(spns, str):
                spns = [spns]

            account = {
                "dn": entry.get("dn", ""),
                "sAMAccountName": attrs.get("sAMAccountName", ""),
                "servicePrincipalNames": spns,
                "memberOf": attrs.get("memberOf", []),
                "adminCount": attrs.get("adminCount", "0"),
                "disabled": self._is_disabled(attrs.get("userAccountControl", "0")),
            }
            if isinstance(account["memberOf"], str):
                account["memberOf"] = [account["memberOf"]]
            accounts.append(account)

        return accounts

    def _get_asrep_roastable(self, dc_ip: str, port: int, base_dn: str) -> List[Dict]:
        """Find accounts with DONT_REQUIRE_PREAUTH set (AS-REP roastable).

        UAC flag 0x400000 = 4194304 = DONT_REQUIRE_PREAUTH
        Uses LDAP extensible match: userAccountControl:1.2.840.113556.1.4.803:=4194304
        """
        filter_str = "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
        attributes = [
            "sAMAccountName",
            "distinguishedName",
            "memberOf",
            "userAccountControl",
            "adminCount",
        ]

        entries = self._query_with_connection(dc_ip, port, base_dn, filter_str, attributes)

        accounts = []
        for entry in entries:
            attrs = entry.get("attributes", {})
            account = {
                "dn": entry.get("dn", ""),
                "sAMAccountName": attrs.get("sAMAccountName", ""),
                "memberOf": attrs.get("memberOf", []),
                "adminCount": attrs.get("adminCount", "0"),
                "userAccountControl": attrs.get("userAccountControl", ""),
            }
            if isinstance(account["memberOf"], str):
                account["memberOf"] = [account["memberOf"]]
            accounts.append(account)

        return accounts

    def _get_domain_trusts(self, dc_ip: str, port: int, base_dn: str) -> List[Dict]:
        """Extract domain trust relationships."""
        filter_str = "(objectClass=trustedDomain)"
        attributes = [
            "cn",
            "distinguishedName",
            "trustPartner",
            "trustDirection",
            "trustType",
            "trustAttributes",
            "flatName",
            "securityIdentifier",
        ]

        entries = self._query_with_connection(dc_ip, port, base_dn, filter_str, attributes)

        trust_direction_map = {"1": "Inbound", "2": "Outbound", "3": "Bidirectional"}
        trust_type_map = {"1": "Windows NT", "2": "Active Directory", "3": "MIT Kerberos"}

        trusts = []
        for entry in entries:
            attrs = entry.get("attributes", {})
            direction = attrs.get("trustDirection", "0")
            ttype = attrs.get("trustType", "0")

            trust = {
                "dn": entry.get("dn", ""),
                "name": attrs.get("cn", ""),
                "trustPartner": attrs.get("trustPartner", ""),
                "flatName": attrs.get("flatName", ""),
                "trustDirection": trust_direction_map.get(str(direction), str(direction)),
                "trustType": trust_type_map.get(str(ttype), str(ttype)),
                "trustAttributes": attrs.get("trustAttributes", ""),
            }
            trusts.append(trust)

        return trusts

    def _get_password_policy(self, dc_ip: str, port: int, base_dn: str) -> Dict:
        """Get domain password policy from the base domain object."""
        filter_str = "(objectClass=domain)"
        attributes = [
            "minPwdLength",
            "maxPwdAge",
            "minPwdAge",
            "pwdHistoryLength",
            "lockoutThreshold",
            "lockoutDuration",
            "lockOutObservationWindow",
            "pwdProperties",
        ]

        entries = self._query_with_connection(
            dc_ip,
            port,
            base_dn,
            filter_str,
            attributes,
        )

        if not entries:
            return {}

        attrs = entries[0].get("attributes", {})

        policy = {
            "minPwdLength": self._safe_int(attrs.get("minPwdLength", "0")),
            "maxPwdAge": self._filetime_duration(attrs.get("maxPwdAge", "0")),
            "minPwdAge": self._filetime_duration(attrs.get("minPwdAge", "0")),
            "pwdHistoryLength": self._safe_int(attrs.get("pwdHistoryLength", "0")),
            "lockoutThreshold": self._safe_int(attrs.get("lockoutThreshold", "0")),
            "lockoutDuration": self._filetime_duration(attrs.get("lockoutDuration", "0")),
            "lockOutObservationWindow": self._filetime_duration(attrs.get("lockOutObservationWindow", "0")),
            "pwdProperties": self._safe_int(attrs.get("pwdProperties", "0")),
            "complexity_required": bool(self._safe_int(attrs.get("pwdProperties", "0")) & 1),
        }

        return policy

    # =========================================================================
    # HELPER METHODS
    # =========================================================================

    @staticmethod
    def _filetime_to_iso(filetime_str: Optional[str]) -> Optional[str]:
        """Convert Windows FILETIME (100ns since 1601) to ISO string."""
        if not filetime_str:
            return None
        try:
            ft = int(filetime_str)
            if ft <= 0 or ft == 9223372036854775807:  # Never logged on
                return None
            # Convert FILETIME to Unix timestamp
            unix_ts = (ft - 116444736000000000) / 10000000
            return datetime.fromtimestamp(unix_ts, tz=timezone.utc).isoformat()
        except (ValueError, OSError, OverflowError):
            return None

    @staticmethod
    def _filetime_duration(filetime_str: Optional[str]) -> Optional[str]:
        """Convert FILETIME duration (negative 100ns intervals) to human-readable."""
        if not filetime_str:
            return None
        try:
            ft = abs(int(filetime_str))
            if ft == 0 or ft == 9223372036854775807:
                return "Never expires"
            # Convert 100ns intervals to minutes
            minutes = ft / (10000000 * 60)
            if minutes < 60:
                return f"{int(minutes)} minutes"
            hours = minutes / 60
            if hours < 24:
                return f"{int(hours)} hours"
            days = hours / 24
            return f"{int(days)} days"
        except (ValueError, OverflowError):
            return None

    @staticmethod
    def _is_disabled(uac_str: str) -> bool:
        """Check if account is disabled from UAC value."""
        try:
            uac = int(uac_str)
            return bool(uac & UAC_ACCOUNTDISABLE)
        except (ValueError, TypeError):
            return False

    @staticmethod
    def _extract_cn(dn: str) -> str:
        """Extract CN from a distinguished name."""
        for part in dn.split(","):
            part = part.strip()
            if part.upper().startswith("CN="):
                return part[3:]
        return dn

    @staticmethod
    def _safe_int(val) -> int:
        """Safely convert value to int."""
        try:
            return int(val)
        except (ValueError, TypeError):
            return 0

    # =========================================================================
    # DATA STORAGE
    # =========================================================================

    def _store_results(self, domain: str, results: Dict):
        """Store all enumerated AD objects into the database."""
        conn = sqlite3.connect(self.db_path)
        now = datetime.now(timezone.utc).isoformat()

        try:
            # Clear previous results for this domain
            conn.execute("DELETE FROM ad_objects WHERE domain = ?", (domain,))

            records = []

            # Users
            for user in results.get("users", []):
                records.append(
                    (domain, "user", user.get("sAMAccountName", ""), user.get("dn", ""), json.dumps(user), now)
                )

            # Groups
            for group in results.get("groups", []):
                records.append(
                    (domain, "group", group.get("sAMAccountName", ""), group.get("dn", ""), json.dumps(group), now)
                )

            # Computers
            for computer in results.get("computers", []):
                records.append(
                    (
                        domain,
                        "computer",
                        computer.get("sAMAccountName", ""),
                        computer.get("dn", ""),
                        json.dumps(computer),
                        now,
                    )
                )

            # Privileged accounts
            for priv in results.get("privileged_accounts", []):
                records.append(
                    (
                        domain,
                        "privileged",
                        priv.get("member_name", ""),
                        priv.get("member_dn", ""),
                        json.dumps(priv),
                        now,
                    )
                )

            # Kerberoastable
            for kerb in results.get("kerberoastable", []):
                records.append(
                    (
                        domain,
                        "kerberoastable",
                        kerb.get("sAMAccountName", ""),
                        kerb.get("dn", ""),
                        json.dumps(kerb),
                        now,
                    )
                )

            # AS-REP roastable
            for asrep in results.get("asrep_roastable", []):
                records.append(
                    (
                        domain,
                        "asrep_roastable",
                        asrep.get("sAMAccountName", ""),
                        asrep.get("dn", ""),
                        json.dumps(asrep),
                        now,
                    )
                )

            # Trusts
            for trust in results.get("trusts", []):
                records.append((domain, "trust", trust.get("name", ""), trust.get("dn", ""), json.dumps(trust), now))

            # Password policy
            if results.get("password_policy"):
                records.append(
                    (
                        domain,
                        "password_policy",
                        "domain_policy",
                        results.get("base_dn", ""),
                        json.dumps(results["password_policy"]),
                        now,
                    )
                )

            conn.executemany(
                "INSERT INTO ad_objects (domain, object_type, name, dn, attributes_json, discovered_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                records,
            )
            conn.commit()
            logger.info(f"Stored {len(records)} AD objects for domain {domain}")

        except Exception as e:
            logger.error(f"Failed to store AD results: {e}")
            conn.rollback()
        finally:
            conn.close()

    def get_ad_summary(self) -> Dict:
        """Get summary of all discovered AD data."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row

        summary = {"domains": []}

        try:
            # Get distinct domains
            domains = conn.execute("SELECT DISTINCT domain FROM ad_objects").fetchall()

            for row in domains:
                domain = row["domain"]
                counts = {}
                for obj_type in [
                    "user",
                    "group",
                    "computer",
                    "privileged",
                    "kerberoastable",
                    "asrep_roastable",
                    "trust",
                ]:
                    cursor = conn.execute(
                        "SELECT COUNT(*) as cnt FROM ad_objects WHERE domain = ? AND object_type = ?",
                        (domain, obj_type),
                    )
                    counts[obj_type] = cursor.fetchone()["cnt"]

                # Get password policy
                policy_row = conn.execute(
                    "SELECT attributes_json FROM ad_objects WHERE domain = ? AND object_type = ?",
                    (domain, "password_policy"),
                ).fetchone()
                policy = json.loads(policy_row["attributes_json"]) if policy_row else {}

                summary["domains"].append(
                    {
                        "domain": domain,
                        "users": counts.get("user", 0),
                        "groups": counts.get("group", 0),
                        "computers": counts.get("computer", 0),
                        "privileged_accounts": counts.get("privileged", 0),
                        "kerberoastable": counts.get("kerberoastable", 0),
                        "asrep_roastable": counts.get("asrep_roastable", 0),
                        "trusts": counts.get("trust", 0),
                        "password_policy": policy,
                    }
                )

        except Exception as e:
            logger.error(f"Failed to get AD summary: {e}")
        finally:
            conn.close()

        return summary
