"""
HostVigil Active Directory Discovery Module

Query Active Directory to map the ENTIRE network WITHOUT sending a single scan packet.
This is the ultimate stealth technique - LDAP queries look like normal domain traffic.

Features:
- Extract all computer objects from AD
- Get OS versions, last logon times, OU structure
- Find domain trusts (pivoting opportunities)
- Identify privileged accounts and groups
- DNS resolution for IP mapping
- BloodHound compatibility
"""

try:
    import ldap3

    LDAP3_AVAILABLE = True
except ImportError:
    LDAP3_AVAILABLE = False

try:
    import dns.resolver
except ImportError:
    pass  # DNS availability handled by dns_recon module

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional

logger = logging.getLogger("hostvigil.ad_discovery")


class ADDiscoverer:
    """
    Active Directory Discovery - Map network via LDAP queries.

    Why this works:
    1. AD has inventory of ALL domain-joined machines
    2. LDAP queries (389/636) are normal admin traffic - NEVER blocked
    3. No scanning required = ZERO detection risk
    4. Rich metadata (OS, last login, owner, groups)
    5. Works through firewalls (domain traffic allowed)
    """

    def __init__(self, domain_controller: str = None, username: str = None, password: str = None):
        self.dc = domain_controller
        self.username = username
        self.password = password
        self.server = None
        self.connection = None
        self.domain = None

    def connect_anonymous(self, domain_controller: str) -> bool:
        """Try anonymous bind (works on misconfigured AD)."""
        if not LDAP3_AVAILABLE:
            logger.warning("ldap3 not installed - AD discovery disabled. Install with: pip install ldap3")
            return False
        try:
            server = ldap3.Server(domain_controller, get_info=ldap3.ALL)
            conn = ldap3.Connection(server, authentication=ldap3.ANONYMOUS)
            if conn.bind():
                self.connection = conn
                self.dc = domain_controller
                logger.info(f"✓ Anonymous bind to {domain_controller}")
                return True
        except Exception as e:
            logger.debug(f"Anonymous bind failed: {e}")
        return False

    def connect_with_creds(self, domain_controller: str, username: str, password: str, domain: str = None) -> bool:
        """Authenticate with credentials."""
        if not LDAP3_AVAILABLE:
            logger.warning("ldap3 not installed - AD discovery disabled. Install with: pip install ldap3")
            return False
        try:
            if domain:
                user_dn = f"{username}@{domain}"
            else:
                user_dn = username

            server = ldap3.Server(domain_controller, get_info=ldap3.ALL)
            conn = ldap3.Connection(server, user=user_dn, password=password, authentication=ldap3.NTLM)

            if conn.bind():
                self.connection = conn
                self.dc = domain_controller
                self.username = username
                self.domain = domain
                logger.info(f"✓ Authenticated to {domain_controller} as {username}")
                return True
            else:
                logger.warning(f"Bind failed: {conn.result}")
        except Exception as e:
            logger.error(f"Connection error: {e}")
        return False

    def get_all_computers(self) -> List[Dict]:
        """Extract ALL computer objects from Active Directory."""
        if not self.connection:
            logger.error("Not connected to AD")
            return []

        computers = []

        # LDAP query for all computer objects
        query = "(objectClass=computer)"
        attributes = [
            "name",
            "dNSHostName",
            "operatingSystem",
            "operatingSystemVersion",
            "operatingSystemServicePack",
            "lastLogon",
            "whenCreated",
            "distinguishedName",
            "memberOf",
            "servicePrincipalName",
            "msDS-AllowedToActOnBehalfOfOtherIdentity",  # RBCD
            "msDS-AllowedToDelegateTo",  # Constrained delegation
            "description",
            "managedBy",
        ]

        try:
            self.connection.search(
                search_base=self._get_domain_dn(), search_filter=query, attributes=attributes, paged_size=1000
            )

            for entry in self.connection.entries:
                try:
                    computer = {
                        "hostname": str(entry.get("dNSHostName", "")),
                        "name": str(entry.get("name", "")),
                        "os": str(entry.get("operatingSystem", "")),
                        "os_version": str(entry.get("operatingSystemVersion", "")),
                        "os_sp": str(entry.get("operatingSystemServicePack", "")),
                        "last_logon": self._parse_timestamp(entry.get("lastLogon")),
                        "created": self._parse_timestamp(entry.get("whenCreated")),
                        "dn": str(entry.get("distinguishedName", "")),
                        "description": str(entry.get("description", "")),
                        "managed_by": str(entry.get("managedBy", "")),
                        "groups": self._parse_groups(entry.get("memberOf")),
                        "spns": self._parse_spns(entry.get("servicePrincipalName")),
                        "rbcd_enabled": bool(entry.get("msDS-AllowedToActOnBehalfOfOtherIdentity")),
                        "delegation": str(entry.get("msDS-AllowedToDelegateTo", "")),
                    }
                    computers.append(computer)
                except Exception as e:
                    logger.debug(f"Error parsing entry: {e}")
                    continue

            logger.info(f"✓ Found {len(computers)} computers in AD")

        except Exception as e:
            logger.error(f"Search failed: {e}")

        return computers

    def get_all_servers(self) -> List[Dict]:
        """Find all server objects (high-value targets)."""
        computers = self.get_all_computers()
        servers = [
            c
            for c in computers
            if "server" in c.get("os", "").lower()
            or "windows" in c.get("os", "").lower()
            and "professional" not in c.get("os", "").lower()
        ]
        logger.info(f"✓ Found {len(servers)} servers")
        return servers

    def get_domain_controllers(self) -> List[Dict]:
        """Find all domain controllers."""
        if not self.connection:
            return []

        dcs = []
        query = "(userAccountControl:1.2.840.113556.1.4.803:=8192)"  # DOMAIN_CONTROLLER flag

        try:
            self.connection.search(
                search_base=self._get_domain_dn(),
                search_filter=query,
                attributes=["name", "dNSHostName", "operatingSystem", "lastLogon"],
            )

            for entry in self.connection.entries:
                dcs.append(
                    {
                        "hostname": str(entry.get("dNSHostName", "")),
                        "name": str(entry.get("name", "")),
                        "os": str(entry.get("operatingSystem", "")),
                        "last_logon": self._parse_timestamp(entry.get("lastLogon")),
                    }
                )

            logger.info(f"✓ Found {len(dcs)} domain controllers")
        except Exception as e:
            logger.error(f"DC search failed: {e}")

        return dcs

    def get_domain_trusts(self) -> List[Dict]:
        """Find trusted domains (pivoting opportunities)."""
        if not self.connection:
            return []

        trusts = []
        query = "(objectClass=trustedDomain)"

        try:
            self.connection.search(
                search_base=self._get_domain_dn(),
                search_filter=query,
                attributes=["name", "trustPartner", "trustType", "trustDirection", "flatName"],
            )

            for entry in self.connection.entries:
                trusts.append(
                    {
                        "name": str(entry.get("name", "")),
                        "partner": str(entry.get("trustPartner", "")),
                        "type": str(entry.get("trustType", "")),
                        "direction": str(entry.get("trustDirection", "")),
                        "flat_name": str(entry.get("flatName", "")),
                    }
                )

            logger.info(f"✓ Found {len(trusts)} domain trusts")
        except Exception as e:
            logger.error(f"Trust search failed: {e}")

        return trusts

    def get_high_value_accounts(self) -> List[Dict]:
        """Find privileged accounts (Domain Admins, Enterprise Admins, etc.)."""
        if not self.connection:
            return []

        high_value = []
        privileged_groups = [
            "CN=Domain Admins",
            "CN=Enterprise Admins",
            "CN=Administrators",
            "CN=Schema Admins",
            "CN=Account Operators",
            "CN=Backup Operators",
            "CN=Server Operators",
            "CN=Print Operators",
        ]

        for group_cn in privileged_groups:
            query = f"(memberOf={group_cn})"

            try:
                self.connection.search(
                    search_base=self._get_domain_dn(),
                    search_filter=query,
                    attributes=["name", "sAMAccountName", "userAccountControl", "lastLogon", "passwordLastSet"],
                )

                for entry in self.connection.entries:
                    high_value.append(
                        {
                            "name": str(entry.get("name", "")),
                            "samaccountname": str(entry.get("sAMAccountName", "")),
                            "group": group_cn,
                            "enabled": self._is_account_enabled(entry.get("userAccountControl")),
                            "last_logon": self._parse_timestamp(entry.get("lastLogon")),
                            "pwd_last_set": self._parse_timestamp(entry.get("passwordLastSet")),
                        }
                    )
            except Exception as e:
                logger.debug(f"Group search failed for {group_cn}: {e}")

        logger.info(f"✓ Found {len(high_value)} high-value accounts")
        return high_value

    def resolve_hostnames_dns(self, computers: List[Dict]) -> List[Dict]:
        """Resolve hostnames to IPs via DNS (looks like normal DNS traffic)."""
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2

        for computer in computers:
            hostname = computer.get("hostname", "").rstrip(".")
            if hostname:
                try:
                    answers = resolver.resolve(hostname, "A")
                    ips = [str(rdata) for rdata in answers]
                    computer["ips"] = ips
                    computer["dns_resolved"] = True
                except Exception:
                    computer["ips"] = []
                    computer["dns_resolved"] = False

        resolved = [c for c in computers if c.get("dns_resolved")]
        logger.info(f"✓ Resolved {len(resolved)}/{len(computers)} hostnames to IPs")
        return computers

    def get_ou_structure(self) -> Dict:
        """Map Organizational Unit structure."""
        if not self.connection:
            return {}

        ous = {}
        query = "(objectClass=organizationalUnit)"

        try:
            self.connection.search(
                search_base=self._get_domain_dn(),
                search_filter=query,
                attributes=["name", "distinguishedName", "description", "memberOf"],
            )

            for entry in self.connection.entries:
                dn = str(entry.get("distinguishedName", ""))
                ous[dn] = {
                    "name": str(entry.get("name", "")),
                    "description": str(entry.get("description", "")),
                    "parent": self._get_parent_ou(dn),
                }

            logger.info(f"✓ Mapped {len(ous)} OUs")
        except Exception as e:
            logger.error(f"OU search failed: {e}")

        return ous

    def export_bloodhound(self, computers: List[Dict], output_file: str = "bloodhound.json"):
        """Export to BloodHound format for graph analysis."""
        import json

        nodes = []
        edges = []

        for comp in computers:
            nodes.append(
                {
                    "Properties": {
                        "name": comp.get("hostname", ""),
                        "operatingsystem": comp.get("os", ""),
                        "lastlogon": comp.get("last_logon", 0),
                        "distinguishedname": comp.get("dn", ""),
                    },
                    "ObjectIdentifier": comp.get("dn", ""),
                    "ObjectType": "Computer",
                }
            )

            # Add edges for group memberships
            for group in comp.get("groups", []):
                edges.append(
                    {
                        "SourceObjectIdentifier": comp.get("dn", ""),
                        "TargetObjectIdentifier": group,
                        "RelationshipType": "MemberOf",
                    }
                )

        output = {"computers": nodes, "edges": edges}

        with open(output_file, "w") as f:
            json.dump(output, f, indent=2)

        logger.info(f"✓ Exported BloodHound format to {output_file}")

    def _get_domain_dn(self) -> str:
        """Get domain DN from connection."""
        if self.domain:
            parts = self.domain.split(".")
            return ",".join([f"DC={p}" for p in parts])
        return ""

    def _get_parent_ou(self, dn: str) -> str:
        """Get parent OU from DN."""
        parts = dn.split(",")
        if len(parts) > 1:
            return ",".join(parts[1:])
        return ""

    def _parse_timestamp(self, value) -> Optional[int]:
        """Parse AD timestamp to Unix epoch."""
        if value is None:
            return None
        try:
            if hasattr(value, "value"):
                ts = value.value
            else:
                ts = int(str(value))

            # AD timestamp is 100-nanosecond intervals since 1601-01-01
            if ts > 0:
                epoch = datetime(1601, 1, 1)
                delta = timedelta(microseconds=ts // 10)
                return int((epoch + delta - datetime(1970, 1, 1)).total_seconds())
        except Exception:
            pass
        return None

    def _parse_groups(self, value) -> List[str]:
        """Parse multi-valued group DN."""
        if value is None:
            return []
        try:
            if hasattr(value, "__iter__") and not isinstance(value, str):
                return [str(g) for g in value]
            return [str(value)]
        except Exception:
            return []

    def _parse_spns(self, value) -> List[str]:
        """Parse service principal names."""
        if value is None:
            return []
        try:
            if hasattr(value, "__iter__") and not isinstance(value, str):
                return [str(s) for s in value]
            return [str(value)]
        except Exception:
            return []

    def _is_account_enabled(self, uac_value) -> bool:
        """Check if account is enabled based on userAccountControl."""
        if uac_value is None:
            return True
        try:
            if hasattr(uac_value, "value"):
                uac = uac_value.value
            else:
                uac = int(uac_value)

            # ACCOUNTDISABLE flag = 0x0002
            return not (uac & 0x0002)
        except Exception:
            return True

    def close(self):
        """Close LDAP connection."""
        if self.connection:
            self.connection.unbind()
            logger.debug("LDAP connection closed")


# Quick test function
def quick_ad_recon(domain_controller: str) -> Dict:
    """
    Quick AD reconnaissance - anonymous bind attempt.
    Returns domain info without credentials.
    """
    result = {"dc": domain_controller, "anonymous_bind": False, "computers": [], "dc_list": [], "trusts": []}

    discoverer = ADDiscoverer()

    # Try anonymous bind
    if discoverer.connect_anonymous(domain_controller):
        result["anonymous_bind"] = True
        result["computers"] = discoverer.get_all_computers()[:100]  # Sample
        result["dc_list"] = discoverer.get_domain_controllers()
        result["trusts"] = discoverer.get_domain_trusts()

    discoverer.close()
    return result


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 -m hostvigil.discovery.ad_discovery <domain_controller>")
        print("Example: python3 -m hostvigil.discovery.ad_discovery dc01.corp.local")
        sys.exit(1)

    dc = sys.argv[1]
    result = quick_ad_recon(dc)

    import json

    print(json.dumps(result, indent=2, default=str))
