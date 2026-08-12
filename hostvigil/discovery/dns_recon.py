"""
HostVigil DNS-Only Reconnaissance

Map ENTIRE networks using ONLY DNS queries - bypasses ALL firewalls.
DNS is allowed everywhere, never blocked, looks like normal traffic.

Techniques:
- Reverse DNS walk (PTR records for every IP)
- Forward DNS brute force (common hostnames)
- Zone transfer attempt (AXFR - jackpot if enabled)
- DNS cache snooping (see what others queried)
- Dynamic DNS enumeration (DHCP- registered hosts)
- Subdomain enumeration for internal domains

Results: Complete network map without sending a single ICMP/ARP/TCP probe.
"""

try:
    import dns.query
    import dns.resolver
    import dns.reversename
    import dns.zone

    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

import ipaddress
import logging
from collections import defaultdict
from typing import Dict, List, Optional

logger = logging.getLogger("hostvigil.dns_recon")


class DNSRecon:
    """DNS-based network reconnaissance - zero packets that look like scanning."""

    def __init__(self, dns_servers: List[str] = None):
        if not DNS_AVAILABLE:
            logger.warning("dnspython not installed - DNS recon disabled. Install with: pip install dnspython")
            self.resolver = None
            self.results = {"hosts": [], "subnets": defaultdict(list), "zones": [], "zone_transfers": []}
            return
        self.resolver = dns.resolver.Resolver()
        if dns_servers:
            self.resolver.nameservers = dns_servers
        else:
            # Default to common internal DNS servers
            self.resolver.nameservers = ["10.0.0.1", "192.168.1.1", "8.8.8.8"]

        self.resolver.timeout = 2
        self.resolver.lifetime = 2
        self.results = {"hosts": [], "subnets": defaultdict(list), "zones": [], "zone_transfers": []}

    def reverse_dns_walk(self, subnet: str) -> List[Dict]:
        """
        Query PTR record for EVERY IP in subnet.
        Looks like normal DNS lookups - NEVER blocked.
        """
        if not DNS_AVAILABLE:
            logger.warning("dnspython not installed - cannot perform reverse DNS walk")
            return []
        try:
            network = ipaddress.ip_network(subnet, strict=False)
        except ValueError as e:
            logger.error(f"Invalid subnet: {e}")
            return []

        hosts = []
        total = network.num_addresses

        # Skip network and broadcast for /24 and larger
        if total > 4:
            hosts_to_check = list(network.hosts())
        else:
            hosts_to_check = list(network)

        logger.info(f"Reverse DNS walk of {subnet} ({len(hosts_to_check)} IPs)")

        for ip in hosts_to_check:
            try:
                reverse_name = dns.reversename.from_address(str(ip))
                answers = self.resolver.resolve(reverse_name, "PTR")

                for rdata in answers:
                    hostname = str(rdata).rstrip(".")
                    hosts.append({"ip": str(ip), "hostname": hostname, "method": "PTR", "subnet": subnet})
            except dns.resolver.NXDOMAIN:
                pass  # No PTR record
            except dns.resolver.Timeout:
                pass  # DNS timeout
            except Exception as e:
                logger.debug(f"PTR lookup failed for {ip}: {e}")

        logger.info(f"✓ Found {len(hosts)} hosts via reverse DNS in {subnet}")
        self.results["hosts"].extend(hosts)
        self.results["subnets"][subnet] = [h["ip"] for h in hosts]
        return hosts

    def forward_dns_bruteforce(self, domain: str, wordlist: List[str]) -> List[Dict]:
        """
        Brute force subdomains/hostnames.
        Uses common naming conventions.
        """
        if not DNS_AVAILABLE:
            logger.warning("dnspython not installed - cannot perform DNS brute force")
            return []
        hosts = []

        for word in wordlist:
            query = f"{word}.{domain}"

            try:
                answers = self.resolver.resolve(query, "A")
                for rdata in answers:
                    ip = str(rdata)
                    hosts.append({"ip": ip, "hostname": query, "method": "A", "domain": domain})
            except dns.resolver.NXDOMAIN:
                pass
            except dns.resolver.NoAnswer:
                pass
            except dns.resolver.Timeout:
                pass
            except Exception as e:
                logger.debug(f"Forward lookup failed for {query}: {e}")

        logger.info(f"✓ Found {len(hosts)} hosts via forward DNS in {domain}")
        self.results["hosts"].extend(hosts)
        return hosts

    def zone_transfer_attempt(self, domain: str, dns_server: str) -> Optional[Dict]:
        """
        Attempt DNS zone transfer (AXFR).
        If successful = ENTIRE DNS database dumped (rare but GOLD).
        """
        if not DNS_AVAILABLE:
            logger.warning("dnspython not installed - cannot attempt zone transfer")
            return None
        try:
            logger.info(f"Attempting zone transfer for {domain} from {dns_server}")

            zone = dns.zone.from_xfr(dns.query.xfr(dns_server, domain, timeout=5, lifetime=10))

            records = []
            for name, node in zone.nodes.items():
                for rdataset in node.rdatasets:
                    records.append(
                        {"name": str(name), "rdtype": dns.rdatatype.to_text(rdataset.rdtype), "data": str(rdataset[0])}
                    )

            result = {
                "domain": domain,
                "dns_server": dns_server,
                "success": True,
                "records": records,
                "record_count": len(records),
            }

            logger.warning(f"🎯 ZONE TRANSFER SUCCESSFUL! {len(records)} records from {domain}")
            self.results["zone_transfers"].append(result)
            return result

        except Exception as e:
            logger.debug(f"Zone transfer failed for {domain}: {e}")
            return {"domain": domain, "dns_server": dns_server, "success": False, "error": str(e)}

    def dns_cache_snoop(self, wordlist: List[str], dns_server: str) -> List[str]:
        """
        DNS cache snooping - see what domains have been recently queried.
        Uses TTL differences to detect cached entries.
        """
        if not DNS_AVAILABLE:
            logger.warning("dnspython not installed - cannot perform DNS cache snooping")
            return []
        cached = []

        for domain in wordlist:
            try:
                # Query with RD (recursion desired) bit
                query = dns.message.make_query(domain, "A")
                response = dns.query.udp(query, dns_server, timeout=2)

                # Check TTL - cached entries have lower TTL
                for rrset in response.answer:
                    if rrset.ttl < 60:  # Very low TTL = likely cached
                        cached.append(domain)
                        logger.debug(f"Cached: {domain} (TTL={rrset.ttl})")
            except Exception:
                pass

        logger.info(f"✓ Found {len(cached)} cached DNS entries")
        return cached

    def enumerate_dhcp_dns(self, subnet: str) -> List[Dict]:
        """
        Find DHCP-registered hosts via DNS.
        Many orgs use dynamic DNS registration from DHCP.
        """
        hosts = []
        ipaddress.ip_address(subnet.split(".")[0] + ".0.0.0")

        # Common DHCP DNS patterns
        dhcp_patterns = [
            "dhcp-{ip}.domain.local",
            "dhcp{ip}.domain.local",
            "host-{ip}.domain.local",
            "dynamic-{ip}.domain.local",
        ]

        # Try common patterns
        for i in range(1, 255):
            dhcp_ip = f"{subnet.split('.')[0]}.{subnet.split('.')[1]}.{subnet.split('.')[2]}.{i}"

            for pattern in dhcp_patterns:
                query = pattern.replace("{ip}", dhcp_ip.replace(".", "-"))

                try:
                    answers = self.resolver.resolve(query, "A")
                    for rdata in answers:
                        hosts.append({"ip": str(rdata), "hostname": query, "method": "DHCP-DNS", "dynamic": True})
                except Exception:
                    pass

        logger.info(f"✓ Found {len(hosts)} DHCP-registered hosts")
        return hosts

    def srv_record_enum(self, domain: str) -> Dict:
        """
        Enumerate SRV records to find services.
        Reveals AD domains, mail servers, VoIP, etc.
        """
        services = {"ldap": [], "kerberos": [], "smb": [], "http": [], "sip": [], "smtp": [], "other": []}

        srv_queries = [
            "_ldap._tcp.{domain}",
            "_kerberos._tcp.{domain}",
            "_cifs._tcp.{domain}",
            "_http._tcp.{domain}",
            "_https._tcp.{domain}",
            "_sip._tcp.{domain}",
            "_smtp._tcp.{domain}",
            "_gc._tcp.{domain}",  # Global Catalog (AD)
            "_ldap._tcp.dc._msdcs.{domain}",  # Domain controllers
            "_kerberos._tcp.dc._msdcs.{domain}",
        ]

        for query_template in srv_queries:
            query = query_template.format(domain=domain)

            try:
                answers = self.resolver.resolve(query, "SRV")
                service_name = query.split(".")[1]

                for rdata in answers:
                    record = {
                        "priority": rdata.priority,
                        "weight": rdata.weight,
                        "port": rdata.port,
                        "target": str(rdata.target).rstrip("."),
                    }

                    if service_name in services:
                        services[service_name].append(record)
                    else:
                        services["other"].append(record)
            except Exception:
                pass

        logger.info(f"✓ Enumerated SRV records for {domain}")
        return services

    def detect_dns_security(self, dns_server: str) -> Dict:
        """
        Check DNS security posture.
        - Zone transfers allowed?
        - DNSsec enabled?
        - Recursion open?
        """
        security = {
            "dns_server": dns_server,
            "zone_transfer_allowed": False,
            "dnssec_enabled": False,
            "recursion_open": False,
            "version_disclosed": False,
            "version": None,
        }

        # Test zone transfer
        try:
            dns.zone.from_xfr(dns.query.xfr(dns_server, ".", timeout=2))
            security["zone_transfer_allowed"] = True
            logger.warning(f"⚠ {dns_server} allows zone transfer on root!")
        except Exception:
            pass

        # Test recursion
        try:
            self.resolver.resolve("google.com", "A")
            security["recursion_open"] = True
        except Exception:
            pass

        # Check DNSsec
        try:
            answers = self.resolver.resolve("com", "DNSKEY")
            if answers:
                security["dnssec_enabled"] = True
        except Exception:
            pass

        # VERSION.BIND query (Chaos class)
        try:
            query = dns.message.make_query("version.bind", "TXT", "CH")
            response = dns.query.udp(query, dns_server, timeout=2)
            for rrset in response.answer:
                if rrset.rdtype == dns.rdatatype.TXT:
                    security["version"] = str(rrset[0])
                    security["version_disclosed"] = True
        except Exception:
            pass

        logger.info(f"DNS security check: {security}")
        return security

    def export_results(self, output_file: str = "dns_recon_results.json"):
        """Export results to file."""
        import json

        with open(output_file, "w") as f:
            json.dump(self.results, f, indent=2, default=str)
        logger.info(f"✓ Results exported to {output_file}")

    def get_all_hosts(self) -> List[Dict]:
        """Get all discovered hosts."""
        return self.results["hosts"]

    def get_subnet_summary(self) -> Dict:
        """Get hosts per subnet."""
        return dict(self.results["subnets"])


def quick_dns_recon(target_domain: str, target_subnet: str = None) -> Dict:
    """
    Quick DNS reconnaissance.
    Returns domain info without credentials.
    """
    result = {
        "domain": target_domain,
        "subnet": target_subnet,
        "hosts": [],
        "srv_records": {},
        "zone_transfer": None,
        "dns_security": {},
    }

    recon = DNSRecon()

    # SRV records (find services)
    result["srv_records"] = recon.srv_record_enum(target_domain)

    # Zone transfer attempt
    dns_servers = recon.resolver.nameservers
    for ns in dns_servers:
        attempt = recon.zone_transfer_attempt(target_domain, ns)
        if attempt and attempt.get("success"):
            result["zone_transfer"] = attempt
            break
        result["zone_transfer"] = attempt

    # Reverse DNS if subnet provided
    if target_subnet:
        hosts = recon.reverse_dns_walk(target_subnet)
        result["hosts"] = hosts

    # DNS security check
    for ns in dns_servers:
        security = recon.detect_dns_security(ns)
        result["dns_security"][ns] = security
        if security.get("zone_transfer_allowed"):
            logger.warning(f"🎯 Zone transfer allowed on {ns}!")

    return result


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 -m hostvigil.discovery.dns_recon <domain> [subnet]")
        print("Example: python3 -m hostvigil.discovery.dns_recon corp.local 10.0.100.0/24")
        sys.exit(1)

    domain = sys.argv[1]
    subnet = sys.argv[2] if len(sys.argv) > 2 else None

    result = quick_dns_recon(domain, subnet)

    import json

    print(json.dumps(result, indent=2, default=str))
