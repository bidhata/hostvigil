"""
HostVigil Attack Path Engine

Analyzes scan findings to build potential lateral movement chains and
privilege escalation paths. Maps initial access vectors, lateral movement
opportunities, and privilege escalation routes into end-to-end attack chains.

Output includes a vis.js-compatible graph for dashboard visualization.
"""

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set

logger = logging.getLogger("hostvigil.attack_paths")

# Attack techniques mapped to findings
ATTACK_TECHNIQUES = {
    "smb_relay": {
        "name": "SMB Relay Attack",
        "description": "SMB signing disabled allows NTLMv2 relay to gain code execution",
        "mitre": "T1557.001",
        "requires": ["smb_signing_disabled"],
        "gains": "code_execution",
        "severity": "critical",
    },
    "null_session": {
        "name": "SMB Null Session Enumeration",
        "description": "Anonymous SMB access reveals users, shares, and domain info",
        "mitre": "T1087.002",
        "requires": ["smb_null_session"],
        "gains": "domain_info",
        "severity": "high",
    },
    "default_creds_rce": {
        "name": "Default Credentials → RCE",
        "description": "Service with default credentials allows command execution",
        "mitre": "T1078.001",
        "requires": ["default_credentials"],
        "gains": "code_execution",
        "severity": "critical",
    },
    "redis_rce": {
        "name": "Redis Unauthenticated → RCE",
        "description": "Redis without auth allows writing SSH keys or cron for shell",
        "mitre": "T1210",
        "requires": ["redis_no_auth"],
        "gains": "code_execution",
        "severity": "critical",
    },
    "docker_escape": {
        "name": "Docker API → Host Takeover",
        "description": "Exposed Docker API allows container creation with host mount",
        "mitre": "T1610",
        "requires": ["docker_api_exposed"],
        "gains": "host_takeover",
        "severity": "critical",
    },
    "kerberoast": {
        "name": "Kerberoasting",
        "description": "Service accounts with SPNs can be roasted for password hashes",
        "mitre": "T1558.003",
        "requires": ["kerberoastable_accounts"],
        "gains": "credentials",
        "severity": "high",
    },
    "asrep_roast": {
        "name": "AS-REP Roasting",
        "description": "Accounts without pre-auth can be roasted offline",
        "mitre": "T1558.004",
        "requires": ["asrep_roastable_accounts"],
        "gains": "credentials",
        "severity": "high",
    },
    "rdp_lateral": {
        "name": "RDP Lateral Movement",
        "description": "Compromised credentials + open RDP allows lateral movement",
        "mitre": "T1021.001",
        "requires": ["rdp_open", "credentials"],
        "gains": "lateral_access",
        "severity": "high",
    },
    "winrm_lateral": {
        "name": "WinRM Lateral Movement",
        "description": "PowerShell remoting for stealthy lateral movement",
        "mitre": "T1021.006",
        "requires": ["winrm_open", "credentials"],
        "gains": "lateral_access",
        "severity": "high",
    },
    "ssh_lateral": {
        "name": "SSH Lateral Movement",
        "description": "Compromised credentials or keys allow SSH access",
        "mitre": "T1021.004",
        "requires": ["ssh_open", "credentials"],
        "gains": "lateral_access",
        "severity": "medium",
    },
    "expired_cert_mitm": {
        "name": "Expired Certificate → MITM",
        "description": "Expired/self-signed certs may allow traffic interception",
        "mitre": "T1557",
        "requires": ["expired_certificate", "self_signed_cert"],
        "gains": "traffic_interception",
        "severity": "medium",
    },
    "elasticsearch_data": {
        "name": "Elasticsearch Data Exfiltration",
        "description": "Unauthenticated Elasticsearch exposes indexed data",
        "mitre": "T1213",
        "requires": ["elasticsearch_no_auth"],
        "gains": "data_access",
        "severity": "high",
    },
    "ldap_anon_enum": {
        "name": "LDAP Anonymous Enumeration",
        "description": "Anonymous LDAP bind reveals domain structure and accounts",
        "mitre": "T1087.002",
        "requires": ["ldap_anonymous_bind"],
        "gains": "domain_info",
        "severity": "medium",
    },
}


class AttackPathEngine:
    """Analyzes findings to construct potential attack paths.

    Builds a directed graph of:
    - Initial access vectors (what can we exploit from zero knowledge)
    - Lateral movement paths (how to move from host to host)
    - Privilege escalation (how to go from user to admin/DA)
    """

    def __init__(self, db_path: str):
        self.db_path = db_path

    def correlate_attack_chains(self, limit: int = 50) -> Dict:
        """Persist the latest attack-chain analysis into the DB and export JSON (F4).

        Runs the full ``analyze()`` graph, writes each completed attack chain row into
        the ``attack_chains`` table, and atomically writes ``attack_chains.json`` beside
        the database for downstream tooling.

        Returns:
            {
                'analyzed_at': str,
                'chain_count': int,
                'cluster_count': int,
                'top_chains': [...],
                'rows_written': int,
                'export_path': str,
                'error': str or None,
            }
        """
        result = {
            "analyzed_at": None,
            "chain_count": 0,
            "cluster_count": 0,
            "top_chains": [],
            "rows_written": 0,
            "export_path": None,
            "error": None,
        }
        try:
            analysis = self.analyze()
            chains = analysis.get("attack_chains", [])
            clusters = analysis.get("credential_clusters", [])
            result["chain_count"] = len(chains)
            result["cluster_count"] = len(clusters)
            result["top_chains"] = chains[:limit]

            payload = {
                "risk_score": analysis.get("risk_score", 0.0),
                "summary": analysis.get("summary", ""),
                "attack_chains": chains,
                "credential_clusters": clusters,
                "best_footholds": analysis.get("best_footholds", []),
                "exported_at": datetime.now(timezone.utc).isoformat(),
            }
        except Exception as e:
            logger.warning("Attack chain correlation failed: %s", e)
            result["error"] = str(e)
            return result

        # Persist chains to the attack_chains table (created by migration 0007)
        conn = sqlite3.connect(self.db_path, timeout=30)
        try:
            conn.execute("""CREATE TABLE IF NOT EXISTS attack_chains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chain_json TEXT NOT NULL,
                severity TEXT,
                step_count INTEGER,
                objective TEXT,
                discovered_at TEXT
            )""")
            now = datetime.now(timezone.utc).isoformat()
            result["analyzed_at"] = now
            rows_written = 0
            for chain in chains:
                conn.execute(
                    "INSERT INTO attack_chains (chain_json, severity, step_count, objective, discovered_at) VALUES (?,?,?,?,?)",
                    (
                        json.dumps(chain, default=str),
                        chain.get("severity"),
                        len(chain.get("steps", [])),
                        chain.get("objective"),
                        now,
                    ),
                )
                rows_written += 1
            conn.commit()
            result["rows_written"] = rows_written
        except Exception as exc:
            logger.error("Failed to persist attack chains: %s", exc)
            result["error"] = str(exc)
        finally:
            conn.close()

        # Atomically export the chains for dashboard/external consumption.
        try:
            export_path = Path(self.db_path).parent / "attack_chains.json"
            tmp = Path(str(export_path) + ".tmp")
            tmp.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
            tmp.replace(export_path)
            result["export_path"] = str(export_path)
        except Exception as exc:
            logger.debug("Failed to export attack chains JSON: %s", exc)
            if result["error"] is None:
                result["error"] = str(exc)

        return result

    def analyze(self) -> Dict:
        """Run full attack path analysis.

        Returns:
            {
                'initial_access': [...],
                'lateral_movement': [...],
                'privilege_escalation': [...],
                'attack_chains': [...],
                'pivot_targets': [...],
                'pivot_paths': [...],
                'best_footholds': [...],
                'graph': {'nodes': [...], 'edges': [...]},
                'risk_score': float,
                'summary': str,
            }
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row

        try:
            # Gather all findings
            findings = self._gather_findings(conn)

            # Build attack vectors
            initial_access = self._find_initial_access(conn, findings)
            lateral_paths = self._find_lateral_movement(conn, findings)
            priv_esc = self._find_privilege_escalation(conn, findings)
            pivot_targets = self._rank_pivot_targets(findings, initial_access, lateral_paths, priv_esc)
            pivot_paths = self._build_pivot_paths(initial_access, lateral_paths, priv_esc, pivot_targets)

            # Build chains (initial → lateral → priv esc)
            chains = self._build_attack_chains(initial_access, lateral_paths, priv_esc)

            # Build visualization graph
            graph = self._build_graph(initial_access, lateral_paths, priv_esc, chains)

            # Calculate overall risk score
            risk_score = self._calculate_risk_score(initial_access, lateral_paths, priv_esc)
        finally:
            conn.close()

        return {
            "initial_access": initial_access,
            "lateral_movement": lateral_paths,
            "privilege_escalation": priv_esc,
            "attack_chains": chains,
            "pivot_targets": pivot_targets,
            "pivot_paths": pivot_paths,
            "best_footholds": pivot_targets[:5],
            "crown_jewels": [item for item in pivot_targets if item.get("is_crown_jewel")][:5],
            "credential_clusters": findings.get("credential_clusters", []),
            "graph": graph,
            "risk_score": risk_score,
            "summary": self._generate_summary(
                initial_access, lateral_paths, priv_esc, chains, risk_score, pivot_targets, pivot_paths
            ),
        }

    def _gather_findings(self, conn) -> Dict:
        """Collect all relevant findings from the database."""
        findings = {
            "hosts": [],
            "ports": [],
            "vulns": [],
            "services": [],
            "creds": [],
            "enum": [],
            "tls": [],
            "host_tags": [],
            "credential_clusters": [],
        }

        findings["hosts"] = [dict(r) for r in conn.execute("SELECT * FROM hosts WHERE is_active = 1").fetchall()]

        findings["ports"] = [
            dict(r)
            for r in conn.execute(
                "SELECT p.*, h.ip, h.hostname FROM ports p JOIN hosts h ON h.id = p.host_id WHERE p.is_active = 1"
            ).fetchall()
        ]

        findings["vulns"] = [
            dict(r)
            for r in conn.execute(
                "SELECT v.*, h.ip, h.hostname FROM vulnerabilities v JOIN hosts h ON h.id = v.host_id"
            ).fetchall()
        ]

        # Service enumeration findings
        try:
            findings["enum"] = [
                dict(r)
                for r in conn.execute(
                    "SELECT se.*, h.ip, h.hostname FROM service_enumeration se LEFT JOIN hosts h ON h.id = se.host_id"
                ).fetchall()
            ]
        except Exception as e:
            logger.warning("Failed to load service_enumeration findings: %s", e)

        # Credential spray results
        try:
            findings["creds"] = [
                dict(r)
                for r in conn.execute(
                    "SELECT c.*, h.ip, h.hostname FROM credential_results c "
                    "JOIN hosts h ON h.id = c.host_id WHERE c.success = 1"
                ).fetchall()
            ]
        except Exception as e:
            logger.warning("Failed to load credential_results findings: %s", e)

        findings["credential_clusters"] = self._build_credential_clusters(findings.get("creds", []))

        # TLS findings
        try:
            findings["tls"] = [
                dict(r)
                for r in conn.execute(
                    "SELECT * FROM tls_certificates WHERE is_expired = 1 OR is_self_signed = 1"
                ).fetchall()
            ]
        except Exception as e:
            logger.warning("Failed to load tls_certificates findings: %s", e)

        try:
            findings["host_tags"] = [
                dict(r)
                for r in conn.execute(
                    "SELECT ht.host_id, ht.tag, ht.added_at, h.ip, h.hostname "
                    "FROM host_tags ht JOIN hosts h ON h.id = ht.host_id"
                ).fetchall()
            ]
        except Exception as e:
            logger.warning("Failed to load host_tags findings: %s", e)

        return findings

    def _find_initial_access(self, conn, findings: Dict) -> List[Dict]:
        """Identify initial access vectors from findings."""
        vectors = []

        # Check for unauthenticated services
        for enum in findings.get("enum", []):
            data = {}
            try:
                data = json.loads(enum.get("enum_data", "{}") or "{}")
            except (json.JSONDecodeError, TypeError):
                data = {}

            # Newer schemas store summary data in details and severity in severity.
            if not data and enum.get("details"):
                try:
                    details_data = json.loads(enum.get("details", "{}") or "{}")
                    if isinstance(details_data, dict):
                        data = (
                            details_data.get("enum_data", {})
                            if isinstance(details_data.get("enum_data", {}), dict)
                            else {}
                        )
                except (json.JSONDecodeError, TypeError):
                    data = {}

            risk = (enum.get("risk_level") or enum.get("severity") or "info").lower()

            if risk in ("critical", "high"):
                technique = None
                if "redis" in (enum.get("service_type", "") or "").lower():
                    technique = ATTACK_TECHNIQUES.get("redis_rce")
                elif "docker" in (enum.get("service_type", "") or "").lower():
                    technique = ATTACK_TECHNIQUES.get("docker_escape")
                elif "elasticsearch" in (enum.get("service_type", "") or "").lower():
                    technique = ATTACK_TECHNIQUES.get("elasticsearch_data")
                elif "smb" in (enum.get("service_type", "") or "").lower():
                    if data.get("signing_required") is False:
                        technique = ATTACK_TECHNIQUES.get("smb_relay")
                    elif data.get("null_session"):
                        technique = ATTACK_TECHNIQUES.get("null_session")
                elif "ldap" in (enum.get("service_type", "") or "").lower():
                    technique = ATTACK_TECHNIQUES.get("ldap_anon_enum")

                if technique:
                    vectors.append(
                        {
                            "host_ip": enum.get("ip", ""),
                            "port": enum.get("port", 0),
                            "technique": technique["name"],
                            "mitre": technique["mitre"],
                            "severity": technique["severity"],
                            "description": technique["description"],
                            "gains": technique["gains"],
                        }
                    )

        # Check successful credential sprays
        for cred in findings.get("creds", []):
            vectors.append(
                {
                    "host_ip": cred.get("ip", ""),
                    "port": cred.get("port", 0),
                    "technique": "Default Credentials \u2192 RCE",
                    "mitre": "T1078.001",
                    "severity": "critical",
                    "description": f"Valid credentials found for {cred.get('service', 'unknown')} ({cred.get('username', '')})",
                    "gains": "code_execution",
                }
            )

        # Check Nuclei critical findings
        for vuln in findings.get("vulns", []):
            if (vuln.get("severity", "") or "").lower() == "critical":
                vectors.append(
                    {
                        "host_ip": vuln.get("ip", ""),
                        "port": 0,
                        "technique": vuln.get("name", "Critical Vulnerability"),
                        "mitre": "T1190",
                        "severity": "critical",
                        "description": vuln.get("description", ""),
                        "gains": "code_execution",
                    }
                )

        return vectors

    def _find_lateral_movement(self, conn, findings: Dict) -> List[Dict]:
        """Identify lateral movement opportunities."""
        paths = []

        # Find all hosts with RDP/SSH/WinRM open
        for port_info in findings.get("ports", []):
            port = port_info.get("port", 0)
            ip = port_info.get("ip", "")
            service = port_info.get("service", "") or ""

            if port == 3389 or "rdp" in service.lower():
                paths.append(
                    {
                        "from": "*",  # Any compromised host with creds
                        "to": ip,
                        "port": port,
                        "method": "RDP",
                        "technique": ATTACK_TECHNIQUES["rdp_lateral"]["name"],
                        "mitre": "T1021.001",
                        "requires": "Valid credentials",
                    }
                )
            elif port == 22 or "ssh" in service.lower():
                paths.append(
                    {
                        "from": "*",
                        "to": ip,
                        "port": port,
                        "method": "SSH",
                        "technique": ATTACK_TECHNIQUES["ssh_lateral"]["name"],
                        "mitre": "T1021.004",
                        "requires": "Valid credentials or SSH key",
                    }
                )
            elif port in (5985, 5986) or "winrm" in service.lower():
                paths.append(
                    {
                        "from": "*",
                        "to": ip,
                        "port": port,
                        "method": "WinRM",
                        "technique": ATTACK_TECHNIQUES["winrm_lateral"]["name"],
                        "mitre": "T1021.006",
                        "requires": "Valid credentials (admin)",
                    }
                )

        # SMB relay paths (from any host to signing-disabled host)
        for enum in findings.get("enum", []):
            try:
                data = json.loads(enum.get("enum_data", "{}") or "{}")
            except (json.JSONDecodeError, TypeError):
                data = {}
            if data.get("signing_required") is False:
                paths.append(
                    {
                        "from": "*",
                        "to": enum.get("ip", ""),
                        "port": 445,
                        "method": "SMB Relay",
                        "technique": "NTLM Relay to unsigned SMB",
                        "mitre": "T1557.001",
                        "requires": "Network position (MITM or coerced auth)",
                    }
                )

        return paths

    def _find_privilege_escalation(self, conn, findings: Dict) -> List[Dict]:
        """Identify privilege escalation paths."""
        priv_esc = []

        # Kerberoasting
        try:
            ad_objects = conn.execute("SELECT * FROM ad_objects WHERE object_type = 'kerberoastable'").fetchall()
            if ad_objects:
                priv_esc.append(
                    {
                        "technique": "Kerberoasting",
                        "mitre": "T1558.003",
                        "targets": len(ad_objects),
                        "description": f"{len(ad_objects)} service accounts with SPNs can be roasted offline",
                        "severity": "high",
                        "gains": "Service account credentials (potentially DA)",
                    }
                )
        except Exception:
            pass

        # AS-REP Roasting
        try:
            asrep = conn.execute("SELECT * FROM ad_objects WHERE object_type = 'asrep_roastable'").fetchall()
            if asrep:
                priv_esc.append(
                    {
                        "technique": "AS-REP Roasting",
                        "mitre": "T1558.004",
                        "targets": len(asrep),
                        "description": f"{len(asrep)} accounts without pre-auth requirement",
                        "severity": "high",
                        "gains": "User credentials",
                    }
                )
        except Exception:
            pass

        # Domain Admin via credential chain
        if findings.get("creds"):
            priv_esc.append(
                {
                    "technique": "Credential Reuse",
                    "mitre": "T1078",
                    "targets": len(findings["creds"]),
                    "description": "Compromised credentials may grant access to higher-privilege systems",
                    "severity": "high",
                    "gains": "Elevated privileges via password reuse",
                }
            )

        return priv_esc

    def _rank_pivot_targets(self, findings: Dict, initial: List, lateral: List, priv_esc: List) -> List[Dict]:
        """Rank hosts by offensive value: foothold quality, chainability, and blast radius."""
        host_index = {}
        for host in findings.get("hosts", []):
            host_index[host.get("ip", "")] = dict(host)

        host_scores = {}

        def ensure_host(ip: str) -> Dict:
            if ip not in host_scores:
                host_scores[ip] = {
                    "host_ip": ip,
                    "hostname": host_index.get(ip, {}).get("hostname"),
                    "score": 0,
                    "reasons": [],
                    "initial_access": [],
                    "lateral_targets": set(),
                    "attack_tags": set(),
                }
            return host_scores[ip]

        def add_reason(entry: Dict, points: int, reason: str):
            entry["score"] += points
            if reason not in entry["reasons"]:
                entry["reasons"].append(reason)

        # Seed with service enumeration tags and host tags.
        for tag_row in findings.get("host_tags", []):
            ip = tag_row.get("ip", "")
            tag = (tag_row.get("tag") or "").lower().replace("_", "-")
            entry = ensure_host(ip)
            entry["attack_tags"].add(tag)
            if tag in ("crown-jewel", "crown jewel", "crownjewel"):
                entry["attack_tags"].add("crown-jewel")
                add_reason(entry, 30, "explicit crown jewel tag")
            if tag in ("host-takeover", "relay-risk"):
                add_reason(entry, 22, f"{tag} service exposure")
            elif tag in ("pivot-node", "lateral-movement"):
                add_reason(entry, 12, f"{tag} movement path")
            elif tag in ("domain-enum", "credential-harvest", "admin-plane", "data-exposure"):
                add_reason(entry, 8, f"{tag} intelligence")

        for cluster in findings.get("credential_clusters", []):
            host_ips = cluster.get("hosts", []) or []
            if len(host_ips) < 2:
                continue
            reuse_score = min(20 + (len(host_ips) - 2) * 4, 32)
            reason = cluster.get("label") or "reused credential set"
            for ip in host_ips:
                entry = ensure_host(ip)
                entry["attack_tags"].add("credential-reuse")
                add_reason(entry, reuse_score, reason)

        for enum in findings.get("enum", []):
            ip = enum.get("ip", "")
            entry = ensure_host(ip)
            data = {}
            try:
                data = json.loads(enum.get("enum_data", "{}") or "{}")
            except (json.JSONDecodeError, TypeError):
                data = {}

            service_type = (enum.get("service_type") or "").lower()
            risk = (enum.get("risk_level") or enum.get("severity") or "info").lower()
            if risk == "critical":
                add_reason(entry, 18, f"critical {service_type} exposure")
            elif risk == "high":
                add_reason(entry, 10, f"high {service_type} exposure")
            elif risk == "medium":
                add_reason(entry, 4, f"medium {service_type} exposure")

            if "attack_tags" in data:
                for tag in data.get("attack_tags", []):
                    tag = str(tag).lower().replace("_", "-")
                    entry["attack_tags"].add(tag)
                    if tag == "crown-jewel":
                        add_reason(entry, 24, f"{service_type} crown jewel adjacency")
                    if tag == "host-takeover":
                        add_reason(entry, 18, f"{service_type} takeover path")
                    elif tag == "relay-risk":
                        add_reason(entry, 16, f"{service_type} relay risk")
                    elif tag == "pivot-node":
                        add_reason(entry, 12, f"{service_type} pivot node")
                    elif tag == "lateral-movement":
                        add_reason(entry, 10, f"{service_type} lateral movement")
                    elif tag in ("domain-enum", "credential-harvest", "admin-plane", "data-exposure"):
                        add_reason(entry, 6, f"{service_type} {tag}")

            if service_type in ("smb", "ldap", "ldaps", "redis", "elasticsearch", "docker", "winrm", "ssh", "rdp"):
                entry["attack_tags"].add(service_type)

        for ia in initial:
            ip = ia.get("host_ip", "")
            entry = ensure_host(ip)
            entry["initial_access"].append(ia)
            severity = (ia.get("severity") or "info").lower()
            if severity == "critical":
                add_reason(entry, 28, f"initial access: {ia.get('technique', 'unknown')}")
            elif severity == "high":
                add_reason(entry, 18, f"initial access: {ia.get('technique', 'unknown')}")
            elif severity == "medium":
                add_reason(entry, 8, f"initial access: {ia.get('technique', 'unknown')}")

        for lm in lateral:
            ip = lm.get("to", "")
            entry = ensure_host(ip)
            entry["lateral_targets"].add(lm.get("method", ""))
            add_reason(entry, 6, f"reachable via {lm.get('method', 'lateral movement')}")

        for pe in priv_esc:
            if pe.get("severity") == "critical":
                for host in host_scores.values():
                    add_reason(host, 8, f"priv esc path: {pe.get('technique', 'unknown')}")
            elif pe.get("severity") == "high":
                for host in host_scores.values():
                    add_reason(host, 4, f"priv esc path: {pe.get('technique', 'unknown')}")

        for ip, entry in host_scores.items():
            open_ports = [p for p in findings.get("ports", []) if p.get("ip") == ip and p.get("state") == "open"]
            sensitive_ports = {
                22,
                23,
                25,
                53,
                80,
                88,
                135,
                139,
                389,
                443,
                445,
                636,
                1433,
                1521,
                2375,
                2376,
                3306,
                3389,
                5432,
                5985,
                5986,
                6379,
                8080,
                8443,
                9200,
                9300,
                27017,
            }
            port_bonus = sum(3 for p in open_ports if int(p.get("port") or 0) in sensitive_ports)
            add_reason(entry, min(port_bonus, 18), "sensitive services exposed")

            if len(open_ports) >= 8:
                add_reason(entry, 6, "wide service surface")
            if len(entry["lateral_targets"]) >= 3:
                add_reason(entry, 8, "multi-target lateral reach")
            if "relay-risk" in entry["attack_tags"] and "pivot-node" in entry["attack_tags"]:
                add_reason(entry, 10, "relay-to-pivot combination")
            if "credential-reuse" in entry["attack_tags"]:
                add_reason(entry, 6, "credential reuse cluster")
            if "crown-jewel" in entry["attack_tags"]:
                add_reason(entry, 12, "explicit crown jewel target")

        ranked = []
        for entry in host_scores.values():
            score = min(100, entry["score"])
            if score <= 0:
                continue
            ranked.append(
                {
                    "host_ip": entry["host_ip"],
                    "hostname": entry["hostname"],
                    "score": score,
                    "rank_label": self._pivot_label(score, entry["attack_tags"]),
                    "reasons": entry["reasons"][:6],
                    "attack_tags": sorted(entry["attack_tags"]),
                    "initial_access_count": len(entry["initial_access"]),
                    "lateral_target_count": len(entry["lateral_targets"]),
                    "is_crown_jewel": "crown-jewel" in entry["attack_tags"],
                }
            )

        ranked.sort(
            key=lambda item: (
                -item["score"],
                -item["initial_access_count"],
                -item["lateral_target_count"],
                item["host_ip"],
            )
        )
        return ranked

    def _build_pivot_paths(self, initial: List, lateral: List, priv_esc: List, pivot_targets: List[Dict]) -> List[Dict]:
        """Build the best offensive pivot paths from foothold to downstream objective."""
        target_scores = {p["host_ip"]: p for p in pivot_targets}
        paths = []

        lateral_by_target = {}
        for lm in lateral:
            lateral_by_target.setdefault(lm.get("to", ""), []).append(lm)

        for ia in initial:
            for target_ip, lm_list in lateral_by_target.items():
                if target_ip == ia.get("host_ip"):
                    continue
                target = target_scores.get(target_ip)
                if not target:
                    continue

                for lm in lm_list:
                    path_score = self._chain_score(ia, lm, target, priv_esc)
                    paths.append(
                        {
                            "score": path_score,
                            "foothold": {
                                "host": ia.get("host_ip"),
                                "technique": ia.get("technique"),
                                "mitre": ia.get("mitre"),
                                "severity": ia.get("severity"),
                            },
                            "pivot": {
                                "host": target_ip,
                                "hostname": target.get("hostname"),
                                "score": target.get("score", 0),
                                "reasons": target.get("reasons", []),
                                "attack_tags": target.get("attack_tags", []),
                                "is_crown_jewel": target.get("is_crown_jewel", False),
                            },
                            "lateral": {
                                "method": lm.get("method"),
                                "port": lm.get("port"),
                                "technique": lm.get("technique"),
                                "mitre": lm.get("mitre"),
                            },
                            "objective": priv_esc[0]["gains"] if priv_esc else "Unknown",
                        }
                    )

        paths.sort(key=lambda item: (-item["score"], item["foothold"]["host"], item["pivot"]["host"]))
        return paths[:3]

    def _chain_score(self, ia: Dict, lm: Dict, pivot: Dict, priv_esc: List[Dict]) -> int:
        """Score a chain by foothold quality, pivot value, and objective proximity."""
        score = 0
        sev = (ia.get("severity") or "info").lower()
        if sev == "critical":
            score += 30
        elif sev == "high":
            score += 20
        elif sev == "medium":
            score += 10

        score += min(int(pivot.get("score") or 0), 100) // 2

        if lm.get("method") in ("SMB Relay", "WinRM", "RDP"):
            score += 8
        elif lm.get("method") == "SSH":
            score += 5

        if priv_esc:
            best = priv_esc[0]
            if best.get("severity") == "critical":
                score += 20
            elif best.get("severity") == "high":
                score += 12

        if "relay-risk" in pivot.get("attack_tags", []):
            score += 8
        if "admin-plane" in pivot.get("attack_tags", []):
            score += 6
        if pivot.get("is_crown_jewel"):
            score += 20

        return min(score, 100)

    @staticmethod
    def _pivot_label(score: int, attack_tags: Optional[Set[str]] = None) -> str:
        if attack_tags and "crown-jewel" in attack_tags:
            return "CROWN JEWEL"
        if score >= 75:
            return "HIGH VALUE FOOTHOLD"
        if score >= 50:
            return "STRONG PIVOT"
        if score >= 25:
            return "USEFUL PIVOT"
        return "WEAK PIVOT"

    def _build_attack_chains(self, initial: List, lateral: List, priv_esc: List) -> List[Dict]:
        """Build end-to-end attack chains from initial access to objective."""
        chains = []

        for ia in initial:
            chain = {
                "id": len(chains),
                "steps": [],
                "severity": ia["severity"],
                "objective": "Unknown",
            }

            # Step 1: Initial access
            chain["steps"].append(
                {
                    "step": 1,
                    "type": "initial_access",
                    "host": ia["host_ip"],
                    "technique": ia["technique"],
                    "mitre": ia["mitre"],
                }
            )

            # Step 2: Find lateral movement from this host
            next_targets = [lat for lat in lateral if lat["to"] != ia["host_ip"]]
            if next_targets:
                target = next_targets[0]  # Pick first available
                chain["steps"].append(
                    {
                        "step": 2,
                        "type": "lateral_movement",
                        "host": target["to"],
                        "technique": target["technique"],
                        "mitre": target["mitre"],
                    }
                )

            # Step 3: Privilege escalation
            if priv_esc:
                pe = priv_esc[0]
                chain["steps"].append(
                    {
                        "step": 3,
                        "type": "privilege_escalation",
                        "technique": pe["technique"],
                        "mitre": pe["mitre"],
                        "gains": pe["gains"],
                    }
                )
                chain["objective"] = pe["gains"]

            if chain["steps"]:
                chains.append(chain)

        # Sort by severity and length
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        chains.sort(key=lambda c: severity_order.get(c["severity"], 9))

        return chains[:20]  # Top 20 chains

    def _build_graph(self, initial, lateral, priv_esc, chains) -> Dict:
        """Build a visualization-ready graph of attack paths."""
        nodes = {}
        edges = []

        # Add attacker node
        nodes["attacker"] = {
            "id": "attacker",
            "label": "Attacker",
            "type": "attacker",
            "color": "#ff1744",
            "size": 30,
        }

        # Add initial access targets
        for ia in initial:
            node_id = ia["host_ip"]
            if node_id not in nodes:
                nodes[node_id] = {
                    "id": node_id,
                    "label": ia["host_ip"],
                    "type": "target",
                    "color": "#dc3545",
                    "size": 25,
                    "techniques": [],
                }
            nodes[node_id]["techniques"].append(ia["technique"])

            edges.append(
                {
                    "from": "attacker",
                    "to": node_id,
                    "label": ia["technique"][:30],
                    "color": "#dc3545",
                    "dashes": False,
                }
            )

        # Add lateral movement paths
        for lm in lateral[:50]:  # Limit edges
            target_id = lm["to"]
            if target_id not in nodes:
                nodes[target_id] = {
                    "id": target_id,
                    "label": target_id,
                    "type": "reachable",
                    "color": "#fcb92c",
                    "size": 15,
                    "techniques": [],
                }
            nodes[target_id]["techniques"].append(lm["method"])

            # Connect from initial access nodes
            for ia in initial[:5]:
                edges.append(
                    {
                        "from": ia["host_ip"],
                        "to": target_id,
                        "label": lm["method"],
                        "color": "#fcb92c",
                        "dashes": True,
                    }
                )
                break  # One edge per lateral target

        # Add privilege escalation as a "crown" node
        if priv_esc:
            nodes["objective"] = {
                "id": "objective",
                "label": "Domain Admin / Objective",
                "type": "objective",
                "color": "#9c27b0",
                "size": 35,
            }
            # Connect from lateral targets
            connected = False
            for node_id, node in nodes.items():
                if node.get("type") == "reachable" and not connected:
                    edges.append(
                        {
                            "from": node_id,
                            "to": "objective",
                            "label": priv_esc[0]["technique"],
                            "color": "#9c27b0",
                            "dashes": False,
                        }
                    )
                    connected = True
            if not connected:
                for ia in initial[:1]:
                    edges.append(
                        {
                            "from": ia["host_ip"],
                            "to": "objective",
                            "label": priv_esc[0]["technique"],
                            "color": "#9c27b0",
                            "dashes": False,
                        }
                    )

        return {
            "nodes": list(nodes.values()),
            "edges": edges,
        }

    def _calculate_risk_score(self, initial, lateral, priv_esc) -> float:
        """Calculate an overall risk score (0-100)."""
        score = 0.0

        # Initial access severity
        for ia in initial:
            if ia["severity"] == "critical":
                score += 25
            elif ia["severity"] == "high":
                score += 15
            elif ia["severity"] == "medium":
                score += 8

        # Lateral movement availability
        unique_lateral = set(lat["to"] for lat in lateral)
        score += min(20, len(unique_lateral) * 2)

        # Privilege escalation paths
        for pe in priv_esc:
            if pe["severity"] == "critical":
                score += 20
            elif pe["severity"] == "high":
                score += 10

        return min(100.0, score)

    def _generate_summary(
        self, initial, lateral, priv_esc, chains, risk_score, pivot_targets=None, pivot_paths=None
    ) -> str:
        """Generate a human-readable summary."""
        parts = [f"Risk Score: {risk_score:.0f}/100"]

        if initial:
            parts.append(f"{len(initial)} initial access vector(s) identified")
        if lateral:
            unique_targets = set(lat["to"] for lat in lateral)
            parts.append(f"{len(unique_targets)} hosts reachable via lateral movement")
        if priv_esc:
            parts.append(f"{len(priv_esc)} privilege escalation path(s)")
        if chains:
            parts.append(f"{len(chains)} complete attack chain(s) from initial access to objective")

        if pivot_targets:
            parts.append(f"Top foothold: {pivot_targets[0]['host_ip']} ({pivot_targets[0]['score']}/100)")
            crown_jewel_count = sum(1 for item in pivot_targets if item.get("is_crown_jewel"))
            if crown_jewel_count:
                parts.append(f"{crown_jewel_count} crown jewel target(s) mapped")
        if pivot_paths:
            parts.append(f"{len(pivot_paths)} best pivot path(s) prioritized")

        if risk_score >= 75:
            parts.append("CRITICAL: Multiple high-confidence paths to domain compromise exist.")
        elif risk_score >= 50:
            parts.append("HIGH: Significant attack surface with exploitable paths.")
        elif risk_score >= 25:
            parts.append("MEDIUM: Some attack vectors present but limited chaining.")
        else:
            parts.append("LOW: Limited attack surface detected.")

        return " | ".join(parts)

    def _build_credential_clusters(self, creds: List[Dict]) -> List[Dict]:
        """Group successful credentials by reuse pattern for offensive prioritization."""
        clusters = {}

        for cred in creds or []:
            username = (cred.get("username") or "").strip().lower()
            service = (cred.get("service") or "").strip().lower()
            credential_hash = (cred.get("credential_hash") or "").strip().lower()
            host_ip = cred.get("ip", "")

            primary_key = credential_hash or f"{username}|{service}"
            if not primary_key:
                continue

            cluster = clusters.setdefault(
                primary_key,
                {
                    "username": username,
                    "service": service,
                    "credential_hash": credential_hash or None,
                    "hosts": set(),
                },
            )
            if host_ip:
                cluster["hosts"].add(host_ip)

        results = []
        for key, cluster in clusters.items():
            hosts = sorted(cluster["hosts"])
            if len(hosts) < 2:
                continue
            label_bits = []
            if cluster["username"]:
                label_bits.append(cluster["username"])
            if cluster["service"]:
                label_bits.append(cluster["service"])
            if not label_bits:
                label_bits.append(key[:12])
            results.append(
                {
                    "label": f"Reused credential: {'/'.join(label_bits)}",
                    "username": cluster["username"] or None,
                    "service": cluster["service"] or None,
                    "credential_hash": cluster["credential_hash"],
                    "hosts": hosts,
                    "host_count": len(hosts),
                }
            )

        results.sort(key=lambda item: (-item["host_count"], item["label"]))
        return results
