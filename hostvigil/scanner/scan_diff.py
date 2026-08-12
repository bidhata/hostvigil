"""
HostVigil Scan Diff - Shows what changed between scan cycles.

Compares current network state against historical data to identify:
- New hosts appearing on the network
- Hosts that have disappeared
- New ports/services opening
- Ports/services that have closed
"""

import logging
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Dict

logger = logging.getLogger("hostvigil.scanner.scan_diff")


class ScanDiff:
    """Computes differences in network state over a given time window."""

    def __init__(self, db_path: str):
        self.db_path = db_path

    def get_diff(self, hours_back: int = 24) -> Dict:
        """Get changes in the last N hours.

        Args:
            hours_back: Number of hours to look back for changes.

        Returns:
            Dictionary containing new hosts, disappeared hosts,
            new ports, closed ports, and a summary.
        """
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours_back)).isoformat()
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row

        try:
            # New hosts (first_seen after cutoff)
            new_hosts = [
                dict(r)
                for r in conn.execute(
                    "SELECT id, ip, hostname, first_seen, discovery_method FROM hosts WHERE first_seen > ?", (cutoff,)
                ).fetchall()
            ]

            # Disappeared hosts (last_seen before cutoff but were active)
            disappeared = [
                dict(r)
                for r in conn.execute(
                    "SELECT id, ip, hostname, last_seen FROM hosts WHERE is_active = 0 AND last_seen > ?", (cutoff,)
                ).fetchall()
            ]

            # New ports (first_seen after cutoff)
            new_ports = [
                dict(r)
                for r in conn.execute(
                    """SELECT p.port, p.protocol, p.service, p.banner, p.first_seen, h.ip, h.hostname
                   FROM ports p JOIN hosts h ON h.id = p.host_id
                   WHERE p.first_seen > ?""",
                    (cutoff,),
                ).fetchall()
            ]

            # Closed ports (was active, now inactive, last_seen after cutoff)
            closed_ports = [
                dict(r)
                for r in conn.execute(
                    """SELECT p.port, p.protocol, p.service, p.last_seen, h.ip, h.hostname
                   FROM ports p JOIN hosts h ON h.id = p.host_id
                   WHERE p.is_active = 0 AND p.last_seen > ?""",
                    (cutoff,),
                ).fetchall()
            ]
        finally:
            conn.close()

        return {
            "period_hours": hours_back,
            "since": cutoff,
            "new_hosts": new_hosts,
            "disappeared_hosts": disappeared,
            "new_ports": new_ports,
            "closed_ports": closed_ports,
            "summary": {
                "new_hosts_count": len(new_hosts),
                "disappeared_count": len(disappeared),
                "new_ports_count": len(new_ports),
                "closed_ports_count": len(closed_ports),
            },
        }
