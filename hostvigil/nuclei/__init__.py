"""HostVigil Nuclei Module - Automated vulnerability scanning with stealth.

Provides the NucleiRunner class for orchestrating Nuclei scans with:
- Auto-generated target lists from discovery/scan results
- Rate-limited, low-concurrency execution for stealth
- JSONL result parsing into structured vulnerability records
- Red team classification (exploit_ready, needs_validation, informational)
- Template filtering by severity, type, or custom paths
"""

from hostvigil.nuclei.nuclei_runner import NucleiRunner

__all__ = ["NucleiRunner"]
