"""
HostVigil - Stealth Network Reconnaissance Platform

A passive-first, stealth-oriented network discovery and vulnerability
assessment platform with ML-driven anomaly detection.
"""

__version__ = "1.0.0"
__author__ = "Krishnendu Paul"
__license__ = "MIT"

VERSION_INFO = {
    "major": 1,
    "minor": 0,
    "patch": 0,
    "release": "",
}


def get_version() -> str:
    """Return the full version string."""
    version = f"{VERSION_INFO['major']}.{VERSION_INFO['minor']}.{VERSION_INFO['patch']}"
    if VERSION_INFO["release"]:
        version += f"-{VERSION_INFO['release']}"
    return version
