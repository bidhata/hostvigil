"""
Configuration loader for HostVigil.

Loads settings from config.yaml with sensible defaults as fallback.
"""

import copy
import ipaddress
import logging
import threading
from pathlib import Path
from typing import Any

import yaml

# Pre-configured profiles for different organization sizes
PRECONFIGURED_PROFILES = {
    "basic": {
        "name": "Basic (Small Network)",
        "description": "For small networks (< 500 hosts). Fast scanning, minimal stealth.",
        "icon": "bi-house-door",
        "config": {
            "target_ranges": ["192.168.1.0/24"],
            "discovery": {
                "techniques": ["arp_sweep", "icmp_sweep"],
                "wave_enabled": False,
                "wave_size": 100,
                "arp_batch_size": 50,
                "arp_batch_delay": 2.0,
            },
            "scanner": {
                "mode": "two_phase",
                "naabu": {
                    "rate": 5000,
                    "threads": 50,
                },
                "nmap": {
                    "version_detection": True,
                    "os_detection": False,
                    "timing": "T4",
                },
            },
            "stealth": {
                "profile": "basic",
                "min_delay": 2.0,
                "max_delay": 10.0,
                "max_threads": 10,
                "jitter_factor": 0.1,
            },
            "nuclei": {
                "auto_run": False,
                "severity_filter": ["critical"],
                "rate_limit": 100,
                "concurrency": 25,
            },
            "pipeline": {
                "mode": "wave",
                "wave_size": 50,
                "wave_delay": 30,
            },
        },
    },
    "sme": {
        "name": "SME (Medium Network)",
        "description": "For medium networks (500-5,000 hosts). Balanced speed and stealth.",
        "icon": "bi-buildings",
        "config": {
            "target_ranges": ["192.168.0.0/16"],
            "discovery": {
                "techniques": ["arp_sweep", "icmp_sweep", "dns_reverse_walk", "mdns_enum"],
                "wave_enabled": True,
                "wave_size": 500,
                "arp_batch_size": 25,
                "arp_batch_delay": 3.0,
            },
            "scanner": {
                "mode": "two_phase",
                "naabu": {
                    "rate": 5000,
                    "threads": 50,
                },
                "nmap": {
                    "version_detection": True,
                    "os_detection": True,
                    "timing": "T3",
                },
            },
            "stealth": {
                "profile": "shadow",
                "min_delay": 5.0,
                "max_delay": 20.0,
                "max_threads": 5,
                "jitter_factor": 0.2,
                "business_hours_only": True,
                "scan_window_start": 9,
                "scan_window_end": 17,
            },
            "nuclei": {
                "auto_run": True,
                "severity_filter": ["critical", "high"],
                "rate_limit": 50,
                "concurrency": 15,
            },
            "pipeline": {
                "mode": "wave",
                "wave_size": 200,
                "wave_delay": 60,
            },
        },
    },
    "enterprise": {
        "name": "Enterprise (Large Network)",
        "description": "For large networks (5,000-200,000+ hosts). Maximum stealth, slow scanning.",
        "icon": "bi-globe-americas",
        "config": {
            "target_ranges": ["10.0.0.0/8"],
            "discovery": {
                "techniques": [
                    "arp_sweep",
                    "icmp_sweep",
                    "dns_reverse_walk",
                    "passive_sniff",
                    "mdns_enum",
                    "nbns_query",
                ],
                "wave_enabled": True,
                "wave_size": 1000,
                "arp_batch_size": 16,
                "arp_batch_delay": 5.0,
            },
            "scanner": {
                "mode": "two_phase",
                "naabu": {
                    "rate": 5000,
                    "threads": 50,
                },
                "nmap": {
                    "version_detection": True,
                    "os_detection": True,
                    "scripts": True,
                    "timing": "T2",
                },
            },
            "stealth": {
                "profile": "ghost",
                "min_delay": 10.0,
                "max_delay": 45.0,
                "max_threads": 3,
                "jitter_factor": 0.3,
                "business_hours_only": True,
                "scan_window_start": 9,
                "scan_window_end": 17,
                "decoy_ips": ["10.0.0.1", "10.0.0.254", "172.16.0.1", "192.168.1.1"],
            },
            "nuclei": {
                "auto_run": True,
                "severity_filter": ["critical", "high", "medium"],
                "rate_limit": 25,
                "concurrency": 10,
            },
            "pipeline": {
                "mode": "wave",
                "wave_size": 500,
                "wave_delay": 120,
            },
            "abort_conditions": {
                "honeypot_detected": True,
                "scan_blocked_count": 10,
                "error_rate_threshold": 0.3,
                "timeout_rate_threshold": 0.4,
            },
        },
    },
}


DEFAULT_CONFIG: dict[str, Any] = {
    "hostvigil": {
        "stealth": {
            "min_delay": 10.0,
            "max_delay": 45.0,
            "max_threads": 3,
            "jitter_factor": 0.3,
            "packet_fragmentation": True,
            "randomize_scan_order": True,
            "ttl_manipulation": True,
            "decoy_ips": ["10.0.0.1", "10.0.0.254", "172.16.0.1", "192.168.1.1", "100.64.0.1", "198.18.0.1"],
        },
        "discovery": {
            # CRITICAL: Start with small, known ranges. DO NOT use 10.0.0.0/8 (16.7M IPs)!
            # Expand gradually after validating performance.
            "target_ranges": [
                # Start with these - adjust to your actual network
                "192.168.1.0/24",  # Typical small network
                "192.168.100.0/24",  # Server VLAN
                # Uncomment as you expand:
                # "10.0.0.0/16",       # 65K IPs - OK after testing
                # NEVER: "10.0.0.0/8"  # 16.7M IPs - will never finish!
            ],
            "passive_sniff_duration": 300,
            "arp_batch_size": 16,
            "arp_batch_delay": 5.0,
            # Wave-based processing for large networks
            "wave_enabled": True,
            "wave_size": 1000,  # Subnets per wave
            "wave_delay_seconds": 10,
        },
        "scanner": {
            "mode": "two_phase",  # Options: nmap_only, two_phase
            "naabu": {
                "rate": 5000,
                "threads": 50,
            },
            "nmap": {
                "phase2_only": True,  # Only scan ports discovered by naabu
                "version_detection": True,
                "os_detection": True,
                "scripts": True,
                "timing": "T3",  # Polite timing for stealth
            },
            "ports": {
                "quick": [22, 80, 443, 445, 3389],
                "standard": [
                    22,
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
                    3306,
                    3389,
                    5432,
                    5985,
                    5986,
                    8080,
                    8443,
                    9200,
                ],
                "full": [
                    21,
                    22,
                    23,
                    25,
                    53,
                    80,
                    88,
                    110,
                    111,
                    135,
                    139,
                    143,
                    389,
                    443,
                    445,
                    465,
                    514,
                    587,
                    636,
                    993,
                    995,
                    1080,
                    1433,
                    1521,
                    2049,
                    2375,
                    2376,
                    3306,
                    3389,
                    5432,
                    5900,
                    5985,
                    5986,
                    6379,
                    8080,
                    8443,
                    8888,
                    9090,
                    9200,
                    9300,
                    11211,
                    27017,
                ],
            },
            "scan_type": "connect",
            "timeout": 1.5,
            "banner_grab": True,
            "service_detection": True,
        },
        "ml_engine": {
            "model_path": "data/models/",
            "training_interval_hours": 24,
            "anomaly_threshold": 0.7,
            "min_training_samples": 50,
            "features": [
                "port_count_per_host",
                "new_service_detection",
                "port_change_rate",
                "unusual_port_combinations",
                "banner_change_detection",
                "time_pattern_deviation",
            ],
        },
        "nuclei": {
            "binary_path": "nuclei",
            "templates_path": "",
            "update_templates": True,  # Auto-run `nuclei -update-templates` before each scan
            "severity_filter": ["critical", "high"],  # Reduced from 3 levels for speed
            "rate_limit": 15,
            "bulk_size": 10,
            "concurrency": 5,
            "timeout": 15,
            "retries": 1,
            "auto_run": True,
            "run_interval_hours": 12,
            # NEW: Run Nuclei on discovered web hosts immediately
            "run_on_web_hosts": True,  # Trigger when HTTP/HTTPS ports found
            "web_ports": [80, 443, 8080, 8443, 8000, 8888, 9000, 9200],
        },
        "pipeline": {
            # NEW: Wave-based pipeline settings for large networks
            "mode": "wave",  # "sequential" or "wave"
            "wave_size": 1000,  # Hosts per wave
            "wave_delay_seconds": 10,
            "nuclei_on_web_discovery": True,  # Run Nuclei immediately on web hosts
            "parallel_phases": True,  # Scan while discovering next batch
            # Resource limits
            "max_memory_gb": 8.0,
            "stop_on_low_memory": True,
        },
        "parallel_scan": {
            # Parallel discovery + port scanning (enterprise mode)
            # When enabled, port scanning (naabu) starts on batches of hosts
            # as they are discovered, instead of waiting for all discovery to finish.
            # Critical for large networks where discovery alone can take 12+ hours.
            "enabled": False,  # Enable via entp_config.yaml for enterprise
            "batch_size": 100,  # Scan every N newly-discovered hosts
            "scan_interval_sec": 30,  # Check for new hosts every N seconds
            "max_scan_threads": 2,  # Concurrent scan batches (keep low for stealth)
        },
        "dashboard": {
            "host": "127.0.0.1",
            "port": 5000,
            "secret_key": "change-this-in-production",
            "refresh_interval": 30,
        },
        "scheduler": {
            "discovery_interval_hours": 4,
            "scan_interval_hours": 2,
            "ml_training_interval_hours": 24,
            "nuclei_interval_hours": 6,
        },
        "database": {
            "path": "data/hostvigil.db",
        },
    }
}


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override dict into base dict.

    Uses deep copy of base to prevent mutation of the original.
    """
    merged = copy.deepcopy(base)
    for key, value in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


class Config:
    """HostVigil configuration manager."""

    def __init__(self, config_path: str | Path | None = None) -> None:
        self._config_path = self._resolve_config_path(config_path)
        self._lock = threading.Lock()
        self._data = self._load_config()
        # Ensure hostvigil key is a dict (handles `hostvigil: null` in YAML)
        if not isinstance(self._data.get("hostvigil"), dict):
            self._data["hostvigil"] = DEFAULT_CONFIG["hostvigil"].copy()
        self.validate()

    def _resolve_config_path(self, config_path: str | Path | None) -> Path:
        """Resolve the configuration file path."""
        if config_path:
            return Path(config_path)
        # Look relative to the project root (one level up from hostvigil package)
        project_root = Path(__file__).parent.parent
        return project_root / "config.yaml"

    def _load_config(self) -> dict[str, Any]:
        """Load configuration from YAML file, merged with defaults."""
        if self._config_path.exists():
            try:
                with open(self._config_path, "r", encoding="utf-8") as f:
                    file_config = yaml.safe_load(f) or {}
            except yaml.YAMLError as e:
                import logging

                logging.getLogger("hostvigil").error(
                    f"Failed to parse config file {self._config_path}: {e}. Using defaults."
                )
                return copy.deepcopy(DEFAULT_CONFIG)
            if not isinstance(file_config, dict):
                import logging

                logging.getLogger("hostvigil").error(
                    f"Config file {self._config_path} is not a YAML mapping. Using defaults."
                )
                return copy.deepcopy(DEFAULT_CONFIG)
            return _deep_merge(DEFAULT_CONFIG, file_config)
        return copy.deepcopy(DEFAULT_CONFIG)

    @property
    def hostvigil(self) -> dict[str, Any]:
        """Full 'hostvigil' config section containing all subsections.

        Some modules (e.g. StealthDiscovery, StealthScanner) expect the
        section that contains both 'stealth' and their own subsection, so
        they can resolve stealth-timing plus module-specific settings.
        """
        return self._data["hostvigil"]

    @property
    def stealth(self) -> dict[str, Any]:
        """Stealth configuration section."""
        return self._data["hostvigil"]["stealth"]

    @property
    def discovery(self) -> dict[str, Any]:
        """Discovery configuration section."""
        return self._data["hostvigil"]["discovery"]

    @property
    def scanner(self) -> dict[str, Any]:
        """Scanner configuration section."""
        return self._data["hostvigil"]["scanner"]

    @property
    def ml_engine(self) -> dict[str, Any]:
        """ML engine configuration section."""
        return self._data["hostvigil"]["ml_engine"]

    @property
    def nuclei(self) -> dict[str, Any]:
        """Nuclei configuration section."""
        return self._data["hostvigil"]["nuclei"]

    @property
    def dashboard(self) -> dict[str, Any]:
        """Dashboard configuration section."""
        return self._data["hostvigil"]["dashboard"]

    @property
    def scheduler(self) -> dict[str, Any]:
        """Scheduler configuration section."""
        return self._data["hostvigil"]["scheduler"]

    @property
    def alerting(self) -> dict[str, Any]:
        """Alerting/webhook configuration section with sensible defaults."""
        return self._data["hostvigil"].get(
            "alerting",
            {
                "enabled": False,
                "urls": [],
                "notify_on": [
                    "critical_vuln",
                    "new_host",
                    "high_anomaly",
                    "service_exposed",
                    "ad_finding",
                    "drift_detected",
                ],
                "rate_limit": 60,
                "include_details": True,
            },
        )

    @property
    def database(self) -> dict[str, Any]:
        """Database configuration section."""
        return self._data["hostvigil"]["database"]

    def get(self, *keys: str, default: Any = None) -> Any:
        """Get a nested config value using dot-separated keys.

        Example: config.get('stealth', 'min_delay')
        """
        current = self._data["hostvigil"]
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return default
        return current

    def reload(self) -> None:
        """Reload configuration from disk (thread-safe)."""
        new_data = self._load_config()
        with self._lock:
            self._data = new_data

    def validate(self) -> list[str]:
        """Validate configuration values and log warnings for any issues.

        Returns a list of error message strings. Does NOT raise exceptions.
        """
        logger = logging.getLogger("hostvigil")
        errors: list[str] = []

        # --- Stealth checks ---
        stealth = self.stealth
        min_delay = stealth.get("min_delay", 0)
        max_delay = stealth.get("max_delay", 0)

        if not isinstance(min_delay, (int, float)) or min_delay <= 0:
            errors.append(f"stealth.min_delay must be > 0, got {min_delay!r}")
        if not isinstance(max_delay, (int, float)) or max_delay <= 0:
            errors.append(f"stealth.max_delay must be > 0, got {max_delay!r}")
        if (
            isinstance(min_delay, (int, float))
            and isinstance(max_delay, (int, float))
            and min_delay > 0
            and max_delay > 0
            and min_delay >= max_delay
        ):
            errors.append(f"stealth.min_delay ({min_delay}) must be < stealth.max_delay ({max_delay})")

        jitter = stealth.get("jitter_factor", 0)
        if not isinstance(jitter, (int, float)) or not (0 <= jitter <= 1):
            errors.append(f"stealth.jitter_factor must be between 0 and 1, got {jitter!r}")

        max_threads = stealth.get("max_threads", 0)
        if not isinstance(max_threads, (int, float)) or max_threads <= 0:
            errors.append(f"stealth.max_threads must be > 0, got {max_threads!r}")

        # --- Dashboard checks ---
        dashboard = self.dashboard
        port = dashboard.get("port", 0)
        if not isinstance(port, int) or not (1 <= port <= 65535):
            errors.append(f"dashboard.port must be an integer in range 1-65535, got {port!r}")

        # --- Discovery checks ---
        discovery = self.discovery
        target_ranges = discovery.get("target_ranges", [])

        if not isinstance(target_ranges, list) or len(target_ranges) == 0:
            errors.append("discovery.target_ranges must be a non-empty list")
        else:
            for cidr in target_ranges:
                try:
                    ipaddress.ip_network(cidr, strict=False)
                except (ValueError, TypeError) as exc:
                    errors.append(f"discovery.target_ranges: invalid CIDR '{cidr}': {exc}")

        # --- Scanner checks ---
        scanner = self.scanner
        valid_profiles = ("quick", "standard", "full", "top1000")
        port_profile = scanner.get("port_profile", "standard")
        if port_profile not in valid_profiles:
            errors.append(f"scanner.port_profile must be one of {valid_profiles}, got {port_profile!r}")

        valid_scan_types = ("connect", "syn")
        scan_type = scanner.get("scan_type", "connect")
        if scan_type not in valid_scan_types:
            errors.append(f"scanner.scan_type must be one of {valid_scan_types}, got {scan_type!r}")

        # --- Scheduler checks ---
        scheduler = self.scheduler
        scheduler_keys = [
            "discovery_interval_hours",
            "scan_interval_hours",
            "ml_training_interval_hours",
            "nuclei_interval_hours",
        ]
        for key in scheduler_keys:
            value = scheduler.get(key)
            if value is not None and (not isinstance(value, (int, float)) or value <= 0):
                errors.append(f"scheduler.{key} must be a positive number, got {value!r}")

        # Log all warnings
        if errors:
            for err in errors:
                logger.warning(f"Config validation: {err}")

        return errors

    def validate_scale(self) -> list[str]:
        """Return warnings/errors for enterprise-scale misconfigurations.

        Called by 'python run.py doctor --verbose' and on orchestrator init.
        """
        warnings = []
        discovery_cfg = self.hostvigil.get("discovery", {})
        scanner_cfg = self.hostvigil.get("scanner", {})
        stealth_cfg = self.hostvigil.get("stealth", {})
        os_fp_cfg = self.hostvigil.get("os_fingerprint", {})
        parallel_cfg = self.hostvigil.get("parallel_scan", {})

        # Estimate total hosts from target ranges
        total_hosts = 0
        for cidr in discovery_cfg.get("target_ranges", []):
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                if net.version == 4:
                    total_hosts += net.num_addresses
            except ValueError:
                pass

        is_enterprise = total_hosts > 5000

        if not is_enterprise:
            return warnings

        port_profile = scanner_cfg.get("port_profile", "standard")
        if port_profile == "standard" and total_hosts > 50000:
            warnings.append(
                f"port_profile='{port_profile}' with {total_hosts:,} est. hosts — "
                f"use 'quick' for daemon passes (19 ports × {total_hosts:,} = naabu overhead)"
            )
        if port_profile == "full" and total_hosts > 10000:
            warnings.append(
                f"port_profile='full' with {total_hosts:,} hosts — "
                f"42 ports × {total_hosts:,} = unsustainable for daemon cycles"
            )

        if os_fp_cfg.get("enabled", True) and os_fp_cfg.get("active_probing", True) and total_hosts > 5000:
            warnings.append(
                f"os_fingerprint.active_probing=true with {total_hosts:,} hosts — "
                f"active TCP probes will take days; set active_probing=false or disable os_fingerprint"
            )
        elif os_fp_cfg.get("enabled", True) and total_hosts > 50000:
            warnings.append(
                f"os_fingerprint enabled with {total_hosts:,} hosts — "
                f"passive-only scanning still serializes per-host delays (~3 days); consider disabling"
            )

        scan_mode = scanner_cfg.get("mode", "two_phase")
        if scan_mode == "nmap_only" and total_hosts > 5000:
            warnings.append(
                f"scanner.mode='nmap_only' with {total_hosts:,} hosts — "
                f"custom scanner with stealth delays will take weeks; use 'two_phase' for naabu"
            )

        if not parallel_cfg.get("enabled", False) and total_hosts > 50000:
            warnings.append(
                f"parallel_scan disabled with {total_hosts:,} hosts — "
                f"port scanning won't start until discovery completes (hours delay)"
            )

        min_delay = stealth_cfg.get("min_delay", 10.0)
        if min_delay > 2.0 and total_hosts > 50000:
            warnings.append(
                f"stealth.min_delay={min_delay}s with {total_hosts:,} hosts — "
                f"inter-host delays will dominate cycle time; consider <= 2.0s"
            )

        return warnings

    def __repr__(self) -> str:
        return f"Config(path={self._config_path})"


# Module-level singleton for convenience
_config_instance: Config | None = None
_config_lock = threading.Lock()


def get_config(config_path: str | Path | None = None) -> Config:
    """Get or create the global Config singleton."""
    global _config_instance
    if _config_instance is None:
        with _config_lock:
            # Double-checked locking pattern
            if _config_instance is None:
                _config_instance = Config(config_path)
    return _config_instance
