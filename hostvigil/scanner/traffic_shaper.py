"""
HostVigil Traffic Shaper - Stealth Network Operations

Mimics normal network traffic patterns to avoid detection.
"""

import logging
import random
from datetime import datetime, timedelta
from typing import Optional, Tuple

logger = logging.getLogger("hostvigil.stealth")


class StealthTrafficShaper:
    """
    Shapes network traffic to blend with normal patterns.

    Profiles:
    - business_hours: Frequent, small delays (looks like user traffic)
    - after_hours: Infrequent, long delays (background tasks)
    - web_server: Exponential distribution (HTTP-like)
    - background: Very slow, irregular (updates, backups)
    - custom: User-defined parameters
    """

    def __init__(self, profile: str = "business_hours"):
        self.profile = profile
        self.last_action_time = datetime.now()
        self.actions_count = 0
        self.session_start = datetime.now()

        # Profile configurations
        self.profiles = {
            "business_hours": {
                "min_delay": 0.5,
                "max_delay": 2.0,
                "pause_chance": 0.05,
                "pause_duration": (30, 300),
                "batch_size_range": (5, 25),
                "active_hours": (9, 17),
            },
            "after_hours": {
                "min_delay": 30.0,
                "max_delay": 300.0,
                "pause_chance": 0.15,
                "pause_duration": (300, 1800),
                "batch_size_range": (1, 5),
                "active_hours": (22, 6),
            },
            "web_server": {
                "min_delay": 0.1,
                "max_delay": 10.0,
                "distribution": "exponential",
                "lambda_param": 0.1,
                "pause_chance": 0.02,
                "batch_size_range": (10, 100),
            },
            "background": {
                "min_delay": 60.0,
                "max_delay": 600.0,
                "pause_chance": 0.20,
                "pause_duration": (600, 3600),
                "batch_size_range": (1, 3),
            },
            "ghost": {
                # Maximum stealth - one action per minute average
                "min_delay": 30.0,
                "max_delay": 120.0,
                "pause_chance": 0.25,
                "pause_duration": (600, 3600),
                "batch_size_range": (1, 2),
            },
        }

    def get_delay(self) -> float:
        """
        Calculate delay before next action.

        Returns delay in seconds that mimics normal traffic for current profile.
        """
        config = self.profiles.get(self.profile, self.profiles["business_hours"])

        # Check if currently in active hours
        current_hour = datetime.now().hour
        active_start, active_end = config.get("active_hours", (0, 24))

        if active_start < active_end:
            # Normal range (e.g., 9-17)
            is_active_time = active_start <= current_hour < active_end
        else:
            # Overnight range (e.g., 22-6)
            is_active_time = current_hour >= active_start or current_hour < active_end

        # Adjust delays based on time
        if not is_active_time and "active_hours" in config:
            # Outside active hours - use much longer delays
            delay = random.uniform(config["min_delay"] * 10, config["max_delay"] * 10)
        else:
            # Generate delay based on distribution
            if config.get("distribution") == "exponential":
                # Exponential distribution looks like web server traffic
                lambda_param = config.get("lambda_param", 0.1)
                delay = random.expovariate(lambda_param)
            else:
                # Uniform distribution
                delay = random.uniform(config["min_delay"], config["max_delay"])

        self.last_action_time = datetime.now()
        self.actions_count += 1

        return delay

    def should_pause(self) -> Tuple[bool, Optional[int]]:
        """
        Check if should take a longer pause.

        Returns:
            (should_pause: bool, pause_duration: int or None)
        """
        config = self.profiles.get(self.profile, self.profiles["business_hours"])

        if random.random() < config.get("pause_chance", 0.05):
            pause_range = config.get("pause_duration", (30, 300))
            pause_duration = random.randint(*pause_range)
            logger.debug(f"Taking random pause: {pause_duration}s")
            return True, pause_duration

        return False, None

    def get_batch_size(self) -> int:
        """Get batch size that avoids detectable patterns."""
        config = self.profiles.get(self.profile, self.profiles["business_hours"])
        batch_range = config.get("batch_size_range", (5, 25))
        return random.randint(*batch_range)

    def mimic_normal_patterns(self):
        """Apply subtle variations to avoid machine detection.

        Note: This method is not called internally by the daemon pipeline.
        It is part of the public API, available for plugins and operator scripts
        that need to shape raw-socket traffic to look like normal user behaviour.
        """
        # Vary TTL slightly
        base_ttl = 64
        ttl_variation = random.randint(-2, 2)
        effective_ttl = base_ttl + ttl_variation

        # Vary source port (if applicable)
        # Common ports that are usually allowed
        allowed_ports = [80, 443, 53, 123, 135, 139, 445]
        source_port = random.choice(allowed_ports) if random.random() < 0.3 else None

        return {"ttl": effective_ttl, "source_port": source_port}

    def get_decayed_delay(
        self,
        base_min: float = None,
        base_max: float = None,
        ramp_hours: float = 24.0,
        max_multiplier: float = 3.0,
    ) -> float:
        """Delay that ramps up as the operation ages (early data > fresh latency).

        Starts near the profile's low end for fast initial coverage, then grows
        towards ``max_multiplier`` once the daemon has been live for ``ramp_hours``.
        Decay avoids a constant cadence that a supervised network could fingerprint.
        """
        config = self.profiles.get(self.profile, self.profiles["business_hours"])
        lo = base_min if base_min is not None else config["min_delay"]
        hi = base_max if base_max is not None else config["max_delay"]

        elapsed_hours = (datetime.now() - self.session_start).total_seconds() / 3600.0
        progress = min(1.0, elapsed_hours / ramp_hours) if ramp_hours > 0 else 1.0

        lo_ramped = lo + (lo * (max_multiplier - 1.0) * progress)
        hi_ramped = hi + (hi * (max_multiplier - 1.0) * progress)
        delay = random.uniform(lo_ramped, hi_ramped)
        self.actions_count += 1
        return delay

    @staticmethod
    def get_decayed_threads(
        base_threads: int,
        ramp_hours: float = 24.0,
        min_threads: int = 1,
        start_time: "datetime" = None,
    ) -> int:
        """Concurrency that tapers off as the operation ages.

        High thread count early (fresh initial coverage) decays toward
        ``min_threads`` over ``ramp_hours`` to low the long-run detection profile.
        """
        start = start_time or datetime.now()
        elapsed_hours = (datetime.now() - start).total_seconds() / 3600.0
        progress = min(1.0, elapsed_hours / ramp_hours) if ramp_hours > 0 else 1.0
        threads = max(min_threads, int(round(base_threads * (1.0 - 0.7 * progress))))
        return threads

    def get_stats(self) -> dict:
        """Get traffic shaping statistics."""
        elapsed = (datetime.now() - self.session_start).total_seconds()
        return {
            "profile": self.profile,
            "session_duration_sec": elapsed,
            "actions_count": self.actions_count,
            "avg_actions_per_minute": (self.actions_count / elapsed * 60) if elapsed > 0 else 0,
            "last_action": self.last_action_time.isoformat(),
        }


class ScanWindowManager:
    """
    Manages when scanning is allowed based on time windows.

    Helps blend scanning into normal business operations or
    conduct operations during low-monitoring periods.
    """

    def __init__(self, config: dict):
        self.config = config
        self.enabled = config.get("scan_window_enabled", False)
        self.window_start = config.get("scan_window_start", 9)  # 9 AM
        self.window_end = config.get("scan_window_end", 17)  # 5 PM
        self.business_days_only = config.get("business_days_only", False)
        self.weekend_only = config.get("weekend_only", False)

    def is_scan_allowed(self) -> Tuple[bool, str]:
        """
        Check if scanning is allowed right now.

        Returns:
            (allowed: bool, reason: str)
        """
        if not self.enabled:
            return True, "Window not enabled"

        now = datetime.now()
        current_hour = now.hour
        current_day = now.weekday()  # 0=Monday, 6=Sunday

        # Check day restrictions
        if self.business_days_only and current_day >= 5:
            return False, "Weekend - business days only configured"

        if self.weekend_only and current_day < 5:
            return False, "Weekday - weekend only configured"

        # Check time window
        if self.window_start <= self.window_end:
            # Normal range (e.g., 9-17)
            in_window = self.window_start <= current_hour < self.window_end
        else:
            # Overnight range (e.g., 22-6)
            in_window = current_hour >= self.window_start or current_hour < self.window_end

        if in_window:
            return True, "Within scan window"
        else:
            return False, f"Outside scan window ({self.window_start}:00-{self.window_end}:00)"

    def get_next_allowed_time(self) -> datetime:
        """Calculate when scanning will be allowed next."""
        now = datetime.now()

        if self.window_start <= self.window_end:
            # Normal range
            if now.hour < self.window_start:
                # Before window starts today
                return now.replace(hour=self.window_start, minute=0, second=0, microsecond=0)
            elif now.hour >= self.window_end:
                # Window closed - next day
                next_day = now + timedelta(days=1)
                return next_day.replace(hour=self.window_start, minute=0, second=0, microsecond=0)
            else:
                # Currently in window
                return now
        else:
            # Overnight range
            if now.hour < self.window_end:
                # Early morning, still in window
                return now
            elif now.hour >= self.window_start:
                # Evening, window just opened
                return now
            else:
                # Middle of day - wait for evening
                return now.replace(hour=self.window_start, minute=0, second=0, microsecond=0)


class AbortConditionChecker:
    """
    Monitors for signs that operation has been detected.

    Checks multiple indicators and recommends abort if detection likely.
    """

    def __init__(self, db_path: str, thresholds: dict = None):
        self.db_path = db_path
        self.thresholds = thresholds or {
            "blocked_scans_per_hour": 10,
            "connection_refused_rate": 0.3,
            "timeout_rate": 0.4,
            "honeypot_count": 1,
            "hosts_vanished": 5,
            "error_rate": 0.25,
        }

    def check_all_conditions(self) -> dict:
        """
        Check all abort conditions.

        Returns:
            {
                'abort': bool,
                'reason': str or None,
                'severity': 'low' | 'medium' | 'high' | 'critical',
                'indicators': list
            }
        """
        import sqlite3

        indicators = []
        severity = "low"

        try:
            conn = sqlite3.connect(self.db_path, timeout=30)

            # Check 1: High block rate (firewall/ACL blocking scanner)
            blocked = self._check_blocked_scans(conn)
            if blocked["triggered"]:
                indicators.append(blocked["indicator"])
                severity = "high" if blocked["rate"] > 0.5 else "medium"

            # Check 2: High timeout rate (IDS inspecting packets)
            timeouts = self._check_timeout_rate(conn)
            if timeouts["triggered"]:
                indicators.append(timeouts["indicator"])
                if severity != "high":
                    severity = "medium"

            # Check 3: Connection refused spike (hosts rejecting scanner IP)
            refused = self._check_refused_rate(conn)
            if refused["triggered"]:
                indicators.append(refused["indicator"])
                severity = "high"

            # Check 4: Honeypot detection
            honeypots = self._check_honeypots(conn)
            if honeypots["triggered"]:
                indicators.append(honeypots["indicator"])
                severity = "critical"

            # Check 5: Hosts disappearing (NAC quarantine)
            vanished = self._check_vanished_hosts(conn)
            if vanished["triggered"]:
                indicators.append(vanished["indicator"])
                severity = "critical"

            conn.close()

        except Exception as e:
            indicators.append(f"Monitor error: {str(e)}")

        abort = len(indicators) > 0 and severity in ["high", "critical"]

        return {
            "abort": abort,
            "reason": "; ".join(indicators) if indicators else None,
            "severity": severity,
            "indicators": indicators,
            "recommendation": self._get_recommendation(severity, abort),
        }

    def _check_blocked_scans(self, conn) -> dict:
        """Check for scans being actively blocked."""
        try:
            cursor = conn.execute("""
                SELECT COUNT(*) as total,
                       SUM(CASE WHEN state='blocked' OR state='filtered' THEN 1 ELSE 0 END) as blocked
                FROM scan_results
                WHERE scanned_at > datetime('now', '-1 hour')
            """)
            row = cursor.fetchone()
            total, blocked = row[0], row[1]

            if total == 0:
                return {"triggered": False}

            rate = blocked / total
            threshold = self.thresholds["blocked_scans_per_hour"] / 100

            return {
                "triggered": rate > threshold,
                "rate": rate,
                "indicator": f"High block rate: {rate * 100:.1f}% ({blocked}/{total})",
            }
        except Exception as e:
            import logging

            logging.warning("Exception suppressed: %s", str(e))
            return {"triggered": False}

    def _check_timeout_rate(self, conn) -> dict:
        """Check for timeouts suggesting IDS inspection."""
        try:
            cursor = conn.execute("""
                SELECT COUNT(*) as total,
                       SUM(CASE WHEN state='timeout' THEN 1 ELSE 0 END) as timeout
                FROM scan_results
                WHERE scanned_at > datetime('now', '-1 hour')
            """)
            row = cursor.fetchone()
            total, timeout = row[0], row[1]

            if total == 0:
                return {"triggered": False}

            rate = timeout / total

            return {
                "triggered": rate > self.thresholds["timeout_rate"],
                "rate": rate,
                "indicator": f"High timeout rate: {rate * 100:.1f}% (possible IDS inspection)",
            }
        except Exception as e:
            import logging

            logging.warning("Exception suppressed: %s", str(e))
            return {"triggered": False}

    def _check_refused_rate(self, conn) -> dict:
        """Check for connection refusals suggesting IP block."""
        try:
            cursor = conn.execute("""
                SELECT COUNT(*) as total,
                       SUM(CASE WHEN state='refused' THEN 1 ELSE 0 END) as refused
                FROM scan_results
                WHERE scanned_at > datetime('now', '-1 hour')
            """)
            row = cursor.fetchone()
            total, refused = row[0], row[1]

            if total == 0:
                return {"triggered": False}

            rate = refused / total

            return {
                "triggered": rate > self.thresholds["connection_refused_rate"],
                "rate": rate,
                "indicator": f"High refusal rate: {rate * 100:.1f}% (scanner IP may be blocked)",
            }
        except Exception as e:
            import logging

            logging.warning("Exception suppressed: %s", str(e))
            return {"triggered": False}

    def _check_honeypots(self, conn) -> dict:
        """Check for honeypot indicators."""
        try:
            # Look for hosts with suspicious port patterns
            cursor = conn.execute("""
                SELECT ip, COUNT(DISTINCT port) as port_count
                FROM ports
                WHERE state = 'open'
                GROUP BY ip
                HAVING port_count > 100
                LIMIT 1
            """)
            row = cursor.fetchone()

            if row:
                return {"triggered": True, "indicator": f"Potential honeypot: {row[0]} with {row[1]} open ports"}

            return {"triggered": False}
        except Exception as e:
            import logging

            logging.warning("Exception suppressed: %s", str(e))
            return {"triggered": False}

    def _check_vanished_hosts(self, conn) -> dict:
        """Check for hosts that suddenly disappeared (NAC quarantine)."""
        try:
            cursor = conn.execute("""
                SELECT COUNT(*) FROM hosts
                WHERE is_active = 1
                AND last_seen < datetime('now', '-1 hour')
                AND last_seen > datetime('now', '-2 hours')
            """)
            count = cursor.fetchone()[0]

            return {
                "triggered": count > self.thresholds["hosts_vanished"],
                "count": count,
                "indicator": f"{count} hosts suddenly went dark (possible NAC quarantine)",
            }
        except Exception as e:
            import logging

            logging.warning("Exception suppressed: %s", str(e))
            return {"triggered": False}

    def _get_recommendation(self, severity: str, abort: bool) -> str:
        """Get human-readable recommendation."""
        if severity == "critical":
            return "🛑 IMMEDIATE ABORT - High confidence of detection"
        elif severity == "high":
            return "⚠️  STRONGLY CONSIDER ABORT - Multiple indicators"
        elif severity == "medium":
            return "⚡ PROCEED WITH CAUTION - Monitor closely"
        else:
            return "✅ Normal operations - continue monitoring"
