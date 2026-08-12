"""
Cron Expression Scheduler for HostVigil.

Supports cron-style scheduling for scan tasks using APScheduler.
Falls back to simple interval-based scheduling if APScheduler is unavailable.

Example config.yaml:
    scheduler:
      cron:
        discovery: '0 */4 * * *'     # Every 4 hours
        scan: '30 */2 * * *'         # Every 2 hours at :30
        ml_analysis: '0 0 * * *'     # Daily at midnight
        nuclei: '0 6 * * 1'          # Every Monday at 6 AM
"""

import logging
import threading
from typing import Callable, Dict

try:
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.cron import CronTrigger

    APSCHEDULER_AVAILABLE = True
except ImportError:
    APSCHEDULER_AVAILABLE = False

logger = logging.getLogger("hostvigil.scheduler")


class CronScheduler:
    """Cron-based task scheduler for HostVigil operations.

    Supports both cron expressions ('0 */4 * * *') and interval-based
    scheduling (hours=4). Uses APScheduler when available, otherwise
    falls back to simple threading timers.
    """

    def __init__(self, config: dict = None):
        self.config = config or {}
        self._scheduler = None
        self._jobs: Dict[str, dict] = {}
        self._fallback_timers: Dict[str, threading.Timer] = {}
        self._running = False
        self._shutdown_event = threading.Event()

        if APSCHEDULER_AVAILABLE:
            self._scheduler = BackgroundScheduler(
                daemon=True,
                job_defaults={
                    "coalesce": True,
                    "max_instances": 1,
                    "misfire_grace_time": 300,
                },
            )
            logger.info("CronScheduler initialized with APScheduler")
        else:
            logger.warning("APScheduler not available - using fallback interval timers")

    def add_cron_job(self, name: str, func: Callable, cron_expr: str, jitter: int = 60) -> bool:
        """Add a job with cron expression scheduling.

        Args:
            name: Unique job name
            func: Callable to execute
            cron_expr: Cron expression (5 fields: min hour dom month dow)
            jitter: Random seconds added to avoid pattern detection

        Returns:
            True if job was added successfully
        """
        if self._scheduler:
            try:
                trigger = CronTrigger.from_crontab(cron_expr)
                self._scheduler.add_job(
                    func,
                    trigger,
                    id=name,
                    name=name,
                    jitter=jitter,
                    replace_existing=True,
                )
                self._jobs[name] = {
                    "type": "cron",
                    "expression": cron_expr,
                    "jitter": jitter,
                }
                logger.info(f"Cron job added: {name} = '{cron_expr}' (jitter={jitter}s)")
                return True
            except Exception as e:
                logger.error(f"Failed to add cron job '{name}': {e}")
                return False
        else:
            # Fallback: parse cron to approximate interval
            interval_hours = self._cron_to_interval(cron_expr)
            return self.add_interval_job(name, func, hours=interval_hours)

    def add_interval_job(self, name: str, func: Callable, hours: float = 1, jitter: int = 60) -> bool:
        """Add a job with interval-based scheduling.

        Args:
            name: Unique job name
            func: Callable to execute
            hours: Interval in hours
            jitter: Random seconds added for stealth
        """
        if self._scheduler:
            try:
                self._scheduler.add_job(
                    func,
                    "interval",
                    hours=hours,
                    id=name,
                    name=name,
                    jitter=jitter,
                    replace_existing=True,
                )
                self._jobs[name] = {
                    "type": "interval",
                    "hours": hours,
                    "jitter": jitter,
                }
                logger.info(f"Interval job added: {name} = every {hours}h (jitter={jitter}s)")
                return True
            except Exception as e:
                logger.error(f"Failed to add interval job '{name}': {e}")
                return False
        else:
            # Fallback: threading timer
            self._jobs[name] = {
                "type": "interval_fallback",
                "hours": hours,
                "func": func,
            }
            if self._running:
                self._start_fallback_timer(name, func, hours)
            return True

    def start(self):
        """Start the scheduler."""
        self._running = True
        self._shutdown_event.clear()

        if self._scheduler:
            self._scheduler.start()
            logger.info(f"Scheduler started with {len(self._jobs)} jobs")
        else:
            # Start all fallback timers
            for name, job in self._jobs.items():
                if job["type"] == "interval_fallback":
                    self._start_fallback_timer(name, job["func"], job["hours"])
            logger.info(f"Fallback scheduler started with {len(self._jobs)} timers")

    def stop(self):
        """Stop the scheduler gracefully."""
        self._running = False
        self._shutdown_event.set()

        if self._scheduler:
            self._scheduler.shutdown(wait=False)
        else:
            for timer in self._fallback_timers.values():
                timer.cancel()
            self._fallback_timers.clear()

        logger.info("Scheduler stopped")

    def get_jobs(self) -> Dict:
        """Get status of all scheduled jobs."""
        jobs_info = {}
        if self._scheduler:
            for job in self._scheduler.get_jobs():
                jobs_info[job.id] = {
                    "name": job.name,
                    "next_run": str(job.next_run_time) if job.next_run_time else None,
                    "trigger": str(job.trigger),
                }
        else:
            jobs_info = {name: info for name, info in self._jobs.items()}
        return jobs_info

    def pause_job(self, name: str):
        """Pause a specific job."""
        if self._scheduler:
            self._scheduler.pause_job(name)
            logger.info(f"Job paused: {name}")

    def resume_job(self, name: str):
        """Resume a paused job."""
        if self._scheduler:
            self._scheduler.resume_job(name)
            logger.info(f"Job resumed: {name}")

    def _start_fallback_timer(self, name: str, func: Callable, hours: float):
        """Start a repeating timer as APScheduler fallback."""
        import random

        def _run():
            if not self._running:
                return
            try:
                func()
            except Exception as e:
                logger.error(f"Fallback job '{name}' failed: {e}")
            # Reschedule (jitter is applied per-cycle below)
            if self._running:
                self._start_fallback_timer(name, func, hours)

        # Apply ±5 min jitter to every interval so fallback runs are not
        # perfectly periodic (preserves stealth timing). Floor at 60s to
        # avoid negative/near-zero intervals for sub-hourly jobs.
        jitter = random.uniform(-300, 300)
        interval = max(60.0, hours * 3600 + jitter)
        timer = threading.Timer(interval, _run)
        timer.daemon = True
        timer.start()
        self._fallback_timers[name] = timer

    @staticmethod
    def _cron_to_interval(cron_expr: str) -> float:
        """Approximate a cron expression as an interval in hours.

        Very basic parsing for fallback mode.
        """
        parts = cron_expr.strip().split()
        if len(parts) != 5:
            return 4.0  # Default

        minute, hour, dom, month, dow = parts

        # '*/N' in hour field → every N hours
        if hour.startswith("*/"):
            try:
                return float(hour[2:])
            except ValueError:
                pass

        # '*/N' in minute field → every N minutes
        if minute.startswith("*/"):
            try:
                return float(minute[2:]) / 60.0
            except ValueError:
                pass

        # Specific hour → once per day
        if hour.isdigit():
            return 24.0

        return 4.0  # Default fallback
