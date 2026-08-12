"""
Webhook Alerting Module - Real-time notifications for critical security events.

Sends notifications to Slack, Discord, Telegram, or generic webhooks when
critical events are detected during stealth reconnaissance.

Supported event types:
- critical_vuln: Critical/high severity vulnerability found
- new_host: Previously unseen host discovered
- high_anomaly: ML engine detected high-confidence anomaly
- service_exposed: Dangerous service exposed without auth
- ad_finding: Privileged AD misconfiguration found
- drift_detected: Significant network change detected

No external dependencies — uses urllib.request for HTTP POST.
"""

import json
import logging
import sqlite3
import threading
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Dict, List

logger = logging.getLogger("hostvigil.alerting")

# Default events to notify on
DEFAULT_NOTIFY_EVENTS = [
    "critical_vuln",
    "new_host",
    "high_anomaly",
    "service_exposed",
    "ad_finding",
    "drift_detected",
]

# Severity color maps
SLACK_COLORS = {
    "critical": "#ff0000",
    "high": "#ff6600",
    "medium": "#ffaa00",
    "low": "#00cc00",
    "info": "#0066ff",
}

DISCORD_COLORS = {
    "critical": 16711680,  # Red
    "high": 16744448,  # Orange
    "medium": 16755200,  # Yellow-orange
    "low": 52224,  # Green
    "info": 26367,  # Blue
}

TELEGRAM_EMOJI = {
    "critical": "\U0001f6a8",  # 🚨
    "high": "\u26a0\ufe0f",  # ⚠️
    "medium": "\U0001f4cb",  # 📋
    "low": "\u2139\ufe0f",  # ℹ️
    "info": "\U0001f4cc",  # 📌
}


class WebhookAlerter:
    """Send webhook notifications for critical HostVigil events."""

    def __init__(self, config: dict, db_path: str):
        """Initialize the alerter.

        Args:
            config: Alerting configuration dict with keys:
                - enabled (bool): Master switch for alerting
                - urls (list): Webhook URLs
                - notify_on (list): Event types to notify on
                - rate_limit (int): Min seconds between same-type alerts
                - include_details (bool): Include extra context in messages
            db_path: Path to the SQLite database.
        """
        self.enabled = config.get("enabled", False)
        self.urls = config.get("urls", [])
        self.notify_on = config.get("notify_on", DEFAULT_NOTIFY_EVENTS)
        self.rate_limit = config.get("rate_limit", 60)
        self.include_details = config.get("include_details", True)
        self.db_path = db_path
        self._last_sent: Dict[str, float] = {}
        self._lock = threading.Lock()
        self._ensure_table()

    def _ensure_table(self):
        """Create alert_history table for tracking sent notifications."""
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute("""CREATE TABLE IF NOT EXISTS alert_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                title TEXT NOT NULL,
                message TEXT,
                severity TEXT NOT NULL DEFAULT 'info',
                webhook_count INTEGER DEFAULT 0,
                sent_at TEXT NOT NULL
            )""")
            conn.execute("""CREATE INDEX IF NOT EXISTS idx_alert_history_type
                ON alert_history(event_type, sent_at)""")
            conn.commit()
        except Exception as e:
            logger.warning(f"Failed to create alert_history table: {e}")
        finally:
            if conn:
                conn.close()

    def notify(self, event_type: str, title: str, message: str, severity: str = "info", extra: dict = None):
        """Send notification to all configured webhooks.

        Args:
            event_type: Category of event (must be in notify_on list).
            title: Short summary title.
            message: Detailed message body.
            severity: One of 'critical', 'high', 'medium', 'low', 'info'.
            extra: Additional context data to include.
        """
        if not self.enabled or not self.urls:
            return

        if event_type not in self.notify_on:
            logger.debug(f"Event type '{event_type}' not in notify_on list, skipping")
            return

        # Rate limiting
        if not self._check_rate_limit(event_type):
            logger.debug(f"Rate limited: {event_type}")
            return

        success_count = 0
        for url in self.urls:
            try:
                self._send(url, title, message, severity, extra)
                success_count += 1
            except Exception as e:
                logger.warning(f"Failed to send webhook to {url[:40]}...: {e}")

        # Record in history
        self._record_alert(event_type, title, message, severity, success_count)

        logger.info(
            f"Alert sent: [{severity.upper()}] {event_type} - {title} ({success_count}/{len(self.urls)} webhooks)"
        )

    def notify_async(self, event_type: str, title: str, message: str, severity: str = "info", extra: dict = None):
        """Send notification asynchronously to avoid blocking scan pipeline."""
        if not self.enabled or not self.urls:
            return
        thread = threading.Thread(
            target=self.notify,
            args=(event_type, title, message, severity, extra),
            daemon=True,
        )
        thread.start()

    def _check_rate_limit(self, event_type: str) -> bool:
        """Check if enough time has passed since last alert of this type."""
        with self._lock:
            now = datetime.now(timezone.utc).timestamp()
            last = self._last_sent.get(event_type, 0)
            if now - last < self.rate_limit:
                return False
            self._last_sent[event_type] = now
            return True

    def _send(self, url: str, title: str, message: str, severity: str, extra: dict = None):
        """Detect webhook type from URL and send appropriately."""
        url_lower = url.lower()

        if "discord.com/api/webhooks" in url_lower or "discordapp.com/api/webhooks" in url_lower:
            self._send_discord(url, title, message, severity, extra)
        elif "hooks.slack.com" in url_lower or "slack.com/api" in url_lower:
            self._send_slack(url, title, message, severity, extra)
        elif "api.telegram.org" in url_lower:
            self._send_telegram(url, title, message, severity, extra)
        else:
            self._send_generic(url, title, message, severity, extra)

    def _send_slack(self, url: str, title: str, message: str, severity: str, extra: dict = None):
        """Send Slack incoming webhook notification."""
        color = SLACK_COLORS.get(severity, SLACK_COLORS["info"])

        fields = []
        if extra and self.include_details:
            for key, value in extra.items():
                fields.append(
                    {
                        "title": key.replace("_", " ").title(),
                        "value": str(value)[:200],
                        "short": len(str(value)) < 40,
                    }
                )

        attachment = {
            "color": color,
            "title": f"\U0001f514 HostVigil: {title}",
            "text": message,
            "footer": "HostVigil Stealth Recon",
            "ts": int(datetime.now(timezone.utc).timestamp()),
        }
        if fields:
            attachment["fields"] = fields[:10]  # Slack limit

        payload = {"attachments": [attachment]}
        self._post_json(url, payload)

    def _send_discord(self, url: str, title: str, message: str, severity: str, extra: dict = None):
        """Send Discord webhook notification with embed."""
        color = DISCORD_COLORS.get(severity, DISCORD_COLORS["info"])

        fields = []
        if extra and self.include_details:
            for key, value in extra.items():
                fields.append(
                    {
                        "name": key.replace("_", " ").title(),
                        "value": str(value)[:200],
                        "inline": len(str(value)) < 40,
                    }
                )

        embed = {
            "title": f"\U0001f514 HostVigil: {title}",
            "description": message[:2048],  # Discord limit
            "color": color,
            "footer": {"text": "HostVigil Stealth Recon"},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        if fields:
            embed["fields"] = fields[:25]  # Discord limit

        payload = {"embeds": [embed]}
        self._post_json(url, payload)

    def _send_telegram(self, url: str, title: str, message: str, severity: str, extra: dict = None):
        """Send Telegram bot API notification.

        URL format: https://api.telegram.org/bot<TOKEN>/sendMessage?chat_id=<CHAT_ID>
        """
        emoji = TELEGRAM_EMOJI.get(severity, TELEGRAM_EMOJI["info"])

        text_parts = [
            f"{emoji} *HostVigil: {self._escape_markdown(title)}*",
            "",
            self._escape_markdown(message),
        ]

        if extra and self.include_details:
            text_parts.append("")
            text_parts.append("*Details:*")
            for key, value in list(extra.items())[:8]:
                text_parts.append(f"\u2022 {self._escape_markdown(key)}: `{str(value)[:100]}`")

        text = "\n".join(text_parts)

        payload = {
            "text": text[:4096],  # Telegram limit
            "parse_mode": "Markdown",
            "disable_web_page_preview": True,
        }

        # Extract chat_id from URL query params and build proper sendMessage URL
        send_url = url
        if "?" in url:
            base_url, query = url.split("?", 1)
            params = dict(p.split("=", 1) for p in query.split("&") if "=" in p)
            if "chat_id" in params:
                payload["chat_id"] = params["chat_id"]
                # Reconstruct URL pointing to /sendMessage endpoint
                # Strip any existing endpoint path if not already /sendMessage
                if "/sendMessage" in base_url:
                    send_url = base_url
                else:
                    send_url = base_url.rstrip("/") + "/sendMessage"
            else:
                # No chat_id in query params — URL must already be complete
                send_url = url
        else:
            # No query string — ensure URL ends with /sendMessage
            if not url.endswith("/sendMessage"):
                send_url = url.rstrip("/") + "/sendMessage"

        if "chat_id" not in payload:
            logger.warning("Telegram webhook missing chat_id — message may fail")

        self._post_json(send_url, payload)

    def _send_generic(self, url: str, title: str, message: str, severity: str, extra: dict = None):
        """Send generic JSON webhook notification."""
        payload = {
            "source": "hostvigil",
            "version": "1.0.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "title": title,
            "message": message,
            "severity": severity,
            "extra": extra or {},
        }
        self._post_json(url, payload)

    def _post_json(self, url: str, payload: dict):
        """Send JSON POST request to webhook URL."""
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "HostVigil/0.1",
            },
            method="POST",
        )
        try:
            response = urllib.request.urlopen(req, timeout=10)
            status = response.getcode()
            if status >= 400:
                logger.warning(f"Webhook returned HTTP {status}: {url[:40]}...")
            else:
                logger.debug(f"Webhook sent successfully to {url[:50]}...")
        except urllib.error.HTTPError as e:
            logger.warning(f"Webhook HTTP error ({e.code}): {url[:40]}... - {e.reason}")
            raise
        except urllib.error.URLError as e:
            logger.warning(f"Webhook URL error: {url[:40]}... - {e.reason}")
            raise
        except Exception as e:
            logger.warning(f"Webhook failed: {url[:40]}... - {e}")
            raise

    def _record_alert(self, event_type: str, title: str, message: str, severity: str, webhook_count: int):
        """Record sent alert in database for history tracking."""
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute(
                "INSERT INTO alert_history (event_type, title, message, severity, webhook_count, sent_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (event_type, title, message[:500], severity, webhook_count, datetime.now(timezone.utc).isoformat()),
            )
            conn.commit()
        except Exception as e:
            logger.debug(f"Failed to record alert history: {e}")
        finally:
            if conn:
                conn.close()

    def get_alert_history(self, limit: int = 50) -> List[Dict]:
        """Get recent alert history."""
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM alert_history ORDER BY sent_at DESC LIMIT ?", (limit,))
            history = [dict(row) for row in cursor.fetchall()]
            return history
        except Exception as e:
            logger.debug(f"Failed to read alert history: {e}")
            return []
        finally:
            if conn:
                conn.close()

    def get_stats(self) -> Dict:
        """Get alerting statistics."""
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row

            # Total alerts
            total = conn.execute("SELECT COUNT(*) as cnt FROM alert_history").fetchone()["cnt"]

            # By severity
            by_severity = {}
            cursor = conn.execute("SELECT severity, COUNT(*) as cnt FROM alert_history GROUP BY severity")
            for row in cursor:
                by_severity[row["severity"]] = row["cnt"]

            # By event type
            by_type = {}
            cursor = conn.execute("SELECT event_type, COUNT(*) as cnt FROM alert_history GROUP BY event_type")
            for row in cursor:
                by_type[row["event_type"]] = row["cnt"]

            # Last 24h
            cursor = conn.execute("SELECT COUNT(*) as cnt FROM alert_history WHERE sent_at > datetime('now', '-1 day')")
            last_24h = cursor.fetchone()["cnt"]

            return {
                "total_alerts": total,
                "last_24h": last_24h,
                "by_severity": by_severity,
                "by_event_type": by_type,
                "webhooks_configured": len(self.urls),
                "enabled": self.enabled,
            }
        except Exception as e:
            logger.debug(f"Failed to get alert stats: {e}")
            return {"total_alerts": 0, "enabled": self.enabled}
        finally:
            if conn:
                conn.close()

    @staticmethod
    def _escape_markdown(text: str) -> str:
        """Escape Telegram Markdown special characters."""
        # Telegram Markdown v1 special chars: _ * ` [
        for char in ("_", "*", "`", "["):
            text = text.replace(char, f"\\{char}")
        return text

    def test_webhook(self, url: str = None) -> Dict:
        """Send a test notification to verify webhook configuration.

        Args:
            url: Specific URL to test, or None to test all configured URLs.

        Returns:
            Dict with success status per URL.
        """
        test_urls = [url] if url else self.urls
        results = {}

        for webhook_url in test_urls:
            try:
                self._send(
                    webhook_url,
                    title="Test Notification",
                    message="This is a test alert from HostVigil. "
                    "If you see this, webhook integration is working correctly.",
                    severity="info",
                    extra={"test": True, "timestamp": datetime.now(timezone.utc).isoformat()},
                )
                results[webhook_url[:50]] = {"success": True}
            except Exception as e:
                results[webhook_url[:50]] = {"success": False, "error": str(e)}

        return results
