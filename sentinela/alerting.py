"""Alert notifications (Discord webhook)."""
import threading

import requests

SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
COLORS = {"LOW": 0x95A5A6, "MEDIUM": 0xE67E22, "HIGH": 0xE74C3C, "CRITICAL": 0x8E44AD}


class DiscordNotifier:
    """Sends new alerts at or above `min_severity` to a Discord webhook, in a background thread."""

    def __init__(self, webhook_url: str, min_severity: str = "HIGH"):
        self.webhook_url = webhook_url
        self.min_severity = min_severity.upper() if min_severity.upper() in SEVERITY_ORDER else "HIGH"

    @property
    def configured(self) -> bool:
        return bool(self.webhook_url)

    def __call__(self, alert: dict):
        if not self.configured:
            return
        if SEVERITY_ORDER.index(alert["severity"]) < SEVERITY_ORDER.index(self.min_severity):
            return
        threading.Thread(target=self._post, args=(alert,), daemon=True).start()

    def _post(self, alert: dict):
        payload = {
            "embeds": [
                {
                    "title": f"🚨 [{alert['severity']}] {alert['rule_name']}",
                    "color": COLORS[alert["severity"]],
                    "fields": [
                        {"name": "Rule ID", "value": alert["rule_id"], "inline": True},
                        {"name": "MITRE ATT&CK", "value": alert["mitre"], "inline": True},
                        {"name": "Hostname", "value": alert["hostname"], "inline": True},
                        {"name": "User", "value": alert["user"], "inline": True},
                        {"name": "Details", "value": alert["details"], "inline": False},
                        {"name": "Time (UTC)", "value": alert["first_seen"], "inline": False},
                    ],
                    "footer": {"text": "Sentinela SOC Simulator"},
                }
            ]
        }
        try:
            response = requests.post(self.webhook_url, json=payload, timeout=5)
            response.raise_for_status()
        except Exception as e:
            print(f"[-] Failed to dispatch webhook: {e}")
