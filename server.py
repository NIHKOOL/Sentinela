import ntpath
import os
import requests
from datetime import datetime, timezone
from typing import Literal, Optional
from dotenv import load_dotenv
from fastapi import FastAPI
from pydantic import BaseModel, Field

load_dotenv()

app = FastAPI(title="Sentinela SIEM - Minimal Ingestion Core", version="0.1.0")

# Set in .env (see .env.example). Alerts are only printed when this is empty.
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")

EventType = Literal["process_creation", "authentication_failure", "authentication_success"]

# 1. Unified Event Schema (Normalization)
class TelemetryEvent(BaseModel):
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    hostname: str
    event_type: EventType
    user: str
    source_ip: Optional[str] = None
    process_name: Optional[str] = None
    command_line: Optional[str] = None

def normalize_process_name(process_name: str) -> str:
    # "C:\Windows\System32\WHOAMI.EXE" -> "whoami.exe" (ntpath handles both \ and /)
    return ntpath.basename(process_name).lower()

# 2. Rule Matcher (Single-Event Detection Engine)
def evaluate_rules(event: TelemetryEvent) -> list[dict]:
    matches = []

    # Rule 1: Suspicious Reconnaissance / Discovery Process
    suspicious_binaries = ["whoami.exe", "whoami", "mimikatz.exe", "net.exe", "powershell.exe"]
    if event.event_type == "process_creation" and event.process_name:
        process = normalize_process_name(event.process_name)
        if process in suspicious_binaries:
            matches.append({
                "rule_id": "SENTINELA-RULE-001",
                "rule_name": "Discovery: Suspicious Process Execution",
                "severity": "HIGH",
                "mitre_id": "T1059 / T1033",
                "details": f"Process '{process}' executed by user '{event.user}'."
            })

    # Rule 2: Root/Privileged Authentication Failure
    if event.event_type == "authentication_failure" and event.user.lower() in ["root", "administrator"]:
        source = event.source_ip or "an unknown source"
        matches.append({
            "rule_id": "SENTINELA-RULE-002",
            "rule_name": "Credential Access: Privileged Auth Failure",
            "severity": "MEDIUM",
            "mitre_id": "T1110",
            "details": f"Failed logon detected for privileged account '{event.user}' from {source}."
        })

    return matches

# 3. Alert Dispatcher (Discord Webhook)
def dispatch_alert(alert_meta: dict, event: TelemetryEvent):
    if not DISCORD_WEBHOOK_URL:
        print(f"[!] Alert triggered but Webhook URL is not configured: {alert_meta['rule_name']}")
        return

    color = 15158332 if alert_meta["severity"] == "HIGH" else 15105570  # Red or Orange

    payload = {
        "embeds": [
            {
                "title": f"🚨 [{alert_meta['severity']}] {alert_meta['rule_name']}",
                "color": color,
                "fields": [
                    {"name": "Rule ID", "value": alert_meta["rule_id"], "inline": True},
                    {"name": "MITRE ATT&CK", "value": alert_meta["mitre_id"], "inline": True},
                    {"name": "Hostname", "value": event.hostname, "inline": True},
                    {"name": "User", "value": event.user, "inline": True},
                    {"name": "Details", "value": alert_meta["details"], "inline": False},
                    {"name": "Timestamp (UTC)", "value": event.timestamp.isoformat(), "inline": False}
                ],
                "footer": {"text": "Sentinela Minimal Ingestion Pipeline"}
            }
        ]
    }

    try:
        response = requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=5)
        response.raise_for_status()
    except Exception as e:
        print(f"[-] Failed to dispatch webhook: {e}")

# 4. API Endpoints
@app.get("/health")
def health_check():
    return {"status": "online", "engine": "Sentinela Core"}

@app.post("/api/v1/ingest")
def ingest_event(event: TelemetryEvent):
    print(f"[*] Ingested event from {event.hostname} ({event.event_type}): {event.process_name or event.user}")

    # Run detection
    matched_rules = evaluate_rules(event)

    for rule in matched_rules:
        print(f"[!] MATCH: {rule['rule_name']} (Severity: {rule['severity']})")
        dispatch_alert(rule, event)

    return {
        "status": "processed",
        "alert_triggered": bool(matched_rules),
        "rules": [rule["rule_id"] for rule in matched_rules],
    }
