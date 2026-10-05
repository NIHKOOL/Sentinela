import time
import requests
from datetime import datetime, timezone

API_URL = "http://127.0.0.1:8000/api/v1/ingest"

def send_event(payload: dict):
    try:
        response = requests.post(API_URL, json=payload, timeout=5)
        print(f"Status: {response.status_code} | Response: {response.json()}")
    except requests.exceptions.ConnectionError:
        print("[-] Connection failed. Is the server running on port 8000?")

print("=== 1. Sending Benign Event (notepad.exe) ===")
benign_event = {
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "hostname": "laptop-victim",
    "event_type": "process_creation",
    "user": "alice",
    "process_name": "notepad.exe",
    "command_line": "notepad.exe report.txt"
}
send_event(benign_event)

time.sleep(1)

print("\n=== 2. Sending Suspicious Event (whoami.exe) ===")
malicious_event = {
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "hostname": "laptop-victim",
    "event_type": "process_creation",
    "user": "alice",
    "process_name": "whoami.exe",
    "command_line": "whoami /all"
}
send_event(malicious_event)