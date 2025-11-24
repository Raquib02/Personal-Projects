from os import name
import re
from datetime import datetime

#Path to the system log you want to monitor
LOG_FILE = "/var/log/auth.log"   

#Suspicious patterns to flag
SUSPICIOUS_PATTERNS = {
    "failed_login": r"Failed password",
    "sudo_attempt": r"sudo:.authentication failure",
    "unknown_user": r"Invalid user",
    "root_login": r"session opened for user root",
    "multiple_failed_attempts": r"Failed password.from"
}

#Function to check if a line matches any suspicious pattern
def detect_anomalies(line):
    alerts = []
    for alert_type, pattern in SUSPICIOUS_PATTERNS.items():
        if re.search(pattern, line, re.IGNORECASE):
            alerts.append(alert_type)
    return alerts

#Main function to parse logs
def parse_log():
    flagged_events = []

    try:
        with open(LOG_FILE, "r") as file:
            for line in file:
                anomalies = detect_anomalies(line)
                if anomalies:
                    flagged_events.append({
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "log_entry": line.strip(),
                        "alerts": anomalies
                    })
    except PermissionError:
        print("Permission denied: run script with sudo.")
        return

    return flagged_events

#Send alerts (example: terminal output, email, Teams/Slack webhook, etc.)
def send_alerts(events):
    if not events:
        print("No anomalies detected.")
        return

    print("\n=== SECURITY ALERTS DETECTED ===")
    for e in events:
        print(f"[{e['timestamp']}] ALERT: {', '.join(e['alerts']).upper()}")
        print(f" → Log Entry: {e['log_entry']}\n")

if name == "main":
    events = parse_log()
    send_alerts(events)