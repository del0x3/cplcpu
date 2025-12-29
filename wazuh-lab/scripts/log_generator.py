#!/usr/bin/env python3
"""
Wazuh Lab - Log Generator
Generates various types of sample logs for testing Filebeat -> Wazuh Indexer pipeline
"""

import json
import random
import time
import os
import logging
from datetime import datetime, timedelta
from pathlib import Path

# Log directories
LOG_BASE = Path("/var/log/app")
ALERTS_DIR = LOG_BASE / "alerts"
SECURITY_DIR = LOG_BASE / "security"
METRICS_DIR = LOG_BASE / "metrics"
APP_DIR = LOG_BASE

# Ensure directories exist
for d in [ALERTS_DIR, SECURITY_DIR, METRICS_DIR, APP_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# Sample data
USERNAMES = ["admin", "john.doe", "jane.smith", "root", "guest", "operator", "service_account"]
IP_ADDRESSES = [
    "192.168.1.100", "192.168.1.101", "10.0.0.50", "10.0.0.51",
    "172.16.0.10", "203.0.113.50", "198.51.100.25", "192.0.2.100"
]
HOSTNAMES = ["web-server-01", "db-server-01", "app-server-01", "cache-server-01", "worker-01"]
ACTIONS = ["login", "logout", "file_read", "file_write", "file_delete", "config_change", "permission_change"]
RULE_IDS = [5501, 5502, 5503, 5710, 5711, 5712, 5901, 5902, 31100, 31101, 31102, 31103]
RULE_LEVELS = [3, 5, 7, 9, 10, 12, 15]

WAZUH_RULE_DESCRIPTIONS = {
    5501: "PAM: Login session opened",
    5502: "PAM: Login session closed",
    5503: "PAM: User login failed",
    5710: "SSH: Attempt to login using a non-existent user",
    5711: "SSH: Maximum authentication attempts exceeded",
    5712: "SSH: Possible SSH brute force attack",
    5901: "Firewall: Drop action detected",
    5902: "Firewall: Reject action detected",
    31100: "Web server: Access to suspicious file",
    31101: "Web server: SQL injection attempt",
    31102: "Web server: XSS attack attempt",
    31103: "Web server: Directory traversal attempt"
}

LOG_LEVELS = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]


def generate_wazuh_alert():
    """Generate a Wazuh-style alert in JSON format"""
    rule_id = random.choice(RULE_IDS)
    timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    alert = {
        "timestamp": timestamp,
        "rule": {
            "level": random.choice(RULE_LEVELS),
            "description": WAZUH_RULE_DESCRIPTIONS.get(rule_id, "Unknown rule"),
            "id": str(rule_id),
            "firedtimes": random.randint(1, 100),
            "mail": False,
            "groups": ["syslog", "authentication", random.choice(["pam", "ssh", "firewall", "web"])]
        },
        "agent": {
            "id": f"{random.randint(1, 100):03d}",
            "name": random.choice(HOSTNAMES),
            "ip": random.choice(IP_ADDRESSES)
        },
        "manager": {
            "name": "wazuh-manager"
        },
        "id": f"{int(time.time())}.{random.randint(1000, 9999)}",
        "full_log": f"Sample log entry for rule {rule_id}",
        "decoder": {
            "name": random.choice(["pam", "sshd", "iptables", "apache-errorlog"])
        },
        "data": {
            "srcip": random.choice(IP_ADDRESSES),
            "srcuser": random.choice(USERNAMES),
            "dstuser": random.choice(USERNAMES) if random.random() > 0.5 else None
        },
        "location": f"/var/log/{random.choice(['auth.log', 'syslog', 'secure', 'messages'])}"
    }

    # Remove None values
    alert["data"] = {k: v for k, v in alert["data"].items() if v is not None}

    return alert


def generate_security_log():
    """Generate security event log"""
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    action = random.choice(ACTIONS)
    user = random.choice(USERNAMES)
    src_ip = random.choice(IP_ADDRESSES)
    status = random.choice(["success", "failure", "blocked", "allowed"])

    log_entry = (
        f"{timestamp} security [{LOG_LEVELS[random.randint(1, 4)]}] "
        f"action={action} user={user} src_ip={src_ip} status={status} "
        f"host={random.choice(HOSTNAMES)} session_id={random.randint(10000, 99999)}"
    )

    return log_entry


def generate_app_log():
    """Generate application log"""
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]
    level = random.choice(LOG_LEVELS)

    messages = [
        "Request processed successfully",
        "Database connection established",
        "Cache miss for key user_session",
        "API rate limit check passed",
        "Background job completed",
        "Configuration reloaded",
        "Health check passed",
        "Connection timeout, retrying...",
        "Invalid input received, validation failed",
        "Memory usage threshold exceeded",
        "Disk space warning",
        "Service degradation detected"
    ]

    log_entry = (
        f"{timestamp} [{level}] "
        f"[{random.choice(['main', 'worker', 'scheduler', 'api'])}] "
        f"{random.choice(messages)} "
        f"(request_id={random.randint(100000, 999999)})"
    )

    return log_entry


def generate_metrics_log():
    """Generate metrics log with read/write statistics"""
    timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    metrics = {
        "timestamp": timestamp,
        "host": random.choice(HOSTNAMES),
        "metrics": {
            "read_ops": random.randint(100, 10000),
            "write_ops": random.randint(50, 5000),
            "read_bytes": random.randint(1000000, 100000000),
            "write_bytes": random.randint(500000, 50000000),
            "read_latency_ms": round(random.uniform(0.5, 50.0), 2),
            "write_latency_ms": round(random.uniform(1.0, 100.0), 2),
            "queue_depth": random.randint(0, 100),
            "iops_total": random.randint(200, 15000),
            "throughput_mbps": round(random.uniform(10.0, 500.0), 2),
            "cache_hit_ratio": round(random.uniform(0.7, 0.99), 3),
            "active_connections": random.randint(10, 500),
            "requests_per_second": random.randint(100, 5000),
            "error_rate": round(random.uniform(0.0, 0.05), 4),
            "cpu_percent": round(random.uniform(5.0, 95.0), 1),
            "memory_percent": round(random.uniform(20.0, 85.0), 1),
            "disk_percent": round(random.uniform(10.0, 90.0), 1)
        }
    }

    return json.dumps(metrics)


def write_logs():
    """Main function to continuously write logs"""
    print("Starting log generator...")

    # Initialize log files
    alerts_file = ALERTS_DIR / "alerts.json"
    security_file = SECURITY_DIR / "security.log"
    app_file = APP_DIR / "application.log"
    metrics_file = METRICS_DIR / "metrics.log"

    log_count = 0

    while True:
        try:
            # Generate and write Wazuh alert (JSON)
            alert = generate_wazuh_alert()
            with open(alerts_file, "a") as f:
                f.write(json.dumps(alert) + "\n")

            # Generate and write security log
            security_log = generate_security_log()
            with open(security_file, "a") as f:
                f.write(security_log + "\n")

            # Generate and write application log
            app_log = generate_app_log()
            with open(app_file, "a") as f:
                f.write(app_log + "\n")

            # Generate and write metrics log
            metrics_log = generate_metrics_log()
            with open(metrics_file, "a") as f:
                f.write(metrics_log + "\n")

            log_count += 4

            if log_count % 100 == 0:
                print(f"Generated {log_count} log entries...")

            # Random sleep between 0.5 and 3 seconds
            time.sleep(random.uniform(0.5, 3.0))

        except Exception as e:
            print(f"Error generating logs: {e}")
            time.sleep(5)


if __name__ == "__main__":
    write_logs()
