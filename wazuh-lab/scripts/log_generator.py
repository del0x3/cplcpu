#!/usr/bin/env python3
"""
Wazuh Lab - High-Volume Log Generator
Generates various types of sample logs for testing Filebeat -> Wazuh Indexer pipeline
Supports configurable log rates for speed testing
"""

import json
import random
import time
import os
import sys
import signal
import threading
from datetime import datetime
from pathlib import Path
from collections import deque

# Configuration from environment
LOG_RATE = int(os.getenv('LOG_RATE', '100'))  # logs per second
BURST_MODE = os.getenv('BURST_MODE', 'false').lower() == 'true'
BURST_SIZE = int(os.getenv('BURST_SIZE', '10000'))  # logs per burst
BURST_INTERVAL = int(os.getenv('BURST_INTERVAL', '60'))  # seconds between bursts

# Log directories
LOG_BASE = Path("/var/log/app")
ALERTS_DIR = LOG_BASE / "alerts"
SECURITY_DIR = LOG_BASE / "security"
METRICS_DIR = LOG_BASE / "metrics"
APP_DIR = LOG_BASE

# Ensure directories exist
for d in [ALERTS_DIR, SECURITY_DIR, METRICS_DIR, APP_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# Sample data pools (expanded for variety)
USERNAMES = [
    "admin", "john.doe", "jane.smith", "root", "guest", "operator",
    "service_account", "backup_user", "monitor", "deploy", "jenkins",
    "gitlab-runner", "prometheus", "grafana", "elastic", "wazuh"
]

IP_ADDRESSES = [
    "192.168.1.100", "192.168.1.101", "192.168.1.102", "192.168.1.103",
    "10.0.0.50", "10.0.0.51", "10.0.0.52", "10.0.1.10", "10.0.1.11",
    "172.16.0.10", "172.16.0.11", "172.16.1.50", "172.17.0.2",
    "203.0.113.50", "203.0.113.51", "198.51.100.25", "192.0.2.100",
    "8.8.8.8", "1.1.1.1", "9.9.9.9"
]

HOSTNAMES = [
    "web-server-01", "web-server-02", "db-server-01", "db-server-02",
    "app-server-01", "app-server-02", "cache-server-01", "worker-01",
    "worker-02", "api-gateway-01", "load-balancer-01", "monitoring-01"
]

ACTIONS = [
    "login", "logout", "file_read", "file_write", "file_delete",
    "config_change", "permission_change", "process_start", "process_stop",
    "network_connect", "network_disconnect", "database_query", "api_call"
]

# Wazuh rule definitions (expanded)
WAZUH_RULES = {
    # PAM rules
    5501: {"desc": "PAM: Login session opened", "level": 3, "groups": ["pam", "authentication"]},
    5502: {"desc": "PAM: Login session closed", "level": 3, "groups": ["pam", "authentication"]},
    5503: {"desc": "PAM: User login failed", "level": 5, "groups": ["pam", "authentication", "authentication_failed"]},
    5504: {"desc": "PAM: User authentication failure", "level": 5, "groups": ["pam", "authentication_failed"]},

    # SSH rules
    5710: {"desc": "SSH: Attempt to login using a non-existent user", "level": 5, "groups": ["sshd", "authentication_failed"]},
    5711: {"desc": "SSH: Maximum authentication attempts exceeded", "level": 10, "groups": ["sshd", "authentication_failed"]},
    5712: {"desc": "SSH: Possible SSH brute force attack", "level": 10, "groups": ["sshd", "authentication_failed", "attack"]},
    5715: {"desc": "SSH: Multiple failed login attempts", "level": 10, "groups": ["sshd", "authentication_failed"]},
    5716: {"desc": "SSH: User successfully logged in", "level": 3, "groups": ["sshd", "authentication_success"]},

    # Firewall rules
    5901: {"desc": "Firewall: Drop action detected", "level": 5, "groups": ["firewall", "network"]},
    5902: {"desc": "Firewall: Reject action detected", "level": 5, "groups": ["firewall", "network"]},
    5903: {"desc": "Firewall: Accept action from suspicious source", "level": 7, "groups": ["firewall", "network"]},

    # Web attack rules
    31100: {"desc": "Web server: Access to suspicious file", "level": 6, "groups": ["web", "attack"]},
    31101: {"desc": "Web server: SQL injection attempt", "level": 12, "groups": ["web", "attack", "sql_injection"]},
    31102: {"desc": "Web server: XSS attack attempt", "level": 12, "groups": ["web", "attack", "xss"]},
    31103: {"desc": "Web server: Directory traversal attempt", "level": 10, "groups": ["web", "attack"]},
    31104: {"desc": "Web server: Command injection attempt", "level": 12, "groups": ["web", "attack"]},
    31105: {"desc": "Web server: Suspicious user agent", "level": 6, "groups": ["web", "recon"]},

    # System rules
    5100: {"desc": "System: Successful sudo command", "level": 3, "groups": ["sudo", "syslog"]},
    5101: {"desc": "System: Failed sudo command", "level": 5, "groups": ["sudo", "syslog", "authentication_failed"]},
    5402: {"desc": "System: User account created", "level": 8, "groups": ["syslog", "account_changed"]},
    5403: {"desc": "System: User account deleted", "level": 8, "groups": ["syslog", "account_changed"]},
    5404: {"desc": "System: Group membership changed", "level": 8, "groups": ["syslog", "account_changed"]},

    # File integrity
    550: {"desc": "FIM: Integrity checksum changed", "level": 7, "groups": ["syscheck", "fim"]},
    551: {"desc": "FIM: File added to the system", "level": 5, "groups": ["syscheck", "fim"]},
    552: {"desc": "FIM: File deleted from the system", "level": 7, "groups": ["syscheck", "fim"]},
    553: {"desc": "FIM: File modified in the system", "level": 7, "groups": ["syscheck", "fim"]},
}

RULE_IDS = list(WAZUH_RULES.keys())
LOG_LEVELS = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]

# Performance tracking
stats = {
    'generated': 0,
    'start_time': None,
    'last_report': None
}
stats_lock = threading.Lock()

running = True

def signal_handler(sig, frame):
    global running
    print("\nShutting down gracefully...")
    running = False

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


def generate_wazuh_alert():
    """Generate a Wazuh-style alert in JSON format"""
    rule_id = random.choice(RULE_IDS)
    rule_info = WAZUH_RULES[rule_id]
    timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    alert = {
        "timestamp": timestamp,
        "rule": {
            "level": rule_info["level"],
            "description": rule_info["desc"],
            "id": str(rule_id),
            "firedtimes": random.randint(1, 1000),
            "mail": rule_info["level"] >= 10,
            "groups": rule_info["groups"]
        },
        "agent": {
            "id": f"{random.randint(1, 100):03d}",
            "name": random.choice(HOSTNAMES),
            "ip": random.choice(IP_ADDRESSES)
        },
        "manager": {
            "name": "wazuh-manager"
        },
        "id": f"{int(time.time())}.{random.randint(10000, 99999)}",
        "full_log": f"Sample log entry for rule {rule_id}: {rule_info['desc']}",
        "decoder": {
            "name": random.choice(["pam", "sshd", "iptables", "apache-errorlog", "syslog", "json"])
        },
        "data": {
            "srcip": random.choice(IP_ADDRESSES),
            "srcport": str(random.randint(1024, 65535)),
            "dstip": random.choice(IP_ADDRESSES),
            "dstport": str(random.choice([22, 80, 443, 3306, 5432, 6379, 9200])),
            "srcuser": random.choice(USERNAMES),
            "protocol": random.choice(["tcp", "udp", "icmp"])
        },
        "location": f"/var/log/{random.choice(['auth.log', 'syslog', 'secure', 'messages', 'apache2/access.log'])}"
    }

    return alert


def generate_security_log():
    """Generate security event log"""
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    action = random.choice(ACTIONS)
    user = random.choice(USERNAMES)
    src_ip = random.choice(IP_ADDRESSES)
    status = random.choice(["success", "failure", "blocked", "allowed", "denied"])

    log_entry = (
        f"{timestamp} security [{LOG_LEVELS[random.randint(1, 4)]}] "
        f"action={action} user={user} src_ip={src_ip} dst_ip={random.choice(IP_ADDRESSES)} "
        f"status={status} host={random.choice(HOSTNAMES)} "
        f"session_id={random.randint(100000, 999999)} "
        f"duration_ms={random.randint(1, 5000)} "
        f"bytes_transferred={random.randint(0, 1000000)}"
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
        "Service degradation detected",
        "New connection established from client",
        "Query executed in acceptable time",
        "Batch processing completed",
        "Websocket connection opened",
        "Message queue consumer started",
        "Scheduled task executed",
        "External API call successful",
        "File upload completed"
    ]

    components = ["main", "worker", "scheduler", "api", "auth", "cache", "db", "queue", "web"]

    log_entry = (
        f"{timestamp} [{level}] "
        f"[{random.choice(components)}] "
        f"{random.choice(messages)} "
        f"(request_id={random.randint(100000, 999999)}, "
        f"latency_ms={random.randint(1, 500)}, "
        f"user={random.choice(USERNAMES)})"
    )

    return log_entry


def generate_metrics_log():
    """Generate metrics log with read/write statistics"""
    timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    metrics = {
        "timestamp": timestamp,
        "host": random.choice(HOSTNAMES),
        "service": random.choice(["api", "database", "cache", "queue", "storage"]),
        "metrics": {
            # I/O Operations
            "read_ops": random.randint(100, 50000),
            "write_ops": random.randint(50, 25000),
            "read_bytes": random.randint(1000000, 500000000),
            "write_bytes": random.randint(500000, 250000000),
            "read_latency_ms": round(random.uniform(0.1, 100.0), 2),
            "write_latency_ms": round(random.uniform(0.5, 200.0), 2),
            "read_latency_p99_ms": round(random.uniform(1.0, 500.0), 2),
            "write_latency_p99_ms": round(random.uniform(2.0, 1000.0), 2),

            # Queue metrics
            "queue_depth": random.randint(0, 1000),
            "queue_wait_ms": round(random.uniform(0, 100.0), 2),

            # Throughput
            "iops_total": random.randint(200, 75000),
            "throughput_mbps": round(random.uniform(10.0, 1000.0), 2),
            "requests_per_second": random.randint(100, 10000),

            # Cache
            "cache_hits": random.randint(1000, 100000),
            "cache_misses": random.randint(10, 10000),
            "cache_hit_ratio": round(random.uniform(0.80, 0.999), 4),

            # Connections
            "active_connections": random.randint(10, 1000),
            "connection_errors": random.randint(0, 10),

            # Errors
            "error_count": random.randint(0, 100),
            "error_rate": round(random.uniform(0.0, 0.05), 4),

            # Resources
            "cpu_percent": round(random.uniform(5.0, 95.0), 1),
            "memory_percent": round(random.uniform(20.0, 85.0), 1),
            "memory_used_mb": random.randint(100, 8000),
            "disk_percent": round(random.uniform(10.0, 90.0), 1),
            "disk_used_gb": random.randint(10, 500),

            # Network
            "network_rx_bytes": random.randint(1000000, 100000000),
            "network_tx_bytes": random.randint(1000000, 100000000),
            "network_rx_packets": random.randint(10000, 1000000),
            "network_tx_packets": random.randint(10000, 1000000)
        }
    }

    return json.dumps(metrics)


def write_batch(alerts_file, security_file, app_file, metrics_file, batch_size):
    """Write a batch of logs"""
    alerts_batch = []
    security_batch = []
    app_batch = []
    metrics_batch = []

    for _ in range(batch_size):
        alerts_batch.append(json.dumps(generate_wazuh_alert()))
        security_batch.append(generate_security_log())
        app_batch.append(generate_app_log())
        metrics_batch.append(generate_metrics_log())

    with open(alerts_file, "a") as f:
        f.write("\n".join(alerts_batch) + "\n")

    with open(security_file, "a") as f:
        f.write("\n".join(security_batch) + "\n")

    with open(app_file, "a") as f:
        f.write("\n".join(app_batch) + "\n")

    with open(metrics_file, "a") as f:
        f.write("\n".join(metrics_batch) + "\n")

    return batch_size * 4


def report_stats():
    """Report generation statistics"""
    with stats_lock:
        if stats['start_time'] is None:
            return

        elapsed = time.time() - stats['start_time']
        rate = stats['generated'] / elapsed if elapsed > 0 else 0
        print(f"[STATS] Generated: {stats['generated']:,} logs | "
              f"Elapsed: {elapsed:.1f}s | "
              f"Rate: {rate:.1f} logs/sec | "
              f"Target: {LOG_RATE * 4} logs/sec")


def write_logs():
    """Main function to continuously write logs"""
    global running

    print(f"Starting log generator...")
    print(f"  Mode: {'BURST' if BURST_MODE else 'CONTINUOUS'}")
    print(f"  Target rate: {LOG_RATE} events/sec per type ({LOG_RATE * 4} total)")
    if BURST_MODE:
        print(f"  Burst size: {BURST_SIZE} events")
        print(f"  Burst interval: {BURST_INTERVAL} seconds")

    # Initialize log files
    alerts_file = ALERTS_DIR / "alerts.json"
    security_file = SECURITY_DIR / "security.log"
    app_file = APP_DIR / "application.log"
    metrics_file = METRICS_DIR / "metrics.log"

    stats['start_time'] = time.time()
    stats['last_report'] = time.time()

    # Calculate timing
    batch_size = min(100, LOG_RATE)  # Write in batches for efficiency
    batches_per_second = LOG_RATE / batch_size
    sleep_time = 1.0 / batches_per_second if batches_per_second > 0 else 1.0

    last_burst = 0

    while running:
        try:
            if BURST_MODE:
                # Burst mode: generate large batch then wait
                current_time = time.time()
                if current_time - last_burst >= BURST_INTERVAL:
                    print(f"[BURST] Generating {BURST_SIZE} events...")
                    count = write_batch(alerts_file, security_file, app_file, metrics_file, BURST_SIZE)
                    with stats_lock:
                        stats['generated'] += count
                    last_burst = current_time
                    print(f"[BURST] Complete!")
                else:
                    time.sleep(1)
            else:
                # Continuous mode: steady rate
                start = time.time()
                count = write_batch(alerts_file, security_file, app_file, metrics_file, batch_size)

                with stats_lock:
                    stats['generated'] += count

                # Sleep to maintain target rate
                elapsed = time.time() - start
                if elapsed < sleep_time:
                    time.sleep(sleep_time - elapsed)

            # Report stats every 10 seconds
            if time.time() - stats['last_report'] >= 10:
                report_stats()
                stats['last_report'] = time.time()

        except Exception as e:
            print(f"Error generating logs: {e}")
            time.sleep(1)

    # Final report
    print("\n[FINAL STATS]")
    report_stats()


if __name__ == "__main__":
    write_logs()
