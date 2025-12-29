#!/usr/bin/env python3
"""
5GB Log Generator for Wazuh Agent
Generates realistic security logs for testing Wazuh agent log collection
"""

import os
import sys
import json
import time
import random
import string
from datetime import datetime, timedelta

try:
    from tqdm import tqdm
except ImportError:
    # Simple fallback if tqdm not available
    def tqdm(iterable, **kwargs):
        total = kwargs.get('total', 0)
        desc = kwargs.get('desc', '')
        for i, item in enumerate(iterable):
            if i % 10000 == 0:
                print(f"{desc}: {i}/{total} ({100*i/total:.1f}%)")
            yield item

# Configuration from environment
TARGET_SIZE_GB = float(os.environ.get('TARGET_SIZE_GB', '5'))
LOG_TYPE = os.environ.get('LOG_TYPE', 'security')
BATCH_SIZE = int(os.environ.get('BATCH_SIZE', '10000'))
LOG_DIR = os.environ.get('LOG_DIR', '/var/log/test-logs')

TARGET_SIZE_BYTES = int(TARGET_SIZE_GB * 1024 * 1024 * 1024)

# Sample data for realistic logs
USERS = ['admin', 'root', 'john.doe', 'jane.smith', 'svc_account', 'backup_user', 'deploy', 'developer', 'analyst', 'security']
SOURCE_IPS = [f'192.168.{random.randint(1,254)}.{random.randint(1,254)}' for _ in range(50)]
SOURCE_IPS += [f'10.0.{random.randint(0,10)}.{random.randint(1,254)}' for _ in range(30)]
SOURCE_IPS += [f'{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}' for _ in range(20)]

PROCESSES = ['sshd', 'sudo', 'su', 'login', 'systemd', 'cron', 'httpd', 'nginx', 'docker', 'kubelet', 'auditd', 'firewalld']
ACTIONS = ['login_success', 'login_failed', 'logout', 'sudo_command', 'file_access', 'process_start', 'process_stop', 'permission_denied', 'configuration_change', 'service_restart']
SEVERITY = ['low', 'medium', 'high', 'critical']
SEVERITY_LEVELS = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]

RULE_DESCRIPTIONS = [
    "User authentication success",
    "User authentication failure",
    "Multiple authentication failures",
    "Successful sudo to ROOT",
    "User changed password",
    "User account created",
    "User account deleted",
    "Firewall rule added",
    "Firewall rule deleted",
    "Service started",
    "Service stopped",
    "Process created",
    "File integrity check failed",
    "Suspicious file access detected",
    "SSH brute force attempt detected",
    "Rootkit detection scan completed",
    "Configuration file modified",
    "Log file rotation",
    "System reboot detected",
    "Disk usage exceeded threshold"
]

GROUPS = [
    ["authentication_success", "sshd", "pam"],
    ["authentication_failed", "sshd", "pam"],
    ["syslog", "systemd"],
    ["sudo", "privilege_escalation"],
    ["firewall", "iptables"],
    ["process_audit", "auditd"],
    ["file_integrity", "syscheck"],
    ["rootcheck", "policy_monitoring"],
    ["ossec", "agent"]
]


def generate_wazuh_alert():
    """Generate a realistic Wazuh alert JSON"""
    timestamp = datetime.utcnow() - timedelta(seconds=random.randint(0, 3600))

    rule_id = random.randint(1000, 99999)
    rule_level = random.choice(SEVERITY_LEVELS)
    groups = random.choice(GROUPS)

    alert = {
        "timestamp": timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000",
        "rule": {
            "level": rule_level,
            "description": random.choice(RULE_DESCRIPTIONS),
            "id": str(rule_id),
            "firedtimes": random.randint(1, 1000),
            "mail": rule_level >= 10,
            "groups": groups,
            "pci_dss": ["10.2.5", "10.6.1"] if random.random() > 0.7 else [],
            "gdpr": ["IV_35.7.d"] if random.random() > 0.8 else [],
            "hipaa": ["164.312.b"] if random.random() > 0.9 else [],
            "nist_800_53": ["AU.14", "AC.7"] if random.random() > 0.7 else []
        },
        "agent": {
            "id": "001",
            "name": "test-agent-5gb",
            "ip": "10.0.0.100"
        },
        "manager": {
            "name": "wazuh-manager"
        },
        "id": f"{timestamp.strftime('%Y%m%d%H%M%S')}.{random.randint(100000, 999999)}",
        "full_log": generate_syslog_message(),
        "predecoder": {
            "program_name": random.choice(PROCESSES),
            "timestamp": timestamp.strftime("%b %d %H:%M:%S"),
            "hostname": "test-agent-5gb"
        },
        "decoder": {
            "name": random.choice(["sshd", "pam", "sudo", "systemd-logind", "auditd"]),
            "parent": random.choice(["syslog", "audit"])
        },
        "data": {
            "srcip": random.choice(SOURCE_IPS),
            "srcuser": random.choice(USERS),
            "dstuser": random.choice(USERS) if random.random() > 0.5 else "root"
        },
        "location": f"/var/log/{random.choice(['auth.log', 'secure', 'syslog', 'messages', 'audit/audit.log'])}"
    }

    # Add GeoLocation data for external IPs
    if not alert["data"]["srcip"].startswith(("192.168.", "10.", "172.")):
        alert["GeoLocation"] = {
            "city_name": random.choice(["Moscow", "Beijing", "New York", "London", "Tokyo", "Berlin", "Paris"]),
            "country_name": random.choice(["Russia", "China", "United States", "United Kingdom", "Japan", "Germany", "France"]),
            "location": {
                "lat": random.uniform(-90, 90),
                "lon": random.uniform(-180, 180)
            }
        }

    return alert


def generate_syslog_message():
    """Generate a realistic syslog message"""
    timestamp = datetime.now().strftime("%b %d %H:%M:%S")
    hostname = "test-agent-5gb"
    process = random.choice(PROCESSES)
    pid = random.randint(1000, 65535)
    user = random.choice(USERS)
    ip = random.choice(SOURCE_IPS)

    messages = [
        f"{timestamp} {hostname} {process}[{pid}]: Accepted publickey for {user} from {ip} port {random.randint(30000, 65535)} ssh2",
        f"{timestamp} {hostname} {process}[{pid}]: Failed password for {user} from {ip} port {random.randint(30000, 65535)} ssh2",
        f"{timestamp} {hostname} {process}[{pid}]: pam_unix(sshd:session): session opened for user {user} by (uid=0)",
        f"{timestamp} {hostname} sudo: {user} : TTY=pts/{random.randint(0,10)} ; PWD=/home/{user} ; USER=root ; COMMAND=/bin/{random.choice(['cat', 'ls', 'vim', 'systemctl', 'docker'])} {random.choice(['/etc/passwd', '/var/log/syslog', 'status nginx', 'ps aux'])}",
        f"{timestamp} {hostname} {process}[{pid}]: Connection closed by {ip} port {random.randint(30000, 65535)}",
        f"{timestamp} {hostname} {process}[{pid}]: Invalid user {user} from {ip} port {random.randint(30000, 65535)}",
        f"{timestamp} {hostname} auditd[{pid}]: SYSCALL arch=c000003e syscall=59 success=yes exit=0 items=2 ppid={random.randint(1000,9999)} pid={pid} auid={random.randint(1000,65535)} uid=0",
        f"{timestamp} {hostname} systemd[1]: Started Session {random.randint(1,1000)} of user {user}.",
        f"{timestamp} {hostname} kernel: [UFW BLOCK] IN=eth0 OUT= MAC={''.join(random.choices('0123456789abcdef', k=34))} SRC={ip} DST=10.0.0.100 LEN={random.randint(40,1500)} TOS=0x00 PREC=0x00 TTL={random.randint(50,128)} ID={random.randint(1,65535)} PROTO=TCP SPT={random.randint(1024,65535)} DPT={random.randint(1,1024)} WINDOW={random.randint(1000,65535)} RES=0x00 SYN URGP=0",
    ]

    return random.choice(messages)


def generate_auth_log_line():
    """Generate auth.log style line"""
    timestamp = datetime.now().strftime("%b %d %H:%M:%S")
    hostname = "test-agent-5gb"
    process = random.choice(['sshd', 'sudo', 'su', 'login', 'systemd-logind'])
    pid = random.randint(1000, 65535)
    user = random.choice(USERS)
    ip = random.choice(SOURCE_IPS)

    templates = [
        f"{timestamp} {hostname} {process}[{pid}]: Accepted password for {user} from {ip} port {random.randint(30000, 65535)} ssh2",
        f"{timestamp} {hostname} {process}[{pid}]: Failed password for {user} from {ip} port {random.randint(30000, 65535)} ssh2",
        f"{timestamp} {hostname} {process}[{pid}]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={ip} user={user}",
        f"{timestamp} {hostname} sudo:    {user} : TTY=pts/{random.randint(0,5)} ; PWD=/home/{user} ; USER=root ; COMMAND=/usr/bin/{random.choice(['systemctl', 'docker', 'apt', 'yum'])} {random.choice(['restart nginx', 'ps aux', 'update', 'list'])}",
        f"{timestamp} {hostname} {process}[{pid}]: Disconnected from user {user} {ip} port {random.randint(30000, 65535)}",
        f"{timestamp} {hostname} {process}[{pid}]: New session {random.randint(1,500)} of user {user}.",
    ]

    return random.choice(templates) + "\n"


def generate_syslog_line():
    """Generate syslog style line"""
    timestamp = datetime.now().strftime("%b %d %H:%M:%S")
    hostname = "test-agent-5gb"
    process = random.choice(PROCESSES)
    pid = random.randint(1000, 65535)

    templates = [
        f"{timestamp} {hostname} {process}[{pid}]: Service started successfully",
        f"{timestamp} {hostname} {process}[{pid}]: Configuration reloaded",
        f"{timestamp} {hostname} kernel: [{''.join(random.choices(string.digits, k=8))}] eth0: link up",
        f"{timestamp} {hostname} systemd[1]: Started {random.choice(['Docker', 'Nginx', 'SSH', 'Cron', 'Apache'])} Service.",
        f"{timestamp} {hostname} cron[{pid}]: ({random.choice(USERS)}) CMD ({random.choice(['/usr/bin/backup.sh', '/opt/scripts/cleanup.sh', 'certbot renew'])})",
        f"{timestamp} {hostname} dockerd[{pid}]: Container {random.choice(['web', 'api', 'db', 'cache'])} started",
    ]

    return random.choice(templates) + "\n"


def main():
    print("=" * 60)
    print("  5GB LOG GENERATOR FOR WAZUH AGENT")
    print("=" * 60)
    print(f"\nConfiguration:")
    print(f"  Target Size:   {TARGET_SIZE_GB} GB ({TARGET_SIZE_BYTES:,} bytes)")
    print(f"  Log Type:      {LOG_TYPE}")
    print(f"  Batch Size:    {BATCH_SIZE}")
    print(f"  Log Directory: {LOG_DIR}")
    print()

    # Ensure directory exists
    os.makedirs(LOG_DIR, exist_ok=True)

    # Generate different log files based on type
    if LOG_TYPE == 'security' or LOG_TYPE == 'all':
        generate_security_logs()
    elif LOG_TYPE == 'wazuh':
        generate_wazuh_alerts()
    elif LOG_TYPE == 'syslog':
        generate_syslog_logs()
    else:
        generate_security_logs()

    print("\n" + "=" * 60)
    print("  LOG GENERATION COMPLETE")
    print("=" * 60)


def generate_security_logs():
    """Generate security-style logs (auth.log format)"""
    auth_log = os.path.join(LOG_DIR, "auth.log")
    syslog_file = os.path.join(LOG_DIR, "syslog")

    print(f"Generating security logs to {LOG_DIR}...")

    total_bytes = 0
    auth_bytes = 0
    sys_bytes = 0

    start_time = time.time()

    with open(auth_log, 'w') as auth_f, open(syslog_file, 'w') as sys_f:
        batch = []
        sys_batch = []

        with tqdm(total=TARGET_SIZE_BYTES, unit='B', unit_scale=True, desc="Generating") as pbar:
            while total_bytes < TARGET_SIZE_BYTES:
                # Generate auth logs (70%)
                for _ in range(int(BATCH_SIZE * 0.7)):
                    line = generate_auth_log_line()
                    batch.append(line)
                    auth_bytes += len(line.encode('utf-8'))

                # Generate syslog entries (30%)
                for _ in range(int(BATCH_SIZE * 0.3)):
                    line = generate_syslog_line()
                    sys_batch.append(line)
                    sys_bytes += len(line.encode('utf-8'))

                # Write batches
                auth_f.write(''.join(batch))
                auth_f.flush()
                sys_f.write(''.join(sys_batch))
                sys_f.flush()

                batch_bytes = auth_bytes + sys_bytes - total_bytes
                total_bytes = auth_bytes + sys_bytes
                pbar.update(batch_bytes)

                batch = []
                sys_batch = []

    elapsed = time.time() - start_time

    print(f"\nGeneration complete!")
    print(f"  Auth log:     {auth_bytes / (1024*1024*1024):.2f} GB")
    print(f"  Syslog:       {sys_bytes / (1024*1024*1024):.2f} GB")
    print(f"  Total:        {total_bytes / (1024*1024*1024):.2f} GB")
    print(f"  Time:         {elapsed:.1f} seconds")
    print(f"  Speed:        {total_bytes / elapsed / (1024*1024):.2f} MB/sec")


def generate_wazuh_alerts():
    """Generate Wazuh-style alert JSON file"""
    alerts_file = os.path.join(LOG_DIR, "alerts.json")

    print(f"Generating Wazuh alerts to {alerts_file}...")

    total_bytes = 0
    event_count = 0

    start_time = time.time()

    with open(alerts_file, 'w') as f:
        with tqdm(total=TARGET_SIZE_BYTES, unit='B', unit_scale=True, desc="Generating") as pbar:
            while total_bytes < TARGET_SIZE_BYTES:
                batch = []

                for _ in range(BATCH_SIZE):
                    alert = generate_wazuh_alert()
                    line = json.dumps(alert) + "\n"
                    batch.append(line)
                    total_bytes += len(line.encode('utf-8'))
                    event_count += 1

                    if total_bytes >= TARGET_SIZE_BYTES:
                        break

                f.write(''.join(batch))
                f.flush()
                pbar.update(sum(len(l.encode('utf-8')) for l in batch))

    elapsed = time.time() - start_time

    print(f"\nGeneration complete!")
    print(f"  Total Size:   {total_bytes / (1024*1024*1024):.2f} GB")
    print(f"  Total Events: {event_count:,}")
    print(f"  Avg Event:    {total_bytes / event_count:.0f} bytes")
    print(f"  Time:         {elapsed:.1f} seconds")
    print(f"  Speed:        {total_bytes / elapsed / (1024*1024):.2f} MB/sec")


def generate_syslog_logs():
    """Generate syslog-style logs"""
    syslog_file = os.path.join(LOG_DIR, "messages")

    print(f"Generating syslog to {syslog_file}...")

    total_bytes = 0
    line_count = 0

    start_time = time.time()

    with open(syslog_file, 'w') as f:
        with tqdm(total=TARGET_SIZE_BYTES, unit='B', unit_scale=True, desc="Generating") as pbar:
            while total_bytes < TARGET_SIZE_BYTES:
                batch = []

                for _ in range(BATCH_SIZE):
                    line = generate_syslog_line()
                    batch.append(line)
                    total_bytes += len(line.encode('utf-8'))
                    line_count += 1

                    if total_bytes >= TARGET_SIZE_BYTES:
                        break

                f.write(''.join(batch))
                f.flush()
                pbar.update(sum(len(l.encode('utf-8')) for l in batch))

    elapsed = time.time() - start_time

    print(f"\nGeneration complete!")
    print(f"  Total Size:   {total_bytes / (1024*1024*1024):.2f} GB")
    print(f"  Total Lines:  {line_count:,}")
    print(f"  Time:         {elapsed:.1f} seconds")
    print(f"  Speed:        {total_bytes / elapsed / (1024*1024):.2f} MB/sec")


if __name__ == '__main__':
    main()
