#!/bin/bash
set -e

# Configure Wazuh Agent
WAZUH_MANAGER="${WAZUH_MANAGER:-wazuh-manager}"
WAZUH_AGENT_GROUP="${WAZUH_AGENT_GROUP:-default}"
WAZUH_AGENT_NAME="${WAZUH_AGENT_NAME:-docker-agent}"

echo "Configuring Wazuh Agent..."
echo "  Manager: $WAZUH_MANAGER"
echo "  Agent Name: $WAZUH_AGENT_NAME"
echo "  Group: $WAZUH_AGENT_GROUP"

# Configure manager address
sed -i "s|<address>.*</address>|<address>$WAZUH_MANAGER</address>|g" /var/ossec/etc/ossec.conf

# Add log monitoring for test logs
if ! grep -q "/var/log/test-logs" /var/ossec/etc/ossec.conf; then
    sed -i '/<\/ossec_config>/i \
  <localfile>\
    <log_format>syslog</log_format>\
    <location>/var/log/test-logs/auth.log</location>\
  </localfile>\
  <localfile>\
    <log_format>syslog</log_format>\
    <location>/var/log/test-logs/syslog</location>\
  </localfile>' /var/ossec/etc/ossec.conf
fi

# Wait for manager to be ready
echo "Waiting for Wazuh Manager to be ready..."
for i in {1..60}; do
    if nc -z $WAZUH_MANAGER 1514 2>/dev/null; then
        echo "Manager is ready!"
        break
    fi
    echo "  Attempt $i/60..."
    sleep 5
done

# Register agent if not already registered
if [ ! -f /var/ossec/etc/client.keys ] || [ ! -s /var/ossec/etc/client.keys ]; then
    echo "Registering agent with manager..."
    /var/ossec/bin/agent-auth -m $WAZUH_MANAGER -A $WAZUH_AGENT_NAME -G $WAZUH_AGENT_GROUP || true
fi

# Start Wazuh Agent
echo "Starting Wazuh Agent..."
/var/ossec/bin/wazuh-control start

# Keep container running and tail logs
echo "Agent started. Tailing logs..."
tail -F /var/ossec/logs/ossec.log 2>/dev/null || sleep infinity
