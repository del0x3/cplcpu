# Wazuh Filebeat Lab

A Docker-based lab environment for testing Filebeat log shipping to Wazuh Indexer with comprehensive metrics and monitoring.

## Architecture

```
┌─────────────────┐     ┌──────────────┐     ┌────────────────┐
│  Log Generator  │────▶│   Filebeat   │────▶│ Wazuh Indexer  │
└─────────────────┘     └──────────────┘     └────────────────┘
                                                      │
                                                      ▼
┌─────────────────┐     ┌──────────────┐     ┌────────────────┐
│    Grafana      │◀────│  Prometheus  │◀────│ Indexer Export │
└─────────────────┘     └──────────────┘     └────────────────┘
```

## Components

| Service | Port | Description |
|---------|------|-------------|
| Wazuh Indexer | 9200 | OpenSearch-based indexer for storing alerts |
| Filebeat | 5066 | Ships logs to Wazuh Indexer |
| Log Generator | - | Generates sample security/application logs |
| Prometheus | 9090 | Metrics collection and alerting |
| Grafana | 3000 | Dashboards and visualization |
| Indexer Exporter | 9114 | Prometheus exporter for Wazuh Indexer |

## Quick Start

```bash
# Start all services
cd wazuh-lab
docker-compose up -d

# Check service status
docker-compose ps

# View logs
docker-compose logs -f filebeat

# Stop services
docker-compose down
```

## Default Filebeat Configuration

The Filebeat configuration (`config/filebeat/filebeat.yml`) is based on the official Wazuh Filebeat configuration:

```yaml
# Wazuh Indexer output
output.elasticsearch:
  hosts: ["http://wazuh-indexer:9200"]
  index: "wazuh-alerts-%{+yyyy.MM.dd}"

# Template settings
setup.template.name: "wazuh"
setup.template.pattern: "wazuh-*"
setup.ilm.enabled: false
```

### Input Sources

- **Application logs**: `/var/log/app/*.log`
- **Wazuh alerts (JSON)**: `/var/log/app/alerts/*.json`
- **Security events**: `/var/log/app/security/*.log`
- **Metrics logs**: `/var/log/app/metrics/*.log`

## Accessing Services

| Service | URL | Credentials |
|---------|-----|-------------|
| Wazuh Indexer | http://localhost:9200 | None (security disabled) |
| Prometheus | http://localhost:9090 | None |
| Grafana | http://localhost:3000 | admin / admin |

## Metrics Available

### Wazuh Indexer Metrics

| Metric | Description |
|--------|-------------|
| `elasticsearch_indices_indexing_index_total` | Total write operations |
| `elasticsearch_indices_search_query_total` | Total read/search operations |
| `elasticsearch_indices_indexing_index_time_seconds_total` | Write latency |
| `elasticsearch_indices_search_query_time_seconds` | Read/search latency |
| `elasticsearch_indices_docs_total` | Total documents indexed |
| `elasticsearch_indices_store_size_bytes_total` | Total storage used |
| `elasticsearch_jvm_memory_used_bytes` | JVM memory usage |
| `elasticsearch_filesystem_data_available_bytes` | Available disk space |
| `elasticsearch_cluster_health_status` | Cluster health (green/yellow/red) |
| `elasticsearch_transport_rx_size_bytes_total` | Network bytes received |
| `elasticsearch_transport_tx_size_bytes_total` | Network bytes transmitted |

### Grafana Dashboard

The pre-configured dashboard includes:

1. **Cluster Overview**
   - Cluster health status
   - Active nodes
   - Total documents
   - Index store size
   - Unassigned shards
   - Pending tasks

2. **Read/Write Operations**
   - Write operations rate (index, delete)
   - Read operations rate (search, fetch, get)
   - Write latency
   - Read/Search latency

3. **Resource Utilization**
   - JVM Heap usage
   - Disk usage
   - GC activity

4. **Throughput & Data Transfer**
   - Network throughput
   - Index maintenance throughput

## Alerting Rules

Pre-configured Prometheus alerts:

- `WazuhIndexerClusterRed` - Cluster in RED status
- `WazuhIndexerClusterYellow` - Cluster in YELLOW status
- `WazuhIndexerNodeDown` - No active nodes
- `WazuhIndexerDiskSpaceLow` - Disk space below 20%
- `WazuhIndexerHighWriteLatency` - Write latency above 1s
- `WazuhIndexerHighReadLatency` - Search latency above 2s
- `WazuhIndexerHeapUsageHigh` - JVM heap above 90%
- `FilebeatNotRunning` - Filebeat process down

## Sample Logs Generated

The log generator creates realistic sample data:

1. **Wazuh Alerts** (JSON format)
   - PAM login events (5501-5503)
   - SSH events (5710-5712)
   - Firewall events (5901-5902)
   - Web attacks (31100-31103)

2. **Security Logs**
   - Login/logout events
   - File operations
   - Permission changes

3. **Application Logs**
   - Request processing
   - Database connections
   - Cache operations
   - Health checks

4. **Metrics Logs**
   - Read/write operations
   - Latency metrics
   - Resource usage

## Querying Data

### Via curl (Wazuh Indexer)

```bash
# Check cluster health
curl http://localhost:9200/_cluster/health?pretty

# List indices
curl http://localhost:9200/_cat/indices?v

# Search alerts
curl -X GET "http://localhost:9200/wazuh-alerts-*/_search?pretty" -H 'Content-Type: application/json' -d'
{
  "query": {"match_all": {}},
  "size": 10
}'

# Get document count
curl http://localhost:9200/wazuh-alerts-*/_count
```

### Via Prometheus

```bash
# Query metrics
curl 'http://localhost:9090/api/v1/query?query=elasticsearch_indices_docs_total'
```

## Configuration Files

```
wazuh-lab/
├── docker-compose.yml              # Main orchestration
├── config/
│   ├── wazuh-indexer/
│   │   └── opensearch.yml          # Indexer configuration
│   ├── filebeat/
│   │   └── filebeat.yml            # Filebeat configuration
│   ├── prometheus/
│   │   ├── prometheus.yml          # Prometheus scrape config
│   │   └── alerts.yml              # Alerting rules
│   └── grafana/
│       ├── provisioning/
│       │   ├── datasources/        # Auto-provision datasources
│       │   └── dashboards/         # Dashboard provisioning
│       └── dashboards/
│           └── wazuh-indexer-metrics.json
├── scripts/
│   ├── log_generator.py            # Sample log generator
│   └── Dockerfile.log-generator
└── logs/                           # Generated logs (mounted volume)
```

## Customization

### Adding SSL/TLS

Edit `config/filebeat/filebeat.yml`:

```yaml
output.elasticsearch:
  hosts: ["https://wazuh-indexer:9200"]
  protocol: https
  ssl.enabled: true
  ssl.certificate_authorities: ["/etc/filebeat/certs/root-ca.pem"]
  ssl.certificate: "/etc/filebeat/certs/filebeat.pem"
  ssl.key: "/etc/filebeat/certs/filebeat-key.pem"
```

### Multiple Indexer Nodes

```yaml
output.elasticsearch:
  hosts: ["10.0.0.1:9200", "10.0.0.2:9200", "10.0.0.3:9200"]
```

## Sources

- [Wazuh Indexer Integration](https://documentation.wazuh.com/current/user-manual/manager/indexer-integration.html)
- [Wazuh Filebeat Configuration](https://github.com/wazuh/wazuh/blob/master/extensions/filebeat/7.x/filebeat.yml)
- [Wazuh Installation Guide](https://documentation.wazuh.com/current/installation-guide/wazuh-server/step-by-step.html)
