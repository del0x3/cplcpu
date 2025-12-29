# Wazuh 4.12 All-in-One Lab with Filebeat Speed Measurement

A complete Docker-based Wazuh 4.12.0 stack with Filebeat log shipping and comprehensive speed/performance measurement **from the outside using default configuration**.

## Architecture

```
┌─────────────────┐     ┌──────────────┐     ┌────────────────┐
│  Log Generator  │────▶│   Filebeat   │────▶│ Wazuh Indexer  │
│  (High Volume)  │     │  (Default)   │     │   (4.12.0)     │
└─────────────────┘     └──────────────┘     └────────────────┘
                                                      │
                              ┌───────────────────────┼───────────────────────┐
                              │                       │                       │
                              ▼                       ▼                       ▼
                     ┌────────────────┐     ┌────────────────┐     ┌────────────────┐
                     │ Wazuh Manager  │     │Wazuh Dashboard │     │ Speed Metrics  │
                     │   (4.12.0)     │     │   (4.12.0)     │     │  (External)    │
                     └────────────────┘     └────────────────┘     └────────────────┘
```

## Wazuh 4.12.0 Components

| Service | Port | Description |
|---------|------|-------------|
| Wazuh Indexer | 9200, 9300 | OpenSearch-based indexer |
| Wazuh Manager | 1514, 1515, 514/udp, 55000 | Core security analysis engine |
| Wazuh Dashboard | 5601 | Web UI for security monitoring |
| Filebeat | 5066 | Ships logs (DEFAULT configuration) |
| Log Generator | - | High-volume sample log generation |
| Prometheus | 9090 | Metrics collection |
| Grafana | 3000 | Dashboards and visualization |

## Quick Start

```bash
cd wazuh-lab

# Start all services
docker-compose up -d

# Check service status
docker-compose ps

# View Filebeat logs
docker-compose logs -f filebeat

# Stop services
docker-compose down -v
```

## Measuring Filebeat Speed (From Outside)

### Method 1: Shell Script (Recommended)

```bash
# Measure speed for 60 seconds (default)
./scripts/measure_filebeat_speed.sh

# Measure for 5 minutes with 10-second intervals
DURATION=300 INTERVAL=10 ./scripts/measure_filebeat_speed.sh

# Save results to JSON file
OUTPUT_FILE=./benchmark-results/speed_test.json ./scripts/measure_filebeat_speed.sh
```

**Output:**
```
============================================
  FILEBEAT SPEED MEASUREMENT (EXTERNAL)
============================================

Time     | Events/sec | Latency(ms) | Throughput(KB/s) | Total Docs
---------|------------|-------------|------------------|------------
   5s    |     423.60 |        0.47 |           245.32 |       2118
  10s    |     456.20 |        0.43 |           264.21 |       4399
  ...

SUMMARY STATISTICS:
Events Indexed Per Second:
  Average:  412.45 events/sec
  Maximum:  523.80 events/sec
  Minimum:  356.20 events/sec

Indexing Latency:
  Average:  0.48 ms/event

Data Throughput:
  Average:  238.56 KB/sec
```

### Method 2: Direct curl Queries

```bash
# Get initial document count
START_COUNT=$(curl -s http://localhost:9200/_stats | \
    python3 -c "import sys,json; print(json.load(sys.stdin)['_all']['primaries']['indexing']['index_total'])")

# Wait 60 seconds
sleep 60

# Get final document count
END_COUNT=$(curl -s http://localhost:9200/_stats | \
    python3 -c "import sys,json; print(json.load(sys.stdin)['_all']['primaries']['indexing']['index_total'])")

# Calculate events per second
echo "Events/sec: $(( (END_COUNT - START_COUNT) / 60 ))"
```

### Method 3: Watch Mode (Real-time)

```bash
# Watch indexing rate in real-time
watch -n 1 'curl -s http://localhost:9200/_stats | \
    python3 -c "import sys,json; d=json.load(sys.stdin)[\"_all\"][\"primaries\"]; \
    print(f\"Docs: {d[\"docs\"][\"count\"]:,} | Indexed: {d[\"indexing\"][\"index_total\"]:,}\")"'
```

### Method 4: Prometheus Queries

```bash
# Current indexing rate (events/sec over last minute)
curl -s 'http://localhost:9090/api/v1/query?query=rate(elasticsearch_indices_indexing_index_total[1m])' | \
    python3 -c "import sys,json; r=json.load(sys.stdin)['data']['result']; \
    print(f\"Indexing Rate: {float(r[0]['value'][1]):.2f} events/sec\") if r else print('No data')"

# Average indexing latency (ms per document)
curl -s 'http://localhost:9090/api/v1/query?query=(rate(elasticsearch_indices_indexing_index_time_seconds_total[1m])/rate(elasticsearch_indices_indexing_index_total[1m]))*1000' | \
    python3 -c "import sys,json; r=json.load(sys.stdin)['data']['result']; \
    print(f\"Latency: {float(r[0]['value'][1]):.2f} ms/doc\") if r else print('No data')"
```

## Default Filebeat Configuration

The lab uses the **official Wazuh Filebeat configuration** without modifications:

```yaml
# Wazuh - Filebeat configuration file (DEFAULT)
output.elasticsearch:
  hosts: ["http://wazuh-indexer:9200"]
  index: "wazuh-alerts-%{+yyyy.MM.dd}"
  bulk_max_size: 1000
  worker: 2

setup.template.name: "wazuh"
setup.template.pattern: "wazuh-*"
setup.template.overwrite: true
setup.ilm.enabled: false

# Monitoring enabled for external metrics
monitoring.enabled: true
http.enabled: true
http.port: 5066
```

## Speed Metrics Explained

| Metric | Description | How to Measure |
|--------|-------------|----------------|
| **Events/sec** | Documents indexed per second | `rate(indexing_index_total[1m])` |
| **Latency** | Time per document (ms) | `index_time_ms / index_total` |
| **Throughput** | Data rate (KB/sec) | `rate(store_size_bytes[1m])` |
| **Event Lag** | Pending events in queue | Filebeat queue depth |

## Adjusting Log Generation Rate

```bash
# Default: 100 events/sec per type (400 total)
docker-compose up -d log-generator

# High volume: 1000 events/sec per type (4000 total)
LOG_RATE=1000 docker-compose up -d log-generator

# Maximum stress test
LOG_RATE=5000 docker-compose up -d log-generator

# Burst mode: 10,000 events every 30 seconds
BURST_MODE=true BURST_SIZE=10000 BURST_INTERVAL=30 docker-compose up -d log-generator
```

## Grafana Dashboards

Access at http://localhost:3000 (admin/admin):

1. **Filebeat Speed Benchmark**
   - Real-time indexing speed
   - Indexing latency
   - Total events indexed
   - Network throughput

2. **Wazuh Indexer Metrics**
   - Cluster health
   - Read/Write operations
   - Resource utilization

## Default Credentials

| Service | Username | Password |
|---------|----------|----------|
| Wazuh Dashboard | admin | admin |
| Wazuh API | wazuh-wui | MyS3cr3tP4ssw0rd* |
| Grafana | admin | admin |

## Accessing Services

| Service | URL |
|---------|-----|
| Wazuh Dashboard | http://localhost:5601 |
| Wazuh Indexer | http://localhost:9200 |
| Wazuh Manager API | https://localhost:55000 |
| Grafana | http://localhost:3000 |
| Prometheus | http://localhost:9090 |
| Filebeat Stats | http://localhost:5066/stats |

## Sample Speed Test Results

With default configuration and LOG_RATE=100:

```
============================================
  SUMMARY STATISTICS
============================================

Events Indexed Per Second:
  Average:  387.45 events/sec
  Maximum:  512.80 events/sec
  Minimum:  298.20 events/sec

Indexing Latency:
  Average:  0.52 ms/event

Data Throughput:
  Average:  224.36 KB/sec
  Average:  0.2190 MB/sec

Final State:
  Total Documents:  23247
  Total Store Size: 14.82 MB
```

## Configuration Files

```
wazuh-lab/
├── docker-compose.yml                    # Full Wazuh 4.12 stack
├── README.md
├── benchmark-results/                    # Speed test results
├── config/
│   ├── wazuh-indexer/
│   │   ├── opensearch.yml
│   │   └── internal_users.yml
│   ├── wazuh-manager/
│   │   └── wazuh_cluster.conf
│   ├── wazuh-dashboard/
│   │   ├── opensearch_dashboards.yml
│   │   └── wazuh.yml
│   ├── filebeat/
│   │   └── filebeat.yml                 # DEFAULT configuration
│   ├── prometheus/
│   │   ├── prometheus.yml
│   │   └── alerts.yml
│   └── grafana/
│       └── dashboards/
│           ├── wazuh-indexer-metrics.json
│           └── filebeat-speed.json
├── scripts/
│   ├── log_generator.py                 # High-volume log generator
│   ├── measure_filebeat_speed.sh        # External speed measurement
│   ├── filebeat_benchmark.py            # Python benchmark tool
│   └── Dockerfile.*
└── logs/
```

## Troubleshooting

### Check Indexer Health
```bash
curl http://localhost:9200/_cluster/health?pretty
```

### Check Filebeat Status
```bash
curl http://localhost:5066/stats | python3 -c "import sys,json; \
d=json.load(sys.stdin); print(json.dumps(d['libbeat']['output'], indent=2))"
```

### View Indexing Stats
```bash
curl http://localhost:9200/_stats/indexing?pretty
```

### Check Manager Status
```bash
docker-compose exec wazuh-manager /var/ossec/bin/wazuh-control status
```

## Sources

- [Wazuh Docker Documentation](https://documentation.wazuh.com/current/deployment-options/docker/index.html)
- [Wazuh Indexer Integration](https://documentation.wazuh.com/current/user-manual/manager/indexer-integration.html)
- [Wazuh Docker GitHub](https://github.com/wazuh/wazuh-docker)
- [Docker Hub - Wazuh 4.12.0](https://hub.docker.com/r/wazuh/wazuh-dashboard/tags?name=4.12.0)
- [Wazuh Filebeat Configuration](https://github.com/wazuh/wazuh/blob/master/extensions/filebeat/7.x/filebeat.yml)
