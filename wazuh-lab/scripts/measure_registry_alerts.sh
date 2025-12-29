#!/bin/bash
#
# Filebeat Registry & alerts.json Measurement Script
# Measures from OUTSIDE using DEFAULT configuration
#
# Tracks:
# 1. Filebeat registry reads (file offset tracking)
# 2. New events added to alerts.json
# 3. Processing rate from file to indexer
#

set -e

# Configuration
FILEBEAT_CONTAINER="${FILEBEAT_CONTAINER:-filebeat}"
INDEXER_HOST="${INDEXER_HOST:-localhost:9200}"
ALERTS_FILE="${ALERTS_FILE:-./logs/alerts/alerts.json}"
DURATION="${DURATION:-60}"
INTERVAL="${INTERVAL:-2}"
OUTPUT_FILE="${OUTPUT_FILE:-}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${BLUE}================================================================${NC}"
echo -e "${BLUE}  FILEBEAT REGISTRY & ALERTS.JSON MEASUREMENT${NC}"
echo -e "${BLUE}================================================================${NC}"
echo ""
echo -e "Configuration:"
echo -e "  Filebeat Container: ${FILEBEAT_CONTAINER}"
echo -e "  Indexer Host:       ${INDEXER_HOST}"
echo -e "  Alerts File:        ${ALERTS_FILE}"
echo -e "  Duration:           ${DURATION}s"
echo -e "  Interval:           ${INTERVAL}s"
echo ""

# Functions
get_alerts_line_count() {
    if [ -f "$ALERTS_FILE" ]; then
        wc -l < "$ALERTS_FILE" 2>/dev/null | tr -d ' ' || echo "0"
    else
        echo "0"
    fi
}

get_alerts_file_size() {
    if [ -f "$ALERTS_FILE" ]; then
        stat -c%s "$ALERTS_FILE" 2>/dev/null || stat -f%z "$ALERTS_FILE" 2>/dev/null || echo "0"
    else
        echo "0"
    fi
}

get_registry_offset() {
    # Read Filebeat registry from container
    docker exec "$FILEBEAT_CONTAINER" cat /usr/share/filebeat/data/registry/filebeat/log.json 2>/dev/null | \
        grep -o '"offset":[0-9]*' | tail -1 | grep -o '[0-9]*' || echo "0"
}

get_registry_for_alerts() {
    # Get registry entry specifically for alerts file
    docker exec "$FILEBEAT_CONTAINER" cat /usr/share/filebeat/data/registry/filebeat/log.json 2>/dev/null | \
        grep -i "alerts" | grep -o '"offset":[0-9]*' | tail -1 | grep -o '[0-9]*' || echo "0"
}

get_indexed_count() {
    curl -s "http://${INDEXER_HOST}/_stats" 2>/dev/null | \
        python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('_all',{}).get('primaries',{}).get('indexing',{}).get('index_total',0))" 2>/dev/null || echo "0"
}

get_wazuh_alerts_count() {
    curl -s "http://${INDEXER_HOST}/wazuh-alerts-*/_count" 2>/dev/null | \
        python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null || echo "0"
}

# Wait for services
echo -e "${YELLOW}Checking services...${NC}"

if [ -f "$ALERTS_FILE" ]; then
    echo -e "${GREEN}  ✓ Alerts file exists${NC}"
else
    echo -e "${YELLOW}  ⚠ Alerts file not found (will monitor when created)${NC}"
fi

if docker ps -q -f "name=${FILEBEAT_CONTAINER}" | grep -q .; then
    echo -e "${GREEN}  ✓ Filebeat container running${NC}"
else
    echo -e "${RED}  ✗ Filebeat container not found${NC}"
fi

if curl -s "http://${INDEXER_HOST}/_cluster/health" > /dev/null 2>&1; then
    echo -e "${GREEN}  ✓ Indexer accessible${NC}"
else
    echo -e "${RED}  ✗ Indexer not accessible${NC}"
fi

echo ""

# Initial values
start_time=$(date +%s)
prev_lines=$(get_alerts_line_count)
prev_size=$(get_alerts_file_size)
prev_offset=$(get_registry_for_alerts)
prev_indexed=$(get_indexed_count)
prev_wazuh_alerts=$(get_wazuh_alerts_count)
prev_time=$start_time

# Arrays for statistics
declare -a write_rates
declare -a read_rates
declare -a index_rates

echo -e "${GREEN}Starting measurement...${NC}"
echo -e "Press Ctrl+C to stop early"
echo ""
echo -e "${BLUE}Time  | alerts.json        | Registry           | Indexer            | Lag${NC}"
echo -e "${BLUE}      | Lines   Rate/s     | Offset   Rate/s    | Indexed  Rate/s    | Events${NC}"
echo "------|--------------------|--------------------|--------------------|---------"

elapsed=0
sample_count=0

while [ $elapsed -lt $DURATION ]; do
    sleep $INTERVAL

    current_time=$(date +%s)
    time_diff=$((current_time - prev_time))

    # Get current values
    current_lines=$(get_alerts_line_count)
    current_size=$(get_alerts_file_size)
    current_offset=$(get_registry_for_alerts)
    current_indexed=$(get_indexed_count)
    current_wazuh_alerts=$(get_wazuh_alerts_count)

    # Calculate deltas
    new_lines=$((current_lines - prev_lines))
    size_change=$((current_size - prev_size))
    offset_change=$((current_offset - prev_offset))
    new_indexed=$((current_indexed - prev_indexed))

    # Calculate rates
    if [ $time_diff -gt 0 ]; then
        write_rate=$(echo "scale=2; $new_lines / $time_diff" | bc)
        read_rate=$(echo "scale=2; $offset_change / $time_diff" | bc)
        index_rate=$(echo "scale=2; $new_indexed / $time_diff" | bc)
    else
        write_rate="0.00"
        read_rate="0.00"
        index_rate="0.00"
    fi

    # Calculate lag (lines in file vs wazuh alerts indexed)
    lag=$((current_lines - current_wazuh_alerts))
    if [ $lag -lt 0 ]; then
        lag=0
    fi

    elapsed=$((current_time - start_time))

    # Store rates for statistics
    write_rates+=("$write_rate")
    read_rates+=("$read_rate")
    index_rates+=("$index_rate")
    sample_count=$((sample_count + 1))

    # Print sample
    printf "%4ds | %7s %8s | %8s %8s | %8s %8s | %7s\n" \
        "$elapsed" \
        "$current_lines" "$write_rate" \
        "$current_offset" "$read_rate" \
        "$current_indexed" "$index_rate" \
        "$lag"

    # Update previous values
    prev_lines=$current_lines
    prev_size=$current_size
    prev_offset=$current_offset
    prev_indexed=$current_indexed
    prev_time=$current_time

done

echo ""
echo -e "${BLUE}================================================================${NC}"
echo -e "${BLUE}  SUMMARY${NC}"
echo -e "${BLUE}================================================================${NC}"

# Calculate statistics
if [ ${#write_rates[@]} -gt 0 ]; then
    # Sum for averages
    total_write=0
    total_read=0
    total_index=0
    max_write=0
    max_read=0
    max_index=0

    for r in "${write_rates[@]}"; do
        total_write=$(echo "$total_write + $r" | bc)
        if (( $(echo "$r > $max_write" | bc -l) )); then
            max_write=$r
        fi
    done

    for r in "${read_rates[@]}"; do
        total_read=$(echo "$total_read + $r" | bc)
        if (( $(echo "$r > $max_read" | bc -l) )); then
            max_read=$r
        fi
    done

    for r in "${index_rates[@]}"; do
        total_index=$(echo "$total_index + $r" | bc)
        if (( $(echo "$r > $max_index" | bc -l) )); then
            max_index=$r
        fi
    done

    avg_write=$(echo "scale=2; $total_write / $sample_count" | bc)
    avg_read=$(echo "scale=2; $total_read / $sample_count" | bc)
    avg_index=$(echo "scale=2; $total_index / $sample_count" | bc)

    final_lines=$(get_alerts_line_count)
    final_offset=$(get_registry_for_alerts)
    final_indexed=$(get_indexed_count)
    final_wazuh_alerts=$(get_wazuh_alerts_count)
    final_lag=$((final_lines - final_wazuh_alerts))

    echo ""
    echo -e "${GREEN}ALERTS.JSON (New Events Written):${NC}"
    echo -e "  Total Lines:        $final_lines"
    echo -e "  Avg Write Rate:     $avg_write lines/sec"
    echo -e "  Max Write Rate:     $max_write lines/sec"

    echo ""
    echo -e "${GREEN}FILEBEAT REGISTRY (File Reads):${NC}"
    echo -e "  Current Offset:     $final_offset bytes"
    echo -e "  Avg Read Rate:      $avg_read bytes/sec"
    echo -e "  Max Read Rate:      $max_read bytes/sec"

    echo ""
    echo -e "${GREEN}INDEXER (Documents Indexed):${NC}"
    echo -e "  Total Indexed:      $final_indexed"
    echo -e "  Wazuh Alerts:       $final_wazuh_alerts"
    echo -e "  Avg Index Rate:     $avg_index docs/sec"
    echo -e "  Max Index Rate:     $max_index docs/sec"

    echo ""
    echo -e "${YELLOW}PROCESSING LAG:${NC}"
    echo -e "  Current Lag:        $final_lag events"

    echo ""
    echo -e "Duration: ${elapsed}s | Samples: ${sample_count}"

    # Save to JSON if output file specified
    if [ -n "$OUTPUT_FILE" ]; then
        cat > "$OUTPUT_FILE" << EOF
{
    "timestamp": "$(date -Iseconds)",
    "duration_seconds": $elapsed,
    "samples": $sample_count,
    "alerts_json": {
        "total_lines": $final_lines,
        "avg_write_rate": $avg_write,
        "max_write_rate": $max_write
    },
    "filebeat_registry": {
        "final_offset": $final_offset,
        "avg_read_rate": $avg_read,
        "max_read_rate": $max_read
    },
    "indexer": {
        "total_indexed": $final_indexed,
        "wazuh_alerts": $final_wazuh_alerts,
        "avg_index_rate": $avg_index,
        "max_index_rate": $max_index
    },
    "lag": {
        "current": $final_lag
    }
}
EOF
        echo -e "${GREEN}Results saved to: $OUTPUT_FILE${NC}"
    fi
fi

echo ""
echo -e "${BLUE}================================================================${NC}"
