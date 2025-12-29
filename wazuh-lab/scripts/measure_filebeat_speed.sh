#!/bin/bash
#
# Filebeat Speed Measurement Script
# Measures Filebeat throughput using DEFAULT configuration from OUTSIDE
#
# This script measures speed by:
# 1. Querying the Wazuh Indexer for document counts
# 2. Calculating the ingestion rate over time
# 3. Measuring from outside the containers (external perspective)
#

set -e

# Configuration
INDEXER_HOST="${INDEXER_HOST:-localhost:9200}"
FILEBEAT_HOST="${FILEBEAT_HOST:-localhost:5066}"
DURATION="${DURATION:-60}"  # Duration in seconds
INTERVAL="${INTERVAL:-5}"   # Sampling interval in seconds
OUTPUT_FILE="${OUTPUT_FILE:-}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}  FILEBEAT SPEED MEASUREMENT (EXTERNAL)${NC}"
echo -e "${BLUE}============================================${NC}"
echo ""
echo -e "Configuration:"
echo -e "  Indexer Host:   ${INDEXER_HOST}"
echo -e "  Filebeat Host:  ${FILEBEAT_HOST}"
echo -e "  Duration:       ${DURATION} seconds"
echo -e "  Interval:       ${INTERVAL} seconds"
echo ""

# Wait for services
echo -e "${YELLOW}Waiting for services to be ready...${NC}"
for i in {1..30}; do
    if curl -s "http://${INDEXER_HOST}/_cluster/health" > /dev/null 2>&1; then
        echo -e "${GREEN}Indexer is ready!${NC}"
        break
    fi
    echo "  Retry $i/30..."
    sleep 2
done

# Get initial counts
echo ""
echo -e "${YELLOW}Getting initial measurements...${NC}"

get_indexer_stats() {
    curl -s "http://${INDEXER_HOST}/_stats" 2>/dev/null
}

get_doc_count() {
    curl -s "http://${INDEXER_HOST}/_stats" 2>/dev/null | \
        python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('_all',{}).get('primaries',{}).get('docs',{}).get('count',0))" 2>/dev/null || echo "0"
}

get_index_total() {
    curl -s "http://${INDEXER_HOST}/_stats" 2>/dev/null | \
        python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('_all',{}).get('primaries',{}).get('indexing',{}).get('index_total',0))" 2>/dev/null || echo "0"
}

get_index_time_ms() {
    curl -s "http://${INDEXER_HOST}/_stats" 2>/dev/null | \
        python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('_all',{}).get('primaries',{}).get('indexing',{}).get('index_time_in_millis',0))" 2>/dev/null || echo "0"
}

get_store_size() {
    curl -s "http://${INDEXER_HOST}/_stats" 2>/dev/null | \
        python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('_all',{}).get('primaries',{}).get('store',{}).get('size_in_bytes',0))" 2>/dev/null || echo "0"
}

# Arrays to store samples
declare -a rates
declare -a latencies
declare -a throughputs

# Initial values
start_time=$(date +%s)
prev_docs=$(get_doc_count)
prev_index_total=$(get_index_total)
prev_index_time=$(get_index_time_ms)
prev_store=$(get_store_size)
prev_time=$start_time

echo ""
echo -e "${GREEN}Starting measurement...${NC}"
echo -e "Press Ctrl+C to stop early"
echo ""
echo -e "${BLUE}Time     | Events/sec | Latency(ms) | Throughput(KB/s) | Total Docs${NC}"
echo "---------|------------|-------------|------------------|------------"

# Measurement loop
elapsed=0
while [ $elapsed -lt $DURATION ]; do
    sleep $INTERVAL

    current_time=$(date +%s)
    current_docs=$(get_doc_count)
    current_index_total=$(get_index_total)
    current_index_time=$(get_index_time_ms)
    current_store=$(get_store_size)

    # Calculate rates
    time_diff=$((current_time - prev_time))
    if [ $time_diff -gt 0 ]; then
        doc_diff=$((current_docs - prev_docs))
        index_diff=$((current_index_total - prev_index_total))
        time_ms_diff=$((current_index_time - prev_index_time))
        store_diff=$((current_store - prev_store))

        events_per_sec=$(echo "scale=2; $index_diff / $time_diff" | bc)

        if [ $index_diff -gt 0 ]; then
            latency_ms=$(echo "scale=2; $time_ms_diff / $index_diff" | bc)
        else
            latency_ms="0.00"
        fi

        throughput_kbps=$(echo "scale=2; ($store_diff / 1024) / $time_diff" | bc)

        # Store samples
        rates+=("$events_per_sec")
        latencies+=("$latency_ms")
        throughputs+=("$throughput_kbps")

        elapsed=$((current_time - start_time))
        printf "%4ds    | %10s | %11s | %16s | %10s\n" \
            "$elapsed" "$events_per_sec" "$latency_ms" "$throughput_kbps" "$current_docs"
    fi

    prev_docs=$current_docs
    prev_index_total=$current_index_total
    prev_index_time=$current_index_time
    prev_store=$current_store
    prev_time=$current_time

    elapsed=$((current_time - start_time))
done

echo ""
echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}  SUMMARY STATISTICS${NC}"
echo -e "${BLUE}============================================${NC}"

# Calculate statistics
if [ ${#rates[@]} -gt 0 ]; then
    # Calculate averages
    total_rate=0
    total_latency=0
    total_throughput=0
    max_rate=0
    min_rate=999999

    for r in "${rates[@]}"; do
        total_rate=$(echo "$total_rate + $r" | bc)
        if (( $(echo "$r > $max_rate" | bc -l) )); then
            max_rate=$r
        fi
        if (( $(echo "$r < $min_rate" | bc -l) )); then
            min_rate=$r
        fi
    done

    for l in "${latencies[@]}"; do
        total_latency=$(echo "$total_latency + $l" | bc)
    done

    for t in "${throughputs[@]}"; do
        total_throughput=$(echo "$total_throughput + $t" | bc)
    done

    num_samples=${#rates[@]}
    avg_rate=$(echo "scale=2; $total_rate / $num_samples" | bc)
    avg_latency=$(echo "scale=2; $total_latency / $num_samples" | bc)
    avg_throughput=$(echo "scale=2; $total_throughput / $num_samples" | bc)

    echo ""
    echo -e "${GREEN}Events Indexed Per Second:${NC}"
    echo -e "  Average:  $avg_rate events/sec"
    echo -e "  Maximum:  $max_rate events/sec"
    echo -e "  Minimum:  $min_rate events/sec"
    echo ""
    echo -e "${GREEN}Indexing Latency:${NC}"
    echo -e "  Average:  $avg_latency ms/event"
    echo ""
    echo -e "${GREEN}Data Throughput:${NC}"
    echo -e "  Average:  $avg_throughput KB/sec"
    echo -e "  Average:  $(echo "scale=4; $avg_throughput / 1024" | bc) MB/sec"
    echo ""
    echo -e "${GREEN}Test Duration:${NC}"
    echo -e "  Total:    $elapsed seconds"
    echo -e "  Samples:  $num_samples"

    # Final document count
    final_docs=$(get_doc_count)
    final_store=$(get_store_size)

    echo ""
    echo -e "${GREEN}Final State:${NC}"
    echo -e "  Total Documents:  $final_docs"
    echo -e "  Total Store Size: $(echo "scale=2; $final_store / 1048576" | bc) MB"

    # Save to JSON if output file specified
    if [ -n "$OUTPUT_FILE" ]; then
        cat > "$OUTPUT_FILE" << EOF
{
    "test_timestamp": "$(date -Iseconds)",
    "duration_seconds": $elapsed,
    "num_samples": $num_samples,
    "config": {
        "indexer_host": "$INDEXER_HOST",
        "filebeat_host": "$FILEBEAT_HOST",
        "sample_interval": $INTERVAL
    },
    "results": {
        "events_per_second": {
            "average": $avg_rate,
            "maximum": $max_rate,
            "minimum": $min_rate
        },
        "latency_ms": {
            "average": $avg_latency
        },
        "throughput_kb_per_sec": {
            "average": $avg_throughput
        },
        "final_state": {
            "total_documents": $final_docs,
            "total_store_bytes": $final_store
        }
    }
}
EOF
        echo ""
        echo -e "${GREEN}Results saved to: $OUTPUT_FILE${NC}"
    fi
else
    echo -e "${RED}No samples collected!${NC}"
fi

echo ""
echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}  MEASUREMENT COMPLETE${NC}"
echo -e "${BLUE}============================================${NC}"
