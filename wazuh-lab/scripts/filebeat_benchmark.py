#!/usr/bin/env python3
"""
Filebeat Speed Benchmark Tool
Measures Filebeat throughput, latency, and performance metrics
"""

import json
import time
import os
import sys
import signal
import requests
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional
import statistics

# Configuration from environment
FILEBEAT_HOST = os.getenv('FILEBEAT_HOST', 'filebeat:5066')
INDEXER_HOST = os.getenv('INDEXER_HOST', 'wazuh-indexer:9200')
BENCHMARK_DURATION = int(os.getenv('BENCHMARK_DURATION', '300'))  # 5 minutes
SAMPLE_INTERVAL = int(os.getenv('SAMPLE_INTERVAL', '5'))  # 5 seconds
RESULTS_DIR = Path(os.getenv('RESULTS_DIR', '/app/results'))

# Ensure results directory exists
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

running = True

def signal_handler(sig, frame):
    global running
    print("\nStopping benchmark...")
    running = False

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


@dataclass
class FilebeatMetrics:
    """Filebeat metrics snapshot"""
    timestamp: str
    # Libbeat metrics
    events_published: int = 0
    events_acked: int = 0
    events_failed: int = 0
    events_dropped: int = 0
    events_active: int = 0
    events_batches: int = 0
    # Output metrics
    output_bytes: int = 0
    output_write_bytes: int = 0
    output_read_bytes: int = 0
    # Harvester metrics
    files_open: int = 0
    files_harvested: int = 0
    # Pipeline metrics
    pipeline_events_total: int = 0
    pipeline_events_filtered: int = 0
    pipeline_events_published: int = 0
    # Queue metrics
    queue_events: int = 0
    queue_filled_percent: float = 0.0


@dataclass
class IndexerMetrics:
    """Wazuh Indexer metrics snapshot"""
    timestamp: str
    # Document counts
    docs_count: int = 0
    docs_deleted: int = 0
    # Store size
    store_size_bytes: int = 0
    # Indexing metrics
    indexing_index_total: int = 0
    indexing_index_time_ms: int = 0
    indexing_delete_total: int = 0
    # Search metrics
    search_query_total: int = 0
    search_query_time_ms: int = 0
    search_fetch_total: int = 0
    # Cluster health
    cluster_status: str = "unknown"
    active_shards: int = 0
    unassigned_shards: int = 0


@dataclass
class BenchmarkSample:
    """A single benchmark sample"""
    timestamp: str
    elapsed_seconds: float
    # Filebeat rates (per second)
    events_published_rate: float = 0.0
    events_acked_rate: float = 0.0
    events_failed_rate: float = 0.0
    throughput_bytes_per_sec: float = 0.0
    # Indexer rates
    indexing_rate: float = 0.0
    indexing_latency_ms: float = 0.0
    # Lag
    event_lag: int = 0  # events_published - indexing_total


@dataclass
class BenchmarkResult:
    """Complete benchmark results"""
    start_time: str
    end_time: str
    duration_seconds: float
    samples: List[BenchmarkSample] = field(default_factory=list)
    # Summary statistics
    summary: Dict = field(default_factory=dict)


def get_filebeat_metrics() -> Optional[FilebeatMetrics]:
    """Fetch metrics from Filebeat HTTP endpoint"""
    try:
        response = requests.get(f"http://{FILEBEAT_HOST}/stats", timeout=5)
        if response.status_code != 200:
            return None

        data = response.json()
        timestamp = datetime.utcnow().isoformat() + "Z"

        metrics = FilebeatMetrics(timestamp=timestamp)

        # Parse libbeat metrics
        libbeat = data.get('libbeat', {})
        output = libbeat.get('output', {})
        pipeline = libbeat.get('pipeline', {})

        # Events metrics
        events = output.get('events', {})
        metrics.events_published = events.get('total', 0)
        metrics.events_acked = events.get('acked', 0)
        metrics.events_failed = events.get('failed', 0)
        metrics.events_dropped = events.get('dropped', 0)
        metrics.events_active = events.get('active', 0)
        metrics.events_batches = events.get('batches', 0)

        # Output bytes
        write = output.get('write', {})
        read = output.get('read', {})
        metrics.output_write_bytes = write.get('bytes', 0)
        metrics.output_read_bytes = read.get('bytes', 0)
        metrics.output_bytes = metrics.output_write_bytes + metrics.output_read_bytes

        # Pipeline metrics
        pipeline_events = pipeline.get('events', {})
        metrics.pipeline_events_total = pipeline_events.get('total', 0)
        metrics.pipeline_events_filtered = pipeline_events.get('filtered', 0)
        metrics.pipeline_events_published = pipeline_events.get('published', 0)

        # Queue metrics
        queue = pipeline.get('queue', {})
        metrics.queue_events = queue.get('events', 0)
        max_events = queue.get('max_events', 1)
        metrics.queue_filled_percent = (metrics.queue_events / max_events) * 100 if max_events > 0 else 0

        # Filebeat specific metrics
        filebeat = data.get('filebeat', {})
        harvester = filebeat.get('harvester', {})
        metrics.files_open = harvester.get('open_files', 0)
        metrics.files_harvested = harvester.get('running', 0)

        return metrics

    except Exception as e:
        print(f"Error fetching Filebeat metrics: {e}")
        return None


def get_indexer_metrics() -> Optional[IndexerMetrics]:
    """Fetch metrics from Wazuh Indexer"""
    try:
        timestamp = datetime.utcnow().isoformat() + "Z"
        metrics = IndexerMetrics(timestamp=timestamp)

        # Get cluster health
        health_response = requests.get(f"http://{INDEXER_HOST}/_cluster/health", timeout=5)
        if health_response.status_code == 200:
            health = health_response.json()
            metrics.cluster_status = health.get('status', 'unknown')
            metrics.active_shards = health.get('active_shards', 0)
            metrics.unassigned_shards = health.get('unassigned_shards', 0)

        # Get index stats
        stats_response = requests.get(f"http://{INDEXER_HOST}/_stats", timeout=5)
        if stats_response.status_code == 200:
            stats = stats_response.json()
            all_stats = stats.get('_all', {}).get('primaries', {})

            # Docs
            docs = all_stats.get('docs', {})
            metrics.docs_count = docs.get('count', 0)
            metrics.docs_deleted = docs.get('deleted', 0)

            # Store
            store = all_stats.get('store', {})
            metrics.store_size_bytes = store.get('size_in_bytes', 0)

            # Indexing
            indexing = all_stats.get('indexing', {})
            metrics.indexing_index_total = indexing.get('index_total', 0)
            metrics.indexing_index_time_ms = indexing.get('index_time_in_millis', 0)
            metrics.indexing_delete_total = indexing.get('delete_total', 0)

            # Search
            search = all_stats.get('search', {})
            metrics.search_query_total = search.get('query_total', 0)
            metrics.search_query_time_ms = search.get('query_time_in_millis', 0)
            metrics.search_fetch_total = search.get('fetch_total', 0)

        return metrics

    except Exception as e:
        print(f"Error fetching Indexer metrics: {e}")
        return None


def calculate_rates(prev: Optional[Dict], curr: Dict, interval: float) -> BenchmarkSample:
    """Calculate rates between two samples"""
    timestamp = datetime.utcnow().isoformat() + "Z"

    if prev is None:
        return BenchmarkSample(timestamp=timestamp, elapsed_seconds=0)

    sample = BenchmarkSample(timestamp=timestamp, elapsed_seconds=interval)

    # Filebeat rates
    if 'filebeat' in prev and 'filebeat' in curr:
        fb_prev = prev['filebeat']
        fb_curr = curr['filebeat']

        sample.events_published_rate = (fb_curr.events_published - fb_prev.events_published) / interval
        sample.events_acked_rate = (fb_curr.events_acked - fb_prev.events_acked) / interval
        sample.events_failed_rate = (fb_curr.events_failed - fb_prev.events_failed) / interval
        sample.throughput_bytes_per_sec = (fb_curr.output_bytes - fb_prev.output_bytes) / interval

    # Indexer rates
    if 'indexer' in prev and 'indexer' in curr:
        idx_prev = prev['indexer']
        idx_curr = curr['indexer']

        index_diff = idx_curr.indexing_index_total - idx_prev.indexing_index_total
        time_diff = idx_curr.indexing_index_time_ms - idx_prev.indexing_index_time_ms

        sample.indexing_rate = index_diff / interval
        sample.indexing_latency_ms = time_diff / index_diff if index_diff > 0 else 0

        # Event lag (Filebeat published vs Indexer indexed)
        if 'filebeat' in curr:
            sample.event_lag = curr['filebeat'].events_published - idx_curr.indexing_index_total

    return sample


def calculate_summary(samples: List[BenchmarkSample]) -> Dict:
    """Calculate summary statistics from samples"""
    if not samples:
        return {}

    def safe_stats(values):
        if not values or len(values) < 2:
            return {"mean": 0, "min": 0, "max": 0, "std": 0, "median": 0}
        return {
            "mean": round(statistics.mean(values), 2),
            "min": round(min(values), 2),
            "max": round(max(values), 2),
            "std": round(statistics.stdev(values), 2),
            "median": round(statistics.median(values), 2)
        }

    # Extract values
    published_rates = [s.events_published_rate for s in samples if s.events_published_rate > 0]
    acked_rates = [s.events_acked_rate for s in samples if s.events_acked_rate > 0]
    throughput = [s.throughput_bytes_per_sec for s in samples if s.throughput_bytes_per_sec > 0]
    indexing_rates = [s.indexing_rate for s in samples if s.indexing_rate > 0]
    indexing_latency = [s.indexing_latency_ms for s in samples if s.indexing_latency_ms > 0]
    event_lags = [s.event_lag for s in samples]

    return {
        "events_published_per_sec": safe_stats(published_rates),
        "events_acked_per_sec": safe_stats(acked_rates),
        "throughput_bytes_per_sec": safe_stats(throughput),
        "throughput_mb_per_sec": {
            k: round(v / (1024 * 1024), 4) if isinstance(v, (int, float)) else v
            for k, v in safe_stats(throughput).items()
        },
        "indexing_rate_per_sec": safe_stats(indexing_rates),
        "indexing_latency_ms": safe_stats(indexing_latency),
        "event_lag": safe_stats(event_lags),
        "total_samples": len(samples)
    }


def print_sample(sample: BenchmarkSample, fb: Optional[FilebeatMetrics], idx: Optional[IndexerMetrics]):
    """Print a sample to console"""
    print(f"\n{'='*60}")
    print(f"Timestamp: {sample.timestamp}")
    print(f"{'='*60}")

    print(f"\nFILEBEAT METRICS:")
    print(f"  Events Published Rate:  {sample.events_published_rate:,.1f} events/sec")
    print(f"  Events Acked Rate:      {sample.events_acked_rate:,.1f} events/sec")
    print(f"  Events Failed Rate:     {sample.events_failed_rate:,.1f} events/sec")
    print(f"  Throughput:             {sample.throughput_bytes_per_sec / (1024*1024):.2f} MB/sec")

    if fb:
        print(f"  Queue Fill:             {fb.queue_filled_percent:.1f}%")
        print(f"  Files Open:             {fb.files_open}")

    print(f"\nINDEXER METRICS:")
    print(f"  Indexing Rate:          {sample.indexing_rate:,.1f} docs/sec")
    print(f"  Indexing Latency:       {sample.indexing_latency_ms:.2f} ms/doc")
    print(f"  Event Lag:              {sample.event_lag:,} events")

    if idx:
        print(f"  Total Documents:        {idx.docs_count:,}")
        print(f"  Store Size:             {idx.store_size_bytes / (1024*1024):.2f} MB")
        print(f"  Cluster Status:         {idx.cluster_status}")


def run_benchmark():
    """Run the benchmark"""
    global running

    print(f"\n{'#'*60}")
    print(f"# FILEBEAT SPEED BENCHMARK")
    print(f"{'#'*60}")
    print(f"\nConfiguration:")
    print(f"  Filebeat Host:    {FILEBEAT_HOST}")
    print(f"  Indexer Host:     {INDEXER_HOST}")
    print(f"  Duration:         {BENCHMARK_DURATION} seconds")
    print(f"  Sample Interval:  {SAMPLE_INTERVAL} seconds")
    print(f"  Results Dir:      {RESULTS_DIR}")
    print(f"\nWaiting for services to be ready...")

    # Wait for services
    max_retries = 30
    for i in range(max_retries):
        fb = get_filebeat_metrics()
        idx = get_indexer_metrics()
        if fb and idx:
            print("Services ready!")
            break
        print(f"  Retry {i+1}/{max_retries}...")
        time.sleep(5)
    else:
        print("ERROR: Services not available after maximum retries")
        return

    # Initialize result
    start_time = datetime.utcnow()
    result = BenchmarkResult(
        start_time=start_time.isoformat() + "Z",
        end_time="",
        duration_seconds=0,
        samples=[],
        summary={}
    )

    # Previous metrics for rate calculation
    prev_metrics = None
    sample_count = 0
    elapsed = 0

    print(f"\nStarting benchmark at {start_time.isoformat()}...")
    print(f"Will run for {BENCHMARK_DURATION} seconds...")

    while running and elapsed < BENCHMARK_DURATION:
        loop_start = time.time()

        # Collect metrics
        fb_metrics = get_filebeat_metrics()
        idx_metrics = get_indexer_metrics()

        if fb_metrics and idx_metrics:
            curr_metrics = {
                'filebeat': fb_metrics,
                'indexer': idx_metrics
            }

            # Calculate rates
            sample = calculate_rates(prev_metrics, curr_metrics, SAMPLE_INTERVAL)
            sample.elapsed_seconds = elapsed

            # Store sample
            result.samples.append(sample)
            sample_count += 1

            # Print to console
            print_sample(sample, fb_metrics, idx_metrics)

            prev_metrics = curr_metrics
        else:
            print(f"\nWarning: Could not collect metrics at sample {sample_count}")

        # Sleep until next sample
        loop_elapsed = time.time() - loop_start
        sleep_time = max(0, SAMPLE_INTERVAL - loop_elapsed)
        time.sleep(sleep_time)

        elapsed += SAMPLE_INTERVAL

    # Finalize results
    end_time = datetime.utcnow()
    result.end_time = end_time.isoformat() + "Z"
    result.duration_seconds = (end_time - start_time).total_seconds()
    result.summary = calculate_summary(result.samples)

    # Print summary
    print(f"\n{'#'*60}")
    print(f"# BENCHMARK COMPLETE")
    print(f"{'#'*60}")
    print(f"\nDuration: {result.duration_seconds:.1f} seconds")
    print(f"Samples:  {len(result.samples)}")

    print(f"\nSUMMARY STATISTICS:")
    summary = result.summary
    if summary:
        print(f"\n  Events Published (events/sec):")
        stats = summary.get('events_published_per_sec', {})
        print(f"    Mean:   {stats.get('mean', 0):,.2f}")
        print(f"    Median: {stats.get('median', 0):,.2f}")
        print(f"    Min:    {stats.get('min', 0):,.2f}")
        print(f"    Max:    {stats.get('max', 0):,.2f}")
        print(f"    Std:    {stats.get('std', 0):,.2f}")

        print(f"\n  Throughput (MB/sec):")
        stats = summary.get('throughput_mb_per_sec', {})
        print(f"    Mean:   {stats.get('mean', 0):.4f}")
        print(f"    Median: {stats.get('median', 0):.4f}")
        print(f"    Max:    {stats.get('max', 0):.4f}")

        print(f"\n  Indexing Rate (docs/sec):")
        stats = summary.get('indexing_rate_per_sec', {})
        print(f"    Mean:   {stats.get('mean', 0):,.2f}")
        print(f"    Median: {stats.get('median', 0):,.2f}")
        print(f"    Max:    {stats.get('max', 0):,.2f}")

        print(f"\n  Indexing Latency (ms/doc):")
        stats = summary.get('indexing_latency_ms', {})
        print(f"    Mean:   {stats.get('mean', 0):.2f}")
        print(f"    P50:    {stats.get('median', 0):.2f}")
        print(f"    Max:    {stats.get('max', 0):.2f}")

        print(f"\n  Event Lag:")
        stats = summary.get('event_lag', {})
        print(f"    Mean:   {stats.get('mean', 0):,.0f}")
        print(f"    Max:    {stats.get('max', 0):,.0f}")

    # Save results to file
    result_file = RESULTS_DIR / f"benchmark_{start_time.strftime('%Y%m%d_%H%M%S')}.json"
    with open(result_file, 'w') as f:
        # Convert dataclasses to dicts
        result_dict = {
            'start_time': result.start_time,
            'end_time': result.end_time,
            'duration_seconds': result.duration_seconds,
            'summary': result.summary,
            'samples': [asdict(s) for s in result.samples]
        }
        json.dump(result_dict, f, indent=2)

    print(f"\nResults saved to: {result_file}")

    # Save summary to separate file
    summary_file = RESULTS_DIR / f"summary_{start_time.strftime('%Y%m%d_%H%M%S')}.json"
    with open(summary_file, 'w') as f:
        json.dump({
            'start_time': result.start_time,
            'end_time': result.end_time,
            'duration_seconds': result.duration_seconds,
            'summary': result.summary
        }, f, indent=2)

    print(f"Summary saved to: {summary_file}")


if __name__ == "__main__":
    run_benchmark()
