#!/usr/bin/env python3
"""
Filebeat Registry and alerts.json Monitoring Tool

Measures:
1. Filebeat registry reads (file offset tracking)
2. New events added to alerts.json
3. Processing rate and lag between file writes and indexing

This tool monitors from OUTSIDE using default Filebeat configuration.
"""

import json
import os
import sys
import time
import signal
import subprocess
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple
import threading

# Configuration
FILEBEAT_CONTAINER = os.getenv('FILEBEAT_CONTAINER', 'filebeat')
INDEXER_HOST = os.getenv('INDEXER_HOST', 'localhost:9200')
ALERTS_FILE = os.getenv('ALERTS_FILE', './logs/alerts/alerts.json')
SAMPLE_INTERVAL = int(os.getenv('SAMPLE_INTERVAL', '2'))
DURATION = int(os.getenv('DURATION', '60'))
OUTPUT_FILE = os.getenv('OUTPUT_FILE', '')

# Colors for terminal
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    CYAN = '\033[0;36m'
    NC = '\033[0m'

running = True

def signal_handler(sig, frame):
    global running
    print(f"\n{Colors.YELLOW}Stopping measurement...{Colors.NC}")
    running = False

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


@dataclass
class RegistryEntry:
    """Filebeat registry entry for a file"""
    source: str
    offset: int
    timestamp: str
    ttl: int = -1
    identifier_name: str = ""


@dataclass
class Sample:
    """A single measurement sample"""
    timestamp: str
    elapsed_seconds: float
    # alerts.json metrics
    alerts_file_size: int = 0
    alerts_line_count: int = 0
    alerts_new_lines: int = 0
    alerts_write_rate: float = 0.0  # lines/sec
    # Registry metrics
    registry_offset: int = 0
    registry_offset_change: int = 0
    registry_read_rate: float = 0.0  # bytes/sec
    # Indexer metrics
    indexed_total: int = 0
    indexed_new: int = 0
    indexing_rate: float = 0.0  # docs/sec
    # Lag metrics
    processing_lag: int = 0  # lines written but not yet indexed
    lag_seconds: float = 0.0


@dataclass
class MeasurementResult:
    """Complete measurement results"""
    start_time: str
    end_time: str
    duration_seconds: float
    alerts_file: str
    samples: List[Sample] = field(default_factory=list)
    summary: Dict = field(default_factory=dict)


def run_command(cmd: List[str], timeout: int = 5) -> Tuple[bool, str]:
    """Run a shell command and return output"""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode == 0, result.stdout.strip()
    except Exception as e:
        return False, str(e)


def get_file_stats(filepath: str) -> Tuple[int, int]:
    """Get file size and line count"""
    try:
        path = Path(filepath)
        if not path.exists():
            return 0, 0

        size = path.stat().st_size
        with open(filepath, 'r') as f:
            lines = sum(1 for _ in f)
        return size, lines
    except Exception as e:
        print(f"{Colors.RED}Error reading file {filepath}: {e}{Colors.NC}")
        return 0, 0


def get_filebeat_registry() -> Dict[str, RegistryEntry]:
    """Get Filebeat registry data from container"""
    registry = {}

    # Try to read registry from container
    # Filebeat stores registry in /usr/share/filebeat/data/registry/filebeat/
    cmd = [
        'docker', 'exec', FILEBEAT_CONTAINER,
        'cat', '/usr/share/filebeat/data/registry/filebeat/log.json'
    ]

    success, output = run_command(cmd, timeout=10)

    if success and output:
        try:
            # Registry is NDJSON format (newline-delimited JSON)
            for line in output.strip().split('\n'):
                if line.strip():
                    entry = json.loads(line)
                    if 'k' in entry and 'v' in entry:
                        # New registry format
                        key = entry.get('k', '')
                        value = entry.get('v', {})
                        if 'source' in value:
                            source = value.get('source', '')
                            registry[source] = RegistryEntry(
                                source=source,
                                offset=value.get('offset', 0),
                                timestamp=value.get('timestamp', ''),
                                ttl=value.get('ttl', -1),
                                identifier_name=value.get('identifier_name', '')
                            )
        except json.JSONDecodeError as e:
            print(f"{Colors.YELLOW}Warning: Could not parse registry: {e}{Colors.NC}")

    return registry


def get_alerts_registry_offset(registry: Dict[str, RegistryEntry]) -> int:
    """Get the registry offset for alerts.json"""
    for source, entry in registry.items():
        if 'alerts' in source.lower() and source.endswith('.json'):
            return entry.offset
    return 0


def get_indexer_doc_count() -> int:
    """Get total indexed documents from Wazuh Indexer"""
    try:
        import urllib.request
        url = f"http://{INDEXER_HOST}/_stats"
        with urllib.request.urlopen(url, timeout=5) as response:
            data = json.loads(response.read().decode())
            return data.get('_all', {}).get('primaries', {}).get('indexing', {}).get('index_total', 0)
    except Exception as e:
        print(f"{Colors.YELLOW}Warning: Could not get indexer stats: {e}{Colors.NC}")
        return 0


def print_header():
    """Print measurement header"""
    print(f"\n{Colors.BLUE}{'='*80}{Colors.NC}")
    print(f"{Colors.BLUE}  FILEBEAT REGISTRY & ALERTS.JSON MEASUREMENT{Colors.NC}")
    print(f"{Colors.BLUE}{'='*80}{Colors.NC}")
    print(f"\nConfiguration:")
    print(f"  Filebeat Container: {FILEBEAT_CONTAINER}")
    print(f"  Indexer Host:       {INDEXER_HOST}")
    print(f"  Alerts File:        {ALERTS_FILE}")
    print(f"  Sample Interval:    {SAMPLE_INTERVAL}s")
    print(f"  Duration:           {DURATION}s")
    print()


def print_sample(sample: Sample, prev_sample: Optional[Sample] = None):
    """Print a sample to console"""
    print(f"\n{Colors.CYAN}[{sample.timestamp}] Elapsed: {sample.elapsed_seconds:.0f}s{Colors.NC}")

    print(f"\n  {Colors.GREEN}ALERTS.JSON:{Colors.NC}")
    print(f"    File Size:        {sample.alerts_file_size:,} bytes")
    print(f"    Total Lines:      {sample.alerts_line_count:,}")
    print(f"    New Lines:        +{sample.alerts_new_lines}")
    print(f"    Write Rate:       {sample.alerts_write_rate:.2f} lines/sec")

    print(f"\n  {Colors.GREEN}FILEBEAT REGISTRY:{Colors.NC}")
    print(f"    Current Offset:   {sample.registry_offset:,} bytes")
    print(f"    Offset Change:    +{sample.registry_offset_change:,} bytes")
    print(f"    Read Rate:        {sample.registry_read_rate:.2f} bytes/sec")

    print(f"\n  {Colors.GREEN}INDEXER:{Colors.NC}")
    print(f"    Total Indexed:    {sample.indexed_total:,}")
    print(f"    New Indexed:      +{sample.indexed_new}")
    print(f"    Indexing Rate:    {sample.indexing_rate:.2f} docs/sec")

    print(f"\n  {Colors.YELLOW}LAG:{Colors.NC}")
    print(f"    Processing Lag:   {sample.processing_lag:,} events")

    # Visual progress bar for lag
    if sample.alerts_line_count > 0:
        processed_pct = min(100, (sample.indexed_total / max(1, sample.alerts_line_count)) * 100)
        bar_len = 30
        filled = int(bar_len * processed_pct / 100)
        bar = '█' * filled + '░' * (bar_len - filled)
        print(f"    Progress:         [{bar}] {processed_pct:.1f}%")


def calculate_summary(samples: List[Sample]) -> Dict:
    """Calculate summary statistics"""
    if not samples:
        return {}

    def safe_avg(values):
        valid = [v for v in values if v is not None and v >= 0]
        return sum(valid) / len(valid) if valid else 0

    def safe_max(values):
        valid = [v for v in values if v is not None and v >= 0]
        return max(valid) if valid else 0

    # Extract rates
    write_rates = [s.alerts_write_rate for s in samples[1:]]  # Skip first (no rate yet)
    read_rates = [s.registry_read_rate for s in samples[1:]]
    index_rates = [s.indexing_rate for s in samples[1:]]
    lags = [s.processing_lag for s in samples]

    return {
        "alerts_json": {
            "total_lines_written": samples[-1].alerts_line_count if samples else 0,
            "final_file_size_bytes": samples[-1].alerts_file_size if samples else 0,
            "avg_write_rate_lines_per_sec": round(safe_avg(write_rates), 2),
            "max_write_rate_lines_per_sec": round(safe_max(write_rates), 2)
        },
        "filebeat_registry": {
            "final_offset_bytes": samples[-1].registry_offset if samples else 0,
            "total_bytes_read": samples[-1].registry_offset - samples[0].registry_offset if len(samples) > 1 else 0,
            "avg_read_rate_bytes_per_sec": round(safe_avg(read_rates), 2),
            "max_read_rate_bytes_per_sec": round(safe_max(read_rates), 2)
        },
        "indexer": {
            "total_docs_indexed": samples[-1].indexed_total if samples else 0,
            "docs_indexed_during_test": samples[-1].indexed_total - samples[0].indexed_total if len(samples) > 1 else 0,
            "avg_indexing_rate_docs_per_sec": round(safe_avg(index_rates), 2),
            "max_indexing_rate_docs_per_sec": round(safe_max(index_rates), 2)
        },
        "lag": {
            "avg_processing_lag_events": round(safe_avg(lags), 0),
            "max_processing_lag_events": int(safe_max(lags)),
            "final_lag_events": samples[-1].processing_lag if samples else 0
        },
        "num_samples": len(samples)
    }


def run_measurement():
    """Run the measurement"""
    global running

    print_header()

    # Check prerequisites
    print(f"{Colors.YELLOW}Checking prerequisites...{Colors.NC}")

    # Check alerts file exists
    if not Path(ALERTS_FILE).exists():
        print(f"{Colors.YELLOW}  Warning: Alerts file not found at {ALERTS_FILE}{Colors.NC}")
        print(f"  Will create monitoring anyway...")
    else:
        print(f"{Colors.GREEN}  ✓ Alerts file found{Colors.NC}")

    # Check Filebeat container
    success, _ = run_command(['docker', 'ps', '-q', '-f', f'name={FILEBEAT_CONTAINER}'])
    if success:
        print(f"{Colors.GREEN}  ✓ Filebeat container running{Colors.NC}")
    else:
        print(f"{Colors.YELLOW}  Warning: Filebeat container not found{Colors.NC}")

    # Check indexer
    doc_count = get_indexer_doc_count()
    if doc_count >= 0:
        print(f"{Colors.GREEN}  ✓ Indexer accessible (current docs: {doc_count:,}){Colors.NC}")
    else:
        print(f"{Colors.YELLOW}  Warning: Indexer not accessible{Colors.NC}")

    # Initialize result
    start_time = datetime.utcnow()
    result = MeasurementResult(
        start_time=start_time.isoformat() + "Z",
        end_time="",
        duration_seconds=0,
        alerts_file=ALERTS_FILE,
        samples=[]
    )

    # Initial measurements
    prev_file_size, prev_line_count = get_file_stats(ALERTS_FILE)
    registry = get_filebeat_registry()
    prev_offset = get_alerts_registry_offset(registry)
    prev_indexed = get_indexer_doc_count()
    prev_time = time.time()

    print(f"\n{Colors.GREEN}Starting measurement...{Colors.NC}")
    print(f"Press Ctrl+C to stop early\n")

    elapsed = 0

    while running and elapsed < DURATION:
        time.sleep(SAMPLE_INTERVAL)

        current_time = time.time()
        interval = current_time - prev_time

        # Get current stats
        file_size, line_count = get_file_stats(ALERTS_FILE)
        registry = get_filebeat_registry()
        offset = get_alerts_registry_offset(registry)
        indexed = get_indexer_doc_count()

        # Calculate deltas and rates
        new_lines = line_count - prev_line_count
        offset_change = offset - prev_offset
        new_indexed = indexed - prev_indexed

        write_rate = new_lines / interval if interval > 0 else 0
        read_rate = offset_change / interval if interval > 0 else 0
        index_rate = new_indexed / interval if interval > 0 else 0

        # Calculate lag (lines in file vs indexed)
        # Note: This is approximate as indexed includes all indices
        processing_lag = max(0, line_count - indexed) if line_count > indexed else 0

        elapsed = current_time - start_time.timestamp()

        sample = Sample(
            timestamp=datetime.utcnow().isoformat() + "Z",
            elapsed_seconds=elapsed,
            alerts_file_size=file_size,
            alerts_line_count=line_count,
            alerts_new_lines=new_lines,
            alerts_write_rate=write_rate,
            registry_offset=offset,
            registry_offset_change=offset_change,
            registry_read_rate=read_rate,
            indexed_total=indexed,
            indexed_new=new_indexed,
            indexing_rate=index_rate,
            processing_lag=processing_lag
        )

        result.samples.append(sample)
        print_sample(sample)

        # Update previous values
        prev_file_size, prev_line_count = file_size, line_count
        prev_offset = offset
        prev_indexed = indexed
        prev_time = current_time

    # Finalize results
    end_time = datetime.utcnow()
    result.end_time = end_time.isoformat() + "Z"
    result.duration_seconds = (end_time - start_time).total_seconds()
    result.summary = calculate_summary(result.samples)

    # Print summary
    print(f"\n{Colors.BLUE}{'='*80}{Colors.NC}")
    print(f"{Colors.BLUE}  MEASUREMENT SUMMARY{Colors.NC}")
    print(f"{Colors.BLUE}{'='*80}{Colors.NC}")

    summary = result.summary

    print(f"\n  {Colors.GREEN}ALERTS.JSON WRITE PERFORMANCE:{Colors.NC}")
    print(f"    Total Lines Written:    {summary['alerts_json']['total_lines_written']:,}")
    print(f"    Final File Size:        {summary['alerts_json']['final_file_size_bytes']:,} bytes")
    print(f"    Avg Write Rate:         {summary['alerts_json']['avg_write_rate_lines_per_sec']:.2f} lines/sec")
    print(f"    Max Write Rate:         {summary['alerts_json']['max_write_rate_lines_per_sec']:.2f} lines/sec")

    print(f"\n  {Colors.GREEN}FILEBEAT REGISTRY READ PERFORMANCE:{Colors.NC}")
    print(f"    Final Offset:           {summary['filebeat_registry']['final_offset_bytes']:,} bytes")
    print(f"    Total Bytes Read:       {summary['filebeat_registry']['total_bytes_read']:,} bytes")
    print(f"    Avg Read Rate:          {summary['filebeat_registry']['avg_read_rate_bytes_per_sec']:.2f} bytes/sec")
    print(f"    Max Read Rate:          {summary['filebeat_registry']['max_read_rate_bytes_per_sec']:.2f} bytes/sec")

    print(f"\n  {Colors.GREEN}INDEXER PERFORMANCE:{Colors.NC}")
    print(f"    Total Docs Indexed:     {summary['indexer']['total_docs_indexed']:,}")
    print(f"    Docs During Test:       {summary['indexer']['docs_indexed_during_test']:,}")
    print(f"    Avg Indexing Rate:      {summary['indexer']['avg_indexing_rate_docs_per_sec']:.2f} docs/sec")
    print(f"    Max Indexing Rate:      {summary['indexer']['max_indexing_rate_docs_per_sec']:.2f} docs/sec")

    print(f"\n  {Colors.YELLOW}PROCESSING LAG:{Colors.NC}")
    print(f"    Avg Lag:                {summary['lag']['avg_processing_lag_events']:.0f} events")
    print(f"    Max Lag:                {summary['lag']['max_processing_lag_events']} events")
    print(f"    Final Lag:              {summary['lag']['final_lag_events']} events")

    print(f"\n  Duration: {result.duration_seconds:.1f} seconds")
    print(f"  Samples:  {summary['num_samples']}")

    # Save results if output file specified
    if OUTPUT_FILE:
        output_path = Path(OUTPUT_FILE)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        result_dict = {
            'start_time': result.start_time,
            'end_time': result.end_time,
            'duration_seconds': result.duration_seconds,
            'alerts_file': result.alerts_file,
            'summary': result.summary,
            'samples': [asdict(s) for s in result.samples]
        }

        with open(output_path, 'w') as f:
            json.dump(result_dict, f, indent=2)

        print(f"\n  {Colors.GREEN}Results saved to: {OUTPUT_FILE}{Colors.NC}")

    print(f"\n{Colors.BLUE}{'='*80}{Colors.NC}")


if __name__ == "__main__":
    run_measurement()
