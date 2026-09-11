#!/usr/bin/env python3
"""
ARM64 DNS Security Dataplane: Automated Benchmark Orchestrator
Measures QPS, tail latency percentiles (p50, p90, p95, p99, p99.9),
and failure rates across controlled concurrency and workload matrices.
"""

import socket
import time
import argparse
import json
import statistics
import concurrent.futures
from pathlib import Path
from datetime import datetime

def make_dns_query(domain: str, txid: int = 0x1234, qtype: int = 1) -> bytes:
    pkt = bytearray(12)
    pkt[0] = (txid >> 8) & 0xFF
    pkt[1] = txid & 0xFF
    pkt[2] = 0x01 # RD = 1
    pkt[3] = 0x00
    pkt[4] = 0x00
    pkt[5] = 0x01 # QDCOUNT = 1

    for label in domain.strip('.').split('.'):
        pkt.append(len(label))
        pkt.extend(label.encode('ascii'))
    pkt.append(0) # Null terminator

    pkt.append((qtype >> 8) & 0xFF)
    pkt.append(qtype & 0xFF)
    pkt.append(0x00)
    pkt.append(0x01) # QCLASS = IN
    return bytes(pkt)

def send_query(server_ip: str, server_port: int, query_bytes: bytes, timeout_s: float = 1.0) -> tuple[float, bool]:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout_s)
    start = time.perf_counter()
    try:
        s.sendto(query_bytes, (server_ip, server_port))
        resp, _ = s.recvfrom(512)
        elapsed_us = (time.perf_counter() - start) * 1_000_000.0
        success = len(resp) >= 12
        return elapsed_us, success
    except Exception:
        elapsed_us = (time.perf_counter() - start) * 1_000_000.0
        return elapsed_us, False
    finally:
        s.close()

def worker_thread(server_ip: str, server_port: int, queries: list[bytes], count_per_thread: int) -> list[tuple[float, bool]]:
    results = []
    num_queries = len(queries)
    for i in range(count_per_thread):
        q = queries[i % num_queries]
        res = send_query(server_ip, server_port, q)
        results.append(res)
    return results

def run_benchmark(server_ip: str, server_port: int, concurrency: int, total_queries: int, workload: str) -> dict:
    # Build query sets based on workload
    if workload == "CACHE_HIT":
        domains = ["example.com"]
    elif workload == "BLOCKED_NXDOMAIN":
        domains = ["doubleclick.net", "ad.doubleclick.net", "blocked.test"]
    else: # MIXED
        domains = ["example.com", "doubleclick.net", "sinkhole.test", "blocked.test", "safe.doubleclick.net"]

    queries = [make_dns_query(d, txid=(i + 1)) for i, d in enumerate(domains)]

    # Warmup query
    for q in queries:
        send_query(server_ip, server_port, q)
    time.sleep(0.1)

    queries_per_thread = total_queries // concurrency
    start_time = time.perf_counter()

    all_latencies = []
    success_count = 0
    error_count = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [
            executor.submit(worker_thread, server_ip, server_port, queries, queries_per_thread)
            for _ in range(concurrency)
        ]
        for f in concurrent.futures.as_completed(futures):
            for lat, ok in f.result():
                all_latencies.append(lat)
                if ok:
                    success_count += 1
                else:
                    error_count += 1

    total_duration = time.perf_counter() - start_time
    qps = len(all_latencies) / total_duration if total_duration > 0 else 0

    all_latencies.sort()
    n = len(all_latencies)

    def percentile(p: float) -> float:
        if n == 0: return 0.0
        k = (n - 1) * (p / 100.0)
        f = int(k)
        c = min(f + 1, n - 1)
        return all_latencies[f] + (all_latencies[c] - all_latencies[f]) * (k - f)

    p50 = percentile(50)
    p90 = percentile(90)
    p95 = percentile(95)
    p99 = percentile(99)
    p999 = percentile(99.9)

    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "workload": workload,
        "concurrency": concurrency,
        "total_queries": len(all_latencies),
        "duration_sec": round(total_duration, 4),
        "qps": round(qps, 2),
        "success_rate": round(success_count / n * 100.0, 2) if n > 0 else 0,
        "error_count": error_count,
        "latency_us": {
            "min": round(all_latencies[0], 2) if n > 0 else 0,
            "mean": round(statistics.mean(all_latencies), 2) if n > 0 else 0,
            "p50": round(p50, 2),
            "p90": round(p90, 2),
            "p95": round(p95, 2),
            "p99": round(p99, 2),
            "p99.9": round(p999, 2),
            "max": round(all_latencies[-1], 2) if n > 0 else 0
        }
    }

def main():
    parser = argparse.ArgumentParser(description="ARM64 DNS Dataplane Benchmark Orchestrator")
    parser.add_argument("--host", default="127.0.0.1", help="Dataplane IP")
    parser.add_argument("--port", type=int, default=1053, help="Dataplane Port")
    parser.add_argument("--output-dir", default="evidence/benchmarks/raw", help="Artifact output directory")
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    print("======================================================")
    print("  ARM64 DNS Security Dataplane: Automated Benchmark")
    print(f"  Target: {args.host}:{args.port}")
    print("======================================================")

    matrix = [
        # (Workload, Concurrency, Total Queries)
        ("BLOCKED_NXDOMAIN", 1, 1000),
        ("BLOCKED_NXDOMAIN", 10, 5000),
        ("BLOCKED_NXDOMAIN", 50, 10000),
        ("CACHE_HIT", 1, 1000),
        ("CACHE_HIT", 10, 5000),
        ("CACHE_HIT", 50, 10000),
        ("MIXED", 10, 5000)
    ]

    all_results = []
    print(f"{'Workload':<18} | {'Clients':<7} | {'Queries':<7} | {'QPS':<10} | {'p50 (us)':<9} | {'p95 (us)':<9} | {'p99 (us)':<9}")
    print("-" * 80)

    for workload, conc, num_q in matrix:
        res = run_benchmark(args.host, args.port, conc, num_q, workload)
        all_results.append(res)
        l = res["latency_us"]
        print(f"{workload:<18} | {conc:<7} | {num_q:<7} | {res['qps']:<10.1f} | {l['p50']:<9.1f} | {l['p95']:<9.1f} | {l['p99']:<9.1f}")
        time.sleep(0.5)

    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = out_dir / f"benchmark_run_{timestamp_str}.json"
    with open(out_file, "w") as f:
        json.dump(all_results, f, indent=2)

    print("-" * 80)
    print(f"Raw benchmark artifacts saved to: {out_file}\n")

if __name__ == "__main__":
    main()
