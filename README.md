# ARM64 DNS Security Dataplane
**C++20 / Linux & macOS / DNS / Security / High-Performance Systems**

[![asciicast](https://asciinema.org/a/fJARAnJTFczeodSr.svg)](https://asciinema.org/a/fJARAnJTFczeodSr)

📖 **Technical Publication:** [**Building a Sub-Microsecond DNS Security Dataplane in Modern C++20 and Go**](https://medium.com/@namanbhatt-01/building-a-sub-microsecond-dns-security-dataplane-in-modern-c-20-and-go-99ba3dd00cd3) *(Published on Medium)* · [Local Markdown Deep-Dive](docs/ARTICLE.md)

A high-performance, resource-conscious DNS security appliance implemented in zero-allocation C++20 with a Go control-plane management daemon and an offline Python benchmark pipeline. Built to RFC 1035 standards with empirical defense against cache poisoning, Kaminsky spoofing, stale-policy cache bypasses, and denial-of-service vectors.

---

## Quick Status

| Subsystem | Status | Verification Evidence |
|---|---|---|
| **Zero-Copy Parser** | ✅ Hardened | 100,000 hostile mutated packets fuzzed (`make fuzz`) with **0 crashes** |
| **Reverse-Label Suffix Trie** | ✅ Production Standard | Flat ~167 ns lookup latency across 1,000 to 100,000 rules; **0 false positives** |
| **Upstream TxID Forwarder** | ✅ Sealed (ADR-001) | Random ephemeral TxID translation; echoes and validates question section |
| **$O(1)$ LRU Cache Engine** | ✅ Sealed (ADR-004) | Monotonic TTL expiration; stale generation invalidation in **84 ns** |
| **Lock-Free RCU Pointer Swap** | ✅ Sealed (ADR-002) | Double-buffered atomic pointer swapping via `SnapshotManager` |
| **Compiler Sanitizers** | ✅ Clean | 29/29 tests pass under UBSan & ASan (`make sanitize`) with 0 memory violations |
| **Throughput & QPS** | ✅ Benchmarked | **~17,420 QPS** under 10 concurrent streams; median single-query latency **48.1 µs** |

---

## Architecture

```text
                 DNS CLIENTS (dig / live applications)
                                │
                                ▼
                        ┌───────────────┐
                        │ C++ DATAPLANE │
                        └───────┬───────┘
                                │
                 ┌──────────────┼──────────────┐
                 ▼              ▼              ▼
             Zero-Copy       Security       Generation
              Parser          Engine        LRU Cache
                 │              │              │
                 └──────────────┼──────────────┘
                                ▼
                             Decision
                            /        \
                        BLOCK        ALLOW
                                       │
                                       ▼
                               Upstream Forwarder
                              (Random Ephemeral TxID)
                                       │
                                       ▼
                             Recursive Upstream (8.8.8.8)

                           ▲
                           │ immutable snapshot swap
                           │
                    ┌──────┴───────┐
                    │ Go Control   │  REST API (:8080)
                    │ Plane        │  IPC (/tmp/dns_dataplane_control.sock)
                    └──────────────┘

      Python = OFFLINE PIPELINE + STATISTICAL BENCHMARKS + PLOTTING
```

---

## Empirical Benchmark Results

### Frame 1: Matcher Architectural Comparison (1,000 to 100,000 Rules)

<p align="center">
  <img src="evidence/perf/matcher_scaling_comparison.svg" alt="Suffix Trie vs Aho-Corasick Benchmark" width="100%"/>
</p>

*Measured via `make benchmark-matchers` across 100,000 iterations per scale with live resident memory (RSS) tracking:*

| Scale | Architecture | Build Time | Memory | $p_{50}$ Latency | $p_{99}$ Latency | Throughput | FP Errors |
|---|---|---|---|---|---|---|---|
| **1,000** | **Reverse-Label Suffix Trie** | 0.81 ms | **0.20 MB** | 334.0 ns | 667.0 ns | **2.64 M/s** | **0** |
| 1,000 | Aho-Corasick Automaton | 1.01 ms | 1.28 MB | 208.0 ns | 292.0 ns | 4.83 M/s | 3 (Failed) |
| **10,000** | **Reverse-Label Suffix Trie** | 2.82 ms | **0.84 MB** | 167.0 ns | 250.0 ns | **5.16 M/s** | **0** |
| 10,000 | Aho-Corasick Automaton | 6.83 ms | 16.20 MB | 167.0 ns | 250.0 ns | 5.98 M/s | 3 (Failed) |
| **50,000** | **Reverse-Label Suffix Trie** | 11.18 ms | **3.67 MB** | 167.0 ns | 250.0 ns | **5.51 M/s** | **0** |
| 50,000 | Aho-Corasick Automaton | 64.43 ms | 94.34 MB | 167.0 ns | 209.0 ns | 6.37 M/s | 3 (Failed) |
| **100,000** | **Reverse-Label Suffix Trie** | **25.88 ms** | **4.59 MB** | **167.0 ns** | **250.0 ns** | **5.63 M/s** | **0** |
| 100,000 | Aho-Corasick Automaton | 129.59 ms ($5.0\times$) | 162.98 MB ($35.5\times$) | 167.0 ns | 209.0 ns | 6.43 M/s | 3 (Failed) |

> **Conclusion (ADR-003):** Aho-Corasick was empirically evaluated and **formally rejected**. It consumes $35.5\times$ more memory, compiles $5\times$ slower, and fails dot-boundary checks (`notdomain.com` matches `domain.com`), requiring expensive secondary slicing.

### Frame 2: $O(1)$ LRU Cache Operations

| Cache Operation | $p_{50}$ Latency | $p_{99}$ Latency | Mean Latency | Throughput |
|---|---|---|---|---|
| **LRU Cache HIT** | **125.0 ns** | 208.0 ns | 142.5 ns | **7.02 M ops/s** |
| **LRU Cache MISS** | **84.0 ns** | 166.0 ns | 94.7 ns | **10.56 M ops/s** |
| **Stale Gen Invalidation** | **84.0 ns** | 208.0 ns | 104.0 ns | **9.61 M ops/s** |

### Frame 3: End-to-End UDP Query Throughput (Live Socket Target `127.0.0.1:1053`)

| Workload | Clients | Total Queries | Throughput (QPS) | $p_{50}$ (µs) | $p_{95}$ (µs) | $p_{99}$ (µs) |
|---|---|---|---|---|---|---|
| `BLOCKED_NXDOMAIN` | 1 | 1,000 | **12,377.3 QPS** | 48.1 µs | 161.4 µs | 191.6 µs |
| `BLOCKED_NXDOMAIN` | 10 | 5,000 | **17,419.9 QPS** | 323.5 µs | 745.1 µs | 999.4 µs |
| `CACHE_HIT` | 1 | 1,000 | **10,249.8 QPS** | 61.2 µs | 228.4 µs | 410.5 µs |
| `CACHE_HIT` | 10 | 5,000 | **16,939.2 QPS** | 349.6 µs | 871.1 µs | 1,243.1 µs |

---

## Security & Reliability Evidence

- **Fuzzing Campaign Report:** [`evidence/fuzzing/campaign.md`](evidence/fuzzing/campaign.md) — 100,000 hostile packets tested with 0 crashes.
- **Wire Capture Evidence:** [`evidence/packet-captures/stage1_verification.pcap`](evidence/packet-captures/stage1_verification.pcap) — Real `dig` queries against `8.8.8.8`.
- **Sanitizer Evidence:** [`evidence/sanitizer/ubsan_verification.md`](evidence/sanitizer/ubsan_verification.md) — 29/29 unit tests pass with zero undefined behavior.
- **Failure Handling:**
  - Upstream Timeout: [`evidence/failures/upstream-timeout.md`](evidence/failures/upstream-timeout.md)
  - Stale / Corrupt Policy Rollback: [`evidence/failures/corrupt-policy.md`](evidence/failures/corrupt-policy.md)
  - Resource Saturation: [`evidence/failures/resource-exhaustion.md`](evidence/failures/resource-exhaustion.md)

---

## Architecture Decision Records (ADRs)

1. **[ADR-001: Upstream TxID Matching & Kaminsky Spoofing Defense](docs/decisions/ADR-001-upstream-tx-matching.md)**
2. **[ADR-002: Lock-Free RCU Double-Buffering & Atomic Pointer Swaps](docs/decisions/ADR-002-lockfree-snapshot-swap.md)**
3. **[ADR-003: Domain Matching Architecture: Suffix Trie vs. Aho-Corasick](docs/decisions/ADR-003-suffix-trie-vs-ahocorasick.md)**
4. **[ADR-004: Cache Invalidation via Global Generation Tagging](docs/decisions/ADR-004-cache-generation-tagging.md)**
5. **[ADR-005: High-Performance Datapath Scaling — recvmmsg vs. io_uring vs. AF_XDP](docs/decisions/ADR-005-kernel-bypass-xdp.md)**

---

## Production Deployment & Operations

- **Operations & Incident Runbook:** **[docs/RUNBOOK.md](docs/RUNBOOK.md)**
- **Production Configuration:** **[config/config.yaml](config/config.yaml)**
- **Live Terminal Demonstration Guide:** **[docs/DEMO.md](docs/DEMO.md)**

### Running via Docker Compose

```bash
# Launch dataplane (port 1053 UDP) and control plane (port 8080 TCP)
docker compose up -d

# Verify service health
curl -s http://127.0.0.1:8080/health | jq .

# Scrape Prometheus metrics
curl -s http://127.0.0.1:8080/metrics
```

---

## Build & Verification Commands

```bash
# 1. Build release binaries
make build

# 2. Run automated TDD unit test suite (29 tests)
make test

# 3. Run test suite under UndefinedBehaviorSanitizer (UBSan) & AddressSanitizer
make sanitize

# 4. Execute 100,000 packet hostile wire fuzzing campaign
make fuzz

# 5. Run Suffix Trie vs. Aho-Corasick empirical comparison (1k - 100k rules)
make benchmark-matchers

# 6. Run end-to-end client concurrency sweep (1, 10, 50 clients)
make benchmark

# 7. Replay live terminal demonstration
asciinema play demo.cast
```
