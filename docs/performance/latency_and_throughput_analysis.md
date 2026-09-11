# Performance Analysis: Micro-benchmarks & Concurrency Scaling

**Target Platform:** ARM64 macOS & Linux  
**Testing Tools:** `benchmark_matcher_comparison` & `offline/benchmarks/runner.py`  

---

## 1. Nanosecond-Level Micro-benchmarks

### Suffix Trie vs. Aho-Corasick at 100,000 Rules
- **Lookup Latency ($p_{50}$):** Suffix Trie sustained **167.0 ns** vs. **167.0 ns** for Aho-Corasick.
- **Construction Overhead:** Suffix Trie built in **25.88 ms** vs. **129.59 ms** for Aho-Corasick ($5.0\times$ slower).
- **Resident Memory:** Suffix Trie consumed **4.59 MB** vs. **162.98 MB** for Aho-Corasick ($35.5\times$ smaller).

### LRU Cache Operation Latency
- **Cache Hit ($p_{50}$):** **125.0 ns** (~7.02 Million operations/second).
- **Cache Miss ($p_{50}$):** **84.0 ns** (~10.56 Million operations/second).
- **Stale Generation Invalidation:** **84.0 ns** (~9.61 Million operations/second).

---

## 2. End-to-End Network Throughput (UDP Datagrams)

Under concurrent multi-threaded load generators:
- **Peak Throughput:** **~17,420 QPS** achieved under 10 concurrent streams.
- **Single-Client Median Latency:** **48.1 µs** for policy NXDOMAIN blocks and **61.2 µs** for in-memory cache hits.
- **Tail Latency ($p_{99}$):** Bounded at **999.4 µs** under 10 concurrent clients.
