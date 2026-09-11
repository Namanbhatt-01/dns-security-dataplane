# ARM64 DNS SECURITY DATAPLANE: MASTER PLAN V4.0 (HARDENED)
===============================================================================

**Project Name:** `arm64-dns-security-dataplane`  
**Portfolio Title:** ARM64 DNS Security Dataplane  
**Subheading:** A C++20/Linux network-security dataplane with Go control-plane management, lock-free RCU policy swapping, reproducible latency evaluation, protocol fuzzing, fault injection, and packet-level wire validation.  
**Research / Systems Title:** Design, Implementation, and Experimental Evaluation of a Resource-Conscious DNS Security Dataplane on ARM64 Linux Systems.

---

## 1. Executive Summary & Core Principle

This document represents the authoritative, hardened blueprint for the DNS Security Dataplane. It addresses all architectural loopholes, protocol spoofing attack surfaces, and synchronization pitfalls identified in prior iterations.

The project does not aim to build the largest possible feature set. It demonstrates deep competence across the entire systems and network engineering stack:
1. Low-level network socket programming (UDP/TCP, framing, descriptor management)
2. High-performance, zero-allocation C++ systems programming
3. Linux OS engineering, memory safety, and concurrency primitives
4. Strict DNS protocol compliance (RFC 1035 wire specifications, pointer protection)
5. Zero-trust security engineering and defense-in-depth policy hierarchies
6. Systematic debugging, sanitizers, and protocol fuzzing campaigns
7. Empirical performance profiling, flamegraphs, and reproducible evaluation

### The Unbreakable Development Philosophy
$$\text{BUILD} \longrightarrow \text{BREAK} \longrightarrow \text{MEASURE} \longrightarrow \text{DEBUG} \longrightarrow \text{FIX} \longrightarrow \text{PROVE}$$

- Compilation does not imply correctness.
- A phase is complete **only** when machine-verifiable evidence (unit tests, sanitizer logs, fuzz corpora, PCAP captures, raw benchmark artifacts) exists.

---

## 2. Architectural Boundaries & Language Separation

```
                              ┌─────────────────────────┐
                              │       DNS CLIENTS       │
                              └────────────┬────────────┘
                                           │ UDP / TCP :1053
                                           ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                   C++20 DATAPLANE                                      │
│                                                                                        │
│   ┌───────────────────┐       ┌────────────────────┐       ┌───────────────────────┐   │
│   │ Socket Listener   │ ───►  │ Zero-Copy Parser   │ ───►  │ Domain Normalizer     │   │
│   │ (UDP / TCP-framed)│       │ (RFC 1035 / Bounds)│       │ (lowercase, trim dot) │   │
│   └───────────────────┘       └────────────────────┘       └───────────┬───────────┘   │
│                                                                        │               │
│   ┌────────────────────────────────────────────────────────────────────┘               │
│   │                                                                                    │
│   ▼                                                                                    │
│ ┌───────────────────────┐       ┌───────────────────────┐                              │
│ │ Policy Precedence     │       │ Generation-Tagged     │                              │
│ │ Engine (Lock-Free)    │ ────► │ Cache (TTL-aware)     │                              │
│ └──────────┬────────────┘       └───────────┬───────────┘                              │
│            │                                │                                          │
│     ┌──────┴──────┐                  Cache Hit / Miss                                  │
│     ▼             ▼                         │                                          │
│   BLOCK        ALLOW / FORWARD ◄────────────┘                                          │
│ (Sinkhole/NX)     │                                                                    │
│                   ▼                                                                    │
│       ┌───────────────────────┐         ┌────────────────────────┐                     │
│       │ Upstream Proxy        │ ──────► │ Upstream DNS Resolver  │                     │
│       │ (TxID / Port Mapper)  │ ◄────── │ (e.g. 8.8.8.8 :53)     │                     │
│       └───────────┬───────────┘         └────────────────────────┘                     │
│                   │                                                                    │
│                   ▼                                                                    │
│       ┌───────────────────────┐                                                        │
│       │ Wire Response Builder │ ───► DNS Response to Client                            │
│       └───────────┬───────────┘                                                        │
│                   │                                                                    │
│                   ▼                                                                    │
│       ┌───────────────────────┐                                                        │
│       │ Ring-Buffer Telemetry │ (Non-blocking, drop-on-full)                          │
│       └───────────────────────┘                                                        │
└───────────────────▲────────────────────────────────────────────────────────────────────┘
                    │ Unix Domain Socket IPC (Candidate staging & atomic swap)
                    │
┌───────────────────┴───────────────────┐    ┌───────────────────────────────────────────┐
│           GO CONTROL PLANE            │    │        PYTHON OFFLINE INTELLIGENCE        │
│  - REST API (:8080) /metrics          │    │  - Threat feed sanitization & hash        │
│  - Candidate policy validation        │    │  - Workload generation (normal/attack)    │
│  - Atomic pointer swap signal         │    │  - Automated statistical benchmark runner │
│  - Automatic rollback on failure      │    │  - Matplotlib / Flamegraph report builder │
└───────────────────────────────────────┘    └───────────────────────────────────────────┘
```

### Tri-Language Division of Responsibilities
- **C++20 (Live Dataplane):** Zero allocations on the request hot path. Owns socket operations, wire parsing, domain normalization, trie lookups, cache lookups, upstream proxying, and lock-free telemetry.  
  *Invariant:* No Go, Python, disk I/O, database calls, or blocking mutexes on the hot path.
- **Go (Control Plane):** Owns management REST APIs, candidate policy validation, candidate staging, atomic update signaling, and health/Prometheus metrics endpoints.  
  *Invariant:* Zero DNS traffic ever passes through Go.
- **Python (Offline Tooling):** Owns feed normalization, deduplication, cryptographic hashing, benchmark orchestration, statistical analysis, and automated plotting.  
  *Invariant:* Python never touches a live network request.

---

## 3. The 10 Hardened Architectural Solutions

### 1. Platform Positioning (ARM64 as Evaluation Platform)
- ARM64 Linux is the empirical deployment target, chosen to evaluate hardware cache-line alignment, instruction density, memory footprint, and tail latency under constrained CPU and RAM.
- Novelty is claimed in **system architecture, measured trade-offs, and empirical verification**, not in ARM64 instruction-set extensions.

### 2. Upstream Transaction State Machine (Spoofing Defense)
To prevent DNS cache poisoning and Kaminsky-style blind spoofing:
1. Client query arrives with client TxID ($TxID_c$).
2. Dataplane assigns a cryptographically random upstream TxID ($TxID_u$) using an entropy source (`getrandom()` / hardware RNG).
3. The query is forwarded from an ephemeral UDP socket to the upstream resolver.
4. An in-flight transaction record tracks `(TxID_u, QNAME, QTYPE, timestamp, client_endpoint, TxID_c)`.
5. Upon receiving an upstream response, the engine verifies:
   - Remote source IP and UDP port match the configured upstream resolver.
   - Response $TxID == TxID_u$.
   - $QR == 1$ (Response flag set).
   - The Question section byte-for-byte matches the original pending query.
   - Response arrived within the timeout threshold ($T \le 1.5\text{s}$).
6. Only verified packets are inserted into the cache and forwarded to the client (with $TxID$ translated back to $TxID_c$).

### 3. Generation-Tagged Cache Invalidation (Preventing Stale Bypass)
- To prevent previously cached `ALLOW` responses from bypassing newly enacted security blocklists, cache entries are tagged with the active `policy_generation`.
- When a policy update is activated, the global atomic generation counter is incremented.
- On cache hit, if `entry.policy_generation != g_global_policy_generation`, the entry is treated as an immediate cache miss and forced through the updated policy engine.

### 4. Stateful TCP DNS Framing & Lifecycle
- RFC 1035 requires a 2-byte big-endian length prefix before every TCP DNS message.
- The TCP listener implements:
  - Non-blocking I/O with connection reassembly buffers to handle partial `read()` and `write()` calls.
  - Idle connection timeout ($T_{\text{idle}} = 10\text{s}$).
  - Global client connection limit ($N_{\text{max}} = 512$) to eliminate file descriptor exhaustion (`EMFILE`).

### 5. Production Suffix Trie vs. Aho-Corasick Research Boundary
- **Production Standard:** Reverse-Label Suffix Trie. Domain labels are tokenized by dots (`.`) and traversed in reverse order (`com` $\to$ `example` $\to$ `sub`). This guarantees strict boundary compliance: `example.com` matches `sub.example.com` but never matches `fakeexample.com` or `example.com.attacker.org`.
- **Research Candidate:** Aho-Corasick automaton. Evaluated strictly as a comparative baseline to measure and document why byte-level substring matching incurs excessive memory and boundary-validation overhead for DNS.

### 6. Pipeline Data Integrity Over List Downloading
- Threat intelligence is evaluated on data pipeline reliability: schema verification, format sanitization, deduplication, SHA-256 manifest hashing, candidate staging, and automatic rollback upon error.

### 7. Heuristic Anomaly Observability (No Security Theater)
- Shannon entropy and label metrics operate strictly in `ALERT_AND_ALLOW` mode.
- Heuristics generate operational telemetry but **never** autonomously block queries, preventing false-positive outages caused by legitimate CDN subdomains.

### 8. Unified Central Research Hypothesis
All performance and scaling experiments support one central question:
> *"How do security policy scale, caching dynamics, and concurrency architectures jointly impact the tail latency ($p_{99}$), throughput, RSS footprint, and failure resilience of a resource-constrained DNS security appliance on ARM64 Linux?"*

### 9. Asynchronous I/O Scope Protection
- Non-blocking POSIX sockets with `epoll` form the production core.
- `io_uring` is strictly an optional Phase 5 research extension. Fuzzing, memory safety, and fault testing take absolute precedence over `io_uring`.

### 10. Concrete Systems Credibility
- Alignment with elite networking roles is demonstrated via wire captures (.pcap), zero memory leaks under AddressSanitizer/UBSan, flamegraphs, and documented Architecture Decision Records (ADRs).

---

## 4. Concrete C++ Systems Mechanics

### Lock-Free Atomic Policy Swap Pattern
```cpp
// Immutable compiled policy state
struct PolicySnapshot {
    uint64_t generation;
    std::string version_hash;
    DomainSuffixTrie suffix_trie;
    std::unordered_set<std::string> exact_blocks;
    std::unordered_set<std::string> allowlist;
};

// Global atomic pointer providing RCU-like read semantics
extern std::atomic<std::shared_ptr<const PolicySnapshot>> g_active_policy;
extern std::atomic<uint64_t> g_global_policy_generation;

// Hot-path worker query evaluation (zero mutex locking):
inline PolicyDecision evaluate_policy(const std::string& normalized_domain) {
    // Acquire local shared ownership via atomic load
    std::shared_ptr<const PolicySnapshot> snapshot = std::atomic_load(&g_active_policy);

    if (snapshot->allowlist.contains(normalized_domain)) {
        return PolicyDecision::Allow();
    }
    if (snapshot->exact_blocks.contains(normalized_domain)) {
        return PolicyDecision::Block("EXACT_MATCH");
    }
    if (snapshot->suffix_trie.matches(normalized_domain)) {
        return PolicyDecision::Block("SUFFIX_TRIE_MATCH");
    }
    return PolicyDecision::DefaultAllow();
}
```

### Resource Quotas & Deterministic Limit Breach Actions
```
Resource                  Limit               Breach Action
------------------------------------------------------------------------------------------
UDP Packet Size           512 bytes (standard) Truncate payload, set TC=1 flag (retry TCP)
EDNS0 Packet Size         4096 bytes          Reject with FORMERR if exceeded
Compression Pointer Depth 8 hops max          Reject with FORMERR (loop defense)
Telemetry Ring Buffer     10,000 events       Drop event, increment telemetry_dropped_total
Upstream In-Flight Pool   2,048 queries       Return SERVFAIL with rate limiting
Cache Memory Ceiling      64 MB               Reject insertion, trigger async LRU prune
Client TCP Connections    512 connections     Refuse new connections (close socket)
Control API Body Size     2 MB max            HTTP 413 Payload Too Large
```

---

## 5. The 5-Stage Gated Implementation Roadmap

```
STAGE 1: Core Dataplane
  │ (UDP, Bounded RFC 1035 Parser, Upstream Forwarder, Wire Builder)
  ▼
STAGE 2: Security Hardening
  │ (Suffix Trie, Generation Cache, ASan/UBSan, libFuzzer Campaign)
  ▼
STAGE 3: Control Plane & Resilience
  │ (Go REST API, Atomic Pointer Swap, Fault Injection, TCP DNS)
  ▼
STAGE 4: Profiling & Performance Evidence
  │ (Worker Pool, perf Flamegraphs, Tail Latency Benchmarks, Rule Scaling)
  ▼
STAGE 5: Research Differentiation
    (Trie vs Aho-Corasick Study, Anomaly Alerting, Empirical Report)
```

---

### STAGE 1: Core Dataplane (The Network & Protocol Foundation)
- **Scope:**
  - Non-blocking UDP socket listener on `127.0.0.1:1053`.
  - Zero-copy RFC 1035 wire parser extracting Header, Flags, QNAME, QTYPE, and QCLASS.
  - Strict compression pointer bounds checking (depth $\le 8$, offsets $< current\_offset$).
  - Domain normalizer (lowercase conversion, trailing root dot removal).
  - Response builder (`A`, `AAAA`, `NXDOMAIN`, `REFUSED`, `FORMERR`).
  - Upstream forwarder with random ephemeral TxID translation.
- **Definition of Done (DoD):**
  - [ ] Passes 100% of unit tests for valid and malformed packets.
  - [ ] Resolves live queries via `dig @127.0.0.1 -p 1053 example.com`.
  - [ ] Wireshark PCAP verifies request/response flow and TxID mapping.
  - [ ] 0 memory leaks detected under LeakSanitizer.

---

### STAGE 2: Security Hardening (Correctness & Defensiveness)
- **Scope:**
  - Reverse-Label Suffix Trie enforcing dot-boundary semantics.
  - Exact allowlist and blocklist matchers.
  - Decision engine implementing strict precedence (Malformed $\to$ Allow $\to$ Block $\to$ Default).
  - TTL-aware cache with generation tagging.
  - Full compiler sanitizer integration: AddressSanitizer (ASan), UndefinedBehaviorSanitizer (UBSan), ThreadSanitizer (TSan).
  - libFuzzer integration targeting parser and compression pointer walker.
- **Definition of Done (DoD):**
  - [ ] Continuous 12-hour libFuzzer run with zero crashes, hangs, or OOB reads.
  - [ ] Automated regression test suite containing 50+ crafted malformed attack packets.
  - [ ] Generation-tag test proving blocked domains are not served from stale cache after policy changes.
  - [ ] Clean sanitizer runs across all test suites.

---

### STAGE 3: Control Plane & Resilience (The Appliance Model)
- **Scope:**
  - Go REST management daemon (`/health`, `/api/v1/policies`, `/api/v1/reload`, `/metrics`).
  - Unix Domain Socket IPC channel between Go and C++.
  - C++ lock-free atomic snapshot swap (`std::atomic<std::shared_ptr<const PolicySnapshot>>`).
  - Automated candidate validation and rollback on error.
  - Stateful TCP DNS handler with 2-byte length-prefix framing and client connection limits.
  - Fault injection test suite: upstream timeout, corrupt policy feed, API kill, worker saturation.
- **Definition of Done (DoD):**
  - [ ] Automated test pushes corrupted policy candidate; gateway safely rejects update, emits alert, and maintains active policy.
  - [ ] Concurrent reload benchmark: 5,000 QPS query load while pushing 100 policy reloads with zero data races under TSan.
  - [ ] TCP DNS query validation via `dig +tcp @127.0.0.1 -p 1053 example.com`.
  - [ ] Wire captures demonstrating graceful fallback during upstream timeout.

---

### STAGE 4: Profiling & Performance Evidence (Empirical Measurement)
- **Scope:**
  - Multi-threaded worker pool with partitioned request queues.
  - Non-blocking ring-buffer telemetry emitting structured JSON events.
  - Linux `perf` and flamegraph profiling pipeline (`evidence/perf/`).
  - Python automated benchmarking orchestrator: sweeps concurrency (1 to 1000) and rule scales (10K to 500K).
  - Latency percentile analysis ($p_{50}, p_{95}, p_{99}, p_{99.9}$) and QPS saturation curves.
- **Definition of Done (DoD):**
  - [ ] Single `make benchmark` command reproduces full benchmark suite from scratch.
  - [ ] Raw JSON/CSV outputs stored in `evidence/benchmarks/raw/`.
  - [ ] Automated flamegraphs identifying the top 3 CPU hotspots before and after optimization.
  - [ ] Formal performance characterization report comparing Cache ON vs. Cache OFF.

---

### STAGE 5: Research Differentiation (Standout Empirical Contribution)
- **Scope:**
  - Empirical Matcher Comparison: Reverse-Label Suffix Trie vs. Aho-Corasick vs. `std::unordered_set`.
  - Security Inspection Overhead: Baseline vs. Policy vs. Policy + Threat Intel vs. Heuristics.
  - Lightweight Anomaly Alerting: Shannon entropy and label length metrics operating strictly in `ALERT_AND_ALLOW` mode.
  - Architecture Decision Records (ADR-001 through ADR-006) documenting all design choices and rejected alternatives.
- **Definition of Done (DoD):**
  - [ ] Completed research report detailing empirical data on why Aho-Corasick was rejected for DNS boundary matching.
  - [ ] ADRs fully documented with context, alternatives, trade-offs, and empirical evidence.
  - [ ] Final technical walkthrough and demonstration script verified.

---

## 6. Cut List vs. Non-Negotiables

### Strictly Cut from V1
- ❌ Frontend Web Dashboard (React / HTML)
- ❌ Remote SIEM / Kafka / Elasticsearch integrations
- ❌ Complex Machine Learning / Neural Network DGA models
- ❌ Full DNSSEC cryptographic validation
- ❌ DoH / DoT TLS proxying and certificate management
- ❌ Multi-gigabyte external threat-feed scrapers

### Non-Negotiable Core (Must Never Be Cut)
- ✅ Zero-copy bounded DNS parser with pointer loop checks
- ✅ Reverse-Label Suffix Trie enforcing dot-boundary semantics
- ✅ AddressSanitizer, UBSan, and ThreadSanitizer clean runs
- ✅ libFuzzer campaigns on network-facing parsers
- ✅ Upstream Transaction ID mapping & response verification
- ✅ Lock-free atomic policy updates with automated rollback
- ✅ Generation-tagged TTL cache
- ✅ Wireshark / tcpdump .pcap wire-level evidence files
- ✅ Linux `perf` flamegraphs and raw latency percentiles
- ✅ Architecture Decision Records (ADRs) explaining trade-offs
