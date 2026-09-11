# System Architecture: ARM64 DNS Security Dataplane

**Status:** Implemented & Verified (V4.0 Hardened Architecture)  
**Target Platform:** ARM64 Linux / macOS  

---

## 1. Tri-Language Responsibility Boundaries

The system strictly decouples the high-performance network hot path from control-plane orchestration and offline analytics:

| Tier | Language | Role | Core Invariant |
|---|---|---|---|
| **Dataplane** | **C++20** | Live packet I/O, parsing, policy evaluation, caching, upstream proxying. | **Zero allocations** on request hot path; no mutexes, disk I/O, or cross-language IPC in query loop. |
| **Control Plane** | **Go (1.22)** | REST API (`:8080`), IPC server, candidate policy validation, atomic update signaling, rollback. | **Zero DNS query packets** ever pass through Go. |
| **Offline Pipeline** | **Python (3.9+)** | Feed ingestion, sanitization, SHA-256 manifest hashing, automated benchmark orchestration, plotting. | **Zero runtime involvement** in live traffic. |

---

## 2. Lock-Free RCU Double-Buffering Pattern

The C++ dataplane maintains an active immutable policy snapshot accessed via atomic load:

```cpp
struct PolicySnapshot {
    uint64_t generation;
    std::string version_hash;
    DomainSuffixTrie suffix_trie;
    std::unordered_set<std::string> exact_blocks;
    std::unordered_set<std::string> allowlist;
};

// Thread-safe pointer swap (RCU mechanics)
std::atomic<std::shared_ptr<const PolicySnapshot>> active_snapshot_;
```

- Worker threads acquire a local `std::shared_ptr` with `std::atomic_load`.
- When an update arrives via Unix domain socket IPC, the control plane compiles a candidate snapshot and invokes `std::atomic_store`.
- Existing queries finish reading the old snapshot safely; new queries immediately see the new snapshot.
- Zero mutex contention or packet drops during policy reloads.

---

## 3. Decision Engine Precedence Hierarchy

Every query evaluated by `SnapshotManager::get_active_snapshot()` traverses a deterministic 5-stage precedence hierarchy:

```text
[Incoming DNS Query]
       │
       ▼
 1. Malformed / Truncated? ─────────► [DROP / FORMERR]
       │ No
       ▼
 2. In Allowlist? ──────────────────► [ALLOW: Cache / Forward]
       │ No
       ▼
 3. In Exact Blocklist? ────────────► [BLOCK: NXDOMAIN / REFUSED]
       │ No
       ▼
 4. Matches Suffix Trie Block? ─────► [BLOCK: NXDOMAIN]
       │ No
       ▼
 5. Default Policy ─────────────────► [ALLOW: Cache / Forward]
```
