# ADR-002: Lock-Free Policy Updates via RCU-Style Pointer Swapping

## Status
Accepted

## Context
A network security dataplane must enforce domain policies (allowlists, blocklists, suffix rules) with minimal latency jitter. In real-world enterprise deployments, security policy rules and threat intelligence feeds are updated frequently (e.g., every 5 to 60 minutes) via an external management plane (Go control plane).

If worker threads acquire read-write locks (`std::shared_mutex`) on every packet to check policies, reader-writer contention can cause significant latency spikes and degrade throughput during policy updates. Furthermore, mutating policy data structures in-place can expose worker threads to partially updated, corrupted, or incoherent policy states.

## Problem
How can the C++ dataplane support concurrent policy updates while guaranteeing:
1. Zero mutex contention on the packet hot path.
2. Complete isolation (readers see either the old valid snapshot or the new valid snapshot, never a partial state).
3. Graceful rollback if a candidate policy is corrupt or invalid.

## Decision
We implement a lock-free, read-copy-update (RCU) double-buffering pattern using `std::atomic<std::shared_ptr<const PolicySnapshot>>`.

### Design
1. **Immutable Snapshot:** All policy data structures (Suffix Trie, exact allowlist set, exact blocklist set, metadata) are encapsulated in an immutable `PolicySnapshot` object:
   ```cpp
   struct PolicySnapshot {
       uint64_t generation;
       std::string version_hash;
       DomainSuffixTrie suffix_trie;
       std::unordered_set<std::string> exact_blocks;
       std::unordered_set<std::string> allowlist;
   };
   ```
2. **Global Atomic Pointer:**
   ```cpp
   std::atomic<std::shared_ptr<const PolicySnapshot>> g_active_policy;
   ```
3. **Reader Path (Dataplane Hot Path):**
   Worker threads load the snapshot pointer with relaxed or acquire memory semantics:
   ```cpp
   std::shared_ptr<const PolicySnapshot> snapshot = std::atomic_load(&g_active_policy);
   // Read from snapshot without acquiring locks...
   ```
4. **Writer Path (Control Plane Staging & Activation):**
   When a new policy is pushed:
   - Build a candidate `PolicySnapshot` in private memory.
   - Execute internal self-checks and verify cryptographic hashes.
   - If validation fails, abort and preserve the active snapshot (rollback).
   - If validation succeeds, atomically store the new snapshot pointer:
     ```cpp
     std::atomic_store(&g_active_policy, std::move(new_snapshot));
     ```
   - Prior snapshots are automatically deallocated when all active reader threads release their shared references.

## Consequences
- **Positive:** Zero mutex locking on the packet hot path.
- **Positive:** Queries are evaluated against an atomic, consistent state.
- **Positive:** Failed reloads have zero impact on active query processing.
- **Trade-off:** Requires transient memory allocation for the candidate snapshot during reload ($O(N)$ memory during build).
