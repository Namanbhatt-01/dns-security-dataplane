# ADR-004: Cache Invalidation via Generation Counters

## Status
Accepted

## Context
In initial design drafts, the hot path placed the TTL cache lookup **before** the policy evaluation engine:
`Client Query -> Cache Lookup (HIT) -> Return Answer`.

During security architecture review (Vulnerability Analysis), this sequence was identified as a critical security hole. If domain `malicious.test` was previously resolved and cached with a 3600-second TTL, and subsequently the security control plane pushes an emergency block rule for `malicious.test`, the cache would continue serving `ALLOW` responses until the TTL expired 50 minutes later.

Conversely, invalidating or wiping the entire cache on every policy reload destroys cache efficiency, causing sudden traffic surges to the upstream resolver.

## Decision
We implement **Generation Tagging** on cache entries to enforce instant policy invalidation without cache flushes:
1. The dataplane maintains a global atomic counter:
   ```cpp
   std::atomic<uint64_t> g_global_policy_generation{1};
   ```
2. Each cache entry records the generation at which it was evaluated:
   ```cpp
   struct CacheEntry {
       DnsWireResponse response;
       std::chrono::steady_clock::time_point expires_at;
       uint64_t policy_generation;
   };
   ```
3. When the Go control plane pushes an updated policy, the dataplane atomically increments `g_global_policy_generation`.
4. On a cache hit:
   - If `entry.policy_generation == g_global_policy_generation.load()`, the cached response is served immediately.
   - If `entry.policy_generation < g_global_policy_generation.load()`, the entry is marked stale. The query is immediately re-evaluated against the new `PolicySnapshot`. If still permitted, the cache entry's generation tag is updated to the current generation. If now blocked, the entry is purged and a `BLOCK` response is returned.

## Consequences
- **Positive:** Closes the stale-cache security bypass immediately upon policy activation.
- **Positive:** Avoids purging the entire cache during routine updates, preserving cache warmth for unimpacted domains.
- **Trade-off:** Adds an atomic load and integer comparison to the cache lookup path.
