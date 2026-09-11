# ADR-001: Upstream Transaction Validation and Cache Poisoning Defense

## Status
Accepted

## Context
When forwarding permitted DNS queries from the local dataplane to an upstream recursive resolver over UDP, the application is inherently exposed to spoofing and cache poisoning attacks (e.g., the Kaminsky attack). If an attacker predicts the transaction ID (TxID) and UDP source port, or if the dataplane blindly accepts any packet arriving on its listening port, an adversary can inject forged DNS records into the local cache, redirecting all downstream clients to malicious IPs.

In initial design drafts, upstream communication was simply described as "forwarding permitted queries". During internal security architecture review, this was identified as a critical security correctness loophole.

## Problem
How can the C++ dataplane guarantee that an incoming UDP response from an upstream server is authentic, strictly corresponds to an active in-flight request, and cannot be spoofed to corrupt the local cache?

## Decision
We implement a stateful **Upstream Transaction Manager** enforcing the following invariants:
1. **Cryptographic TxID Generation:** When a client query arrives with client TxID ($TxID_c$), the dataplane generates a fresh, pseudo-random upstream TxID ($TxID_u$) using a cryptographically secure random number generator (`arc4random()` on BSD/macOS or `getrandom()` / `/dev/urandom` on Linux).
2. **Ephemeral Port Randomization:** Queries to upstream servers are dispatched from an ephemeral UDP socket bound to a dynamically allocated OS port.
3. **Pending Transaction Tracking:** The dataplane records an in-flight entry in a bounded concurrent hash table:
   `Key: (TxID_u, Remote_Endpoint) -> Value: (TxID_c, Client_Endpoint, Expected_QNAME, Expected_QTYPE, Timestamp)`
4. **Strict Response Verification:** When a packet is received on the upstream socket, the engine verifies:
   - Remote source IP and port strictly match the configured upstream resolver.
   - Response header flag `QR == 1` (message is a response, not a query).
   - $TxID$ matches an active, non-expired pending entry in the tracking table.
   - The Question section of the response matches `Expected_QNAME` and `Expected_QTYPE` byte-for-byte.
   - Arrival time is within the response timeout threshold ($T_{\text{timeout}} = 1500\text{ms}$).
5. **Atomic Cache Insertion & Client Forwarding:**
   - Only responses passing all checks are permitted to populate the cache.
   - The response packet's TxID is overwritten with $TxID_c$ before transmitting back to the client.

## Consequences
- **Positive:** Completely eliminates blind Kaminsky-style cache poisoning attacks.
- **Positive:** Prevents stale, late-arriving upstream responses from corrupting newer queries for the same domain.
- **Trade-off:** Requires maintaining an in-flight table (bounded to 2,048 entries) and performing table lookups upon packet arrival.
