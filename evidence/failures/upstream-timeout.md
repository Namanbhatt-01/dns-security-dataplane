# Failure Injection & Resilience: Upstream Resolver Timeout

**Component:** `dataplane::dns::UpstreamForwarder`  
**Fault Category:** Network Drop / Unresponsive Upstream Resolver  
**Specification:** RFC 1035 §4.2.1 & RFC 5452 Spoofing Resilience  

---

## 1. Failure Scenario
In production deployments, the authoritative or recursive upstream resolver (`8.8.8.8:53`) may experience packet loss, rate limiting, BGP route flaps, or transient blackholing. 

Without defensive engineering:
- The proxy leaks file descriptors and ephemeral socket bindings.
- Client queries hang indefinitely until socket buffer exhaustion.
- Re-transmitted responses arriving after timeout could be mismatched to newer client queries (Kaminsky vector).

---

## 2. Implemented Defense Mechanism

1. **State Machine Expiration:**
   - Every forwarded transaction is recorded in the pending table with a monotonic timestamp:
     ```cpp
     struct PendingTransaction {
         uint16_t client_txid;
         sockaddr_in client_addr;
         std::string expected_qname;
         uint16_t expected_qtype;
         std::chrono::steady_clock::time_point timestamp;
     };
     ```
2. **Timeout Boundary ($T_{\text{timeout}} = 1500\text{ ms}$):**
   - Responses arriving after $1.5\text{s}$ are automatically dropped as `DnsError::UPSTREAM_TIMEOUT`.
   - The transaction state is purged, preventing late poisoned answers from ever matching future queries.
3. **Graceful Client Fallback:**
   - If an upstream failure occurs, the dataplane immediately returns `Rcode::SERVFAIL` to the client instead of hanging the client socket.

---

## 3. Verification & Evidence
- **Test Case:** Verified in `test_response.cpp` and `test_decision.cpp`.
- **Wire Behavior:** Upstream packet drops trigger immediate cleanup without memory leaks or unbounded state growth under AddressSanitizer.
