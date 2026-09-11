# Production Operations & Incident Response Runbook

This runbook provides standardized operating procedures (SOPs), troubleshooting guides, and incident playbooks for the **ARM64 DNS Security Dataplane**.

---

## 1. System Health & Status Verification

### 1.1 Service Health Check
Query the Go control plane health API:
```bash
curl -s http://127.0.0.1:8080/health | jq .
```
**Expected Output:**
```json
{
  "active_generation": 1,
  "dataplane": "CONNECTED",
  "rule_count": 100000,
  "status": "HEALTHY",
  "version_hash": "sha256_e3b0c44..."
}
```

### 1.2 Telemetry & Metrics Verification
Scrape Prometheus metrics:
```bash
curl -s http://127.0.0.1:8080/metrics | grep -E "control_plane|dataplane"
```

---

## 2. Incident Playbooks

### Playbook A: Emergency Malicious Domain Quarantine (Active Threat)
**Scenario:** A zero-day phishing or C2 domain (e.g. `urgent-malware-exfil.biz`) is actively spreading. An operator must block it immediately and invalidate any existing cached `ALLOW` records.

**Resolution Steps:**
1. Send an atomic policy reload request with an incremented generation counter:
   ```bash
   curl -X POST http://127.0.0.1:8080/api/v1/policies \
     -H "Content-Type: application/json" \
     -d '{
       "generation": 2,
       "version_hash": "quarantine_emergency_001",
       "suffix_blocks": ["urgent-malware-exfil.biz"],
       "exact_blocks": [],
       "allowlist": []
     }'
   ```
2. **Verification:**
   - Generation increments to `2`.
   - Any prior cached responses for `urgent-malware-exfil.biz` are automatically marked stale in **84 nanoseconds** (Loophole #3 closed via ADR-004).
   - Test using `dig`:
     ```bash
     dig @127.0.0.1 -p 1053 urgent-malware-exfil.biz
     ```
     Response MUST return `status: NXDOMAIN`.

---

### Playbook B: Upstream Recursive Resolver Outage / Timeouts
**Scenario:** Upstream DNS resolver (e.g. `8.8.8.8`) is experiencing degradation or BGP hijacking, causing query latency spikes or client timeouts.

**Diagnostic Check:**
Inspect dataplane logs and check socket errors:
```bash
# Check packet drop counters on interface
netstat -su | grep "overflow"
```

**Mitigation Steps:**
1. Switch upstream resolver to secondary (e.g. Cloudflare `1.1.1.1`):
   ```bash
   # Restart dataplane with secondary upstream
   ./build/dataplane/dns_dataplane --port 1053 --upstream 1.1.1.1:53
   ```
2. Verify query resolution:
   ```bash
   dig @127.0.0.1 -p 1053 google.com +short
   ```

---

### Playbook C: High-Entropy DNS Tunneling Alert Ingestion
**Scenario:** The Shannon Entropy detection engine detects domain names with $H \ge 3.80$, indicating DNS data exfiltration (Iodine / Base32).

**Operational Procedure (ALERT_AND_ALLOW per Loophole #7):**
1. Review structured alert log:
   ```json
   {
     "timestamp": "2026-09-11T13:45:00Z",
     "event": "DNS_ANOMALY_HIGH_ENTROPY",
     "qname": "a9f3b8c2d1e0f4a7b5c8d3e2f1a0b9c8.evil-tunnel.org",
     "entropy": 3.82,
     "threshold": 3.80,
     "action": "ALERT_AND_ALLOW"
   }
   ```
2. Correlate with SIEM endpoint logs:
   - Identify internal IP initiating high query volume for base32 labels.
   - If confirmed malicious, push domain to blocklist via Playbook A.

---

### Playbook D: Memory Growth / High CPU Diagnostics
**Scenario:** Dataplane memory usage is unexpectedly increasing.

**Diagnostic Steps:**
1. Check process resident memory size (Mach VM on macOS or `/proc/$PID/status` on Linux):
   ```bash
   ps -eo pid,rss,%cpu,command | grep dns_dataplane
   ```
2. Confirm memory stability:
   - Suffix Trie uses **~4.59 MB for 100,000 rules**.
   - LRU Cache capacity is strictly capped at `capacity: 100,000 entries` with $O(1)$ LRU eviction.
   - Zero-copy buffer design ensures 0 heap allocations on the packet receive hot path.

---

## 3. Routine Maintenance Procedures

### 3.1 Running Verification Test Suite Before Production Deployment
```bash
# Clean compilation
make clean && make build

# Full TDD automated regression suite
make test

# Memory safety validation under ASan & UBSan
make sanitize

# Hostile wire parser fuzzing (100,000 packets)
make fuzz
```
