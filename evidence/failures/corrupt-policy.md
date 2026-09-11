# Failure Injection & Resilience: Corrupt / Stale Policy Rollback

**Component:** `controlplane` (Go) & `dataplane::runtime::SnapshotManager` (C++)  
**Fault Category:** Operator Misconfiguration / Threat Feed Corruption / Stale Rollback Attack  
**Specification:** Loophole #6 Data Integrity & Atomic Activation  

---

## 1. Failure Scenario
During dynamic policy updates, an operator or automated threat intelligence pipeline may attempt to push:
1. A syntactically corrupted payload (non-JSON, truncated IPC buffer).
2. A stale policy snapshot where `candidate.generation <= active.generation` (replay / downgrade attack).
3. A policy containing invalid rules.

---

## 2. Implemented Defense & Automated Rollback

1. **Staged Candidate Validation:**
   - The Go management daemon (`:8080/api/v1/policies`) performs schema validation, domain normalization, and SHA-256 fingerprinting before signaling the dataplane.
2. **Generation Monotonicity Invariant:**
   - In `SnapshotManager::apply_candidate`:
     ```cpp
     if (candidate->generation <= current_gen) {
         // Reject stale generation and abort swap
         return false;
     }
     ```
3. **Atomic Rollback Guarantee:**
   - If candidate validation fails, the active pointer `active_snapshot_` is untouched.
   - The Go control plane returns HTTP 400 Bad Request:
     ```json
     {
       "status": "error",
       "error": "candidate generation must be strictly greater than active generation",
       "action": "ROLLBACK_PRESERVED_ACTIVE"
     }
     ```

---

## 3. Empirical Verification Evidence
- **Automated Test:** `atomic_snapshot_rollback_on_invalid_candidate` in `dataplane/tests/test_atomic_swap.cpp`:
  ```text
  [PASS] atomic_snapshot_rollback_on_invalid_candidate
  ```
- **Fault Injection Test:** Stale generation 1 pushed against active generation 2: verified rejected, active generation 2 preserved.
