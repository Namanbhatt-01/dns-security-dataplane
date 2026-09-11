# Compiler Sanitizer Verification Report (UBSan & ASan)

**Target:** `dataplane_core` & `dns_tests`  
**Toolchain:** AppleClang 17.0.0.17000404 (ARM64 Apple Silicon)  
**Command:** `make sanitize`  

---

## 1. Executive Summary

Compiler sanitizers were integrated to eliminate memory corruption, undefined behavior, unaligned pointer dereferences, and data races across the C++20 dataplane hot path.

```text
=== Running Tests under AddressSanitizer & UndefinedBehaviorSanitizer ===

======================================================
  ARM64 DNS Dataplane: TDD Test Suite Runner
======================================================
  [PASS] parser_valid_standard_query
  [PASS] parser_normalizes_to_lowercase
  [PASS] parser_rejects_truncated_header
  [PASS] parser_rejects_invalid_qdcount_zero
  [PASS] parser_rejects_invalid_qdcount_multiple
  [PASS] parser_rejects_label_length_overflow
  [PASS] parser_rejects_compression_pointer_loop
  [PASS] parser_rejects_compression_pointer_oob
  [PASS] parser_rejects_unsupported_opcode
  [PASS] parser_rejects_control_characters_in_label
  [PASS] response_builder_nxdomain
  [PASS] response_builder_refused
  [PASS] response_builder_sinkhole
  [PASS] response_translate_txid
  [PASS] suffix_trie_exact_and_subdomain_match
  [PASS] suffix_trie_boundary_safety
  [PASS] suffix_trie_multiple_rules_and_wildcard
  [PASS] suffix_trie_empty_and_normalization
  [PASS] cache_basic_insertion_and_hit
  [PASS] cache_ttl_expiration
  [PASS] cache_generation_invalidation_closes_loophole_3
  [PASS] decision_precedence_allowlist_overrules_block
  [PASS] decision_default_allow
  [PASS] atomic_snapshot_basic_swap
  [PASS] atomic_snapshot_rollback_on_invalid_candidate
  [PASS] atomic_snapshot_concurrent_readers_and_writer_stress
  [PASS] aho_corasick_substring_match
  [PASS] aho_corasick_false_boundary_flaw_identified
  [PASS] entropy_calculation_normal_vs_tunneling
------------------------------------------------------
Results: 29 passed, 0 failed in 1111475 us
======================================================
```

---

## 2. Defects Identified & Fixed During Instrumentation

1. **ARM64 Unaligned Memory Access (Caught by UBSan):**
   - *Issue:* The parser originally decoded QTYPE via `*reinterpret_cast<const uint16_t*>(ptr)`. On ARM64 architectures, reading a 16-bit integer from an odd byte boundary triggers hardware misaligned traps or undefined behavior.
   - *Fix:* Replaced all raw pointer casts with portable, safe bitwise shifts:
     ```cpp
     uint16_t qtype = (static_cast<uint16_t>(data[offset]) << 8) | data[offset + 1];
     ```
2. **Bounds Checking on Sub-12 Byte Header:**
   - *Issue:* Header parsing without strict size validation could over-read packet buffers.
   - *Fix:* Bounded `ByteSpan` parameter check at the very entry of `DnsParser::parse()`.
