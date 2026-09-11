# DNS Wire Parser Fuzzing Campaign Report

**Date:** Sep 11 2026 19:14:05  
**Target Component:** `dataplane::dns::DnsParser::parse(ByteSpan)`  
**Execution Engine:** Hostile Protocol Wire Mutator  

## Summary Results

- **Total Iterations:** 100000
- **Total Execution Time:** 26.3839 ms (3.79019 M packets/sec)
- **Parser Crashes:** 0
- **Gracefully Handled Protocol Rejections:** 84757
- **Valid Parsed Packets:** 15243

## Verified Hostile Attack Vectors

1. **Compression Pointer Loops:** Cycles (self-referencing and multi-hop) detected within maximum 8 hops and rejected (`COMPRESSION_POINTER_LOOP`).
2. **Buffer Over-Read Truncation:** Sub-12 byte headers and partial labels safely rejected before memory dereference (`HEADER_TRUNCATED`, `LABEL_LENGTH_OVERFLOW`).
3. **Out-of-Bounds Compression Pointers:** Offsets referencing data beyond received byte span rejected (`COMPRESSION_POINTER_OOB`).
4. **Bit-Level Random Mutation:** 0 unaligned loads or undefined behavior instances flagged under UBSan.
