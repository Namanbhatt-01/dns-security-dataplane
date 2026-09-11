# Protocol Specification: DNS Wire Format & Stateful TCP Framing

**Specification:** RFC 1035, RFC 3596, RFC 6891 (EDNS0), RFC 7766 (DNS over TCP)  
**Implementation:** `dataplane::dns::DnsParser` & `dataplane::dns::ResponseBuilder`  

---

## 1. Zero-Copy UDP Wire Parsing

DNS packets are processed directly within non-owning memory slices (`ByteSpan`):

```cpp
struct ByteSpan {
    const uint8_t* data;
    size_t size;
};
```

### Safety & Loop Defenses
1. **Header Validation:** Packets $< 12$ bytes are rejected immediately (`DnsError::HEADER_TRUNCATED`).
2. **Compression Pointer Walking:**
   - Offset mask `0xC0` indicates an indirect label pointer.
   - Pointers are bounded to prevent out-of-bounds reads: `offset < packet.size`.
   - Cycle detection: An atomic counter tracks dereference hops. If `hop_count > 8`, the packet is dropped as `DnsError::COMPRESSION_POINTER_LOOP`.
3. **QNAME Length Limits:** Total decoded domain name is capped at 253 characters; individual labels capped at 63 characters (RFC 1035 §2.3.4).

---

## 2. Stateful TCP DNS Framing (Loophole #4 Mitigation)

Unlike UDP datagrams, TCP DNS operates as a stream with explicit length delimiters:

### RFC 1035 §4.2.2 Framing
```text
+-----------------------+------------------------------------------+
|  2-byte Big-Endian    |          Standard DNS Message             |
|     Length Prefix     |             (Header + Body)              |
+-----------------------+------------------------------------------+
```

### TCP Connection Lifecycle
1. **Partial Read Reassembly:**
   - Because TCP delivers fragmented bytes, the engine buffers partial reads until the full 2-byte prefix and message payload are received.
2. **Idle Connection Management:**
   - Idle connections are closed after $T_{\text{idle}} = 10\text{ seconds}$ to reclaim kernel socket descriptors.
3. **Connection Limits:**
   - Global client connections are capped at $N_{\text{max}} = 512$ to prevent file descriptor exhaustion (`EMFILE`).
