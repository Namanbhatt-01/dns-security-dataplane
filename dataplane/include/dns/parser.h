#pragma once

#include "protocol.h"
#include "../common/types.h"
#include "../common/result.h"
#include <string>

namespace dataplane::dns {

struct ParsedQuestion {
    std::string qname;          // Normalized: lowercase, no trailing dot
    QType qtype{QType::A};
    QClass qclass{QClass::IN};
    size_t wire_bytes_consumed{0}; // Length of the question section in bytes
};

struct ParsedPacket {
    WireHeader header;
    ParsedQuestion question;
    ByteSpan raw_packet;
};

class DnsParser {
public:
    // Zero-copy parse of an incoming DNS packet buffer
    static Result<ParsedPacket> parse(ByteSpan buffer);

    // Helper: decodes a wire QNAME at a given offset with loop detection
    static Result<std::pair<std::string, size_t>> decode_name(
        ByteSpan buffer, size_t offset);
};

} // namespace dataplane::dns
