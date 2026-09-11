#include "dns/parser.h"
#include <cctype>

namespace dataplane::dns {

Result<std::pair<std::string, size_t>> DnsParser::decode_name(ByteSpan buffer, size_t offset) {
    if (offset >= buffer.size()) {
        return ErrorCode::POINTER_OUT_OF_BOUNDS;
    }

    std::string name;
    size_t curr_offset = offset;
    size_t bytes_consumed = 0;
    bool jumped = false;
    size_t depth = 0;

    while (true) {
        if (curr_offset >= buffer.size()) {
            return ErrorCode::POINTER_OUT_OF_BOUNDS;
        }

        uint8_t len = buffer[curr_offset];

        // Null terminator: end of domain name
        if (len == 0) {
            if (!jumped) {
                bytes_consumed++;
            }
            break;
        }

        // Check if compression pointer: high 2 bits set (0xC0)
        if ((len & 0xC0) == 0xC0) {
            if (curr_offset + 1 >= buffer.size()) {
                return ErrorCode::POINTER_OUT_OF_BOUNDS;
            }

            depth++;
            if (depth > kMaxCompressionDepth) {
                return ErrorCode::POINTER_LOOP_DETECTED;
            }

            uint16_t ptr_offset = ((static_cast<uint16_t>(len) & 0x3F) << 8) | buffer[curr_offset + 1];

            if (ptr_offset >= buffer.size()) {
                return ErrorCode::POINTER_OUT_OF_BOUNDS;
            }

            // Pointer must point strictly before the pointer itself to prevent cycles
            if (ptr_offset >= curr_offset && !jumped) {
                return ErrorCode::POINTER_LOOP_DETECTED;
            }

            if (!jumped) {
                bytes_consumed += 2;
                jumped = true;
            }

            curr_offset = ptr_offset;
            continue;
        }

        // Regular label
        if ((len & 0xC0) != 0) {
            // Reserved label bits 0x80 or 0x40 are invalid in standard DNS
            return ErrorCode::INVALID_LABEL_LENGTH;
        }

        if (len > kMaxLabelLength) {
            return ErrorCode::INVALID_LABEL_LENGTH;
        }

        if (curr_offset + 1 + len > buffer.size()) {
            return ErrorCode::POINTER_OUT_OF_BOUNDS;
        }

        if (!name.empty()) {
            name.push_back('.');
        }

        for (size_t i = 0; i < len; ++i) {
            char c = static_cast<char>(buffer[curr_offset + 1 + i]);
            if (static_cast<unsigned char>(c) < 32 || static_cast<unsigned char>(c) == 127) {
                return ErrorCode::INVALID_LABEL_LENGTH;
            }
            name.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
        }

        if (name.size() > kMaxDomainNameLength) {
            return ErrorCode::NAME_TOO_LONG;
        }

        curr_offset += (1 + len);
        if (!jumped) {
            bytes_consumed += (1 + len);
        }
    }

    return std::make_pair(name, bytes_consumed);
}

Result<ParsedPacket> DnsParser::parse(ByteSpan buffer) {
    if (buffer.size() < kDnsHeaderSize) {
        return ErrorCode::PACKET_TOO_SHORT;
    }

    if (buffer.size() > kMaxEdns0PayloadSize) {
        return ErrorCode::PACKET_TOO_LARGE;
    }

    WireHeader hdr = WireHeader::parse(buffer.data());

    if (hdr.opcode() != static_cast<uint8_t>(Opcode::QUERY)) {
        return ErrorCode::UNSUPPORTED_OPCODE;
    }

    // Defensive check: standard queries must contain exactly 1 question
    if (hdr.qdcount != 1) {
        return ErrorCode::INVALID_QDCOUNT;
    }

    // Decode QNAME starting at offset 12
    auto name_res = decode_name(buffer, kDnsHeaderSize);
    if (name_res.is_err()) {
        return name_res.error();
    }

    const auto& [qname, qname_bytes] = name_res.value();
    size_t qtype_offset = kDnsHeaderSize + qname_bytes;

    if (qtype_offset + 4 > buffer.size()) {
        return ErrorCode::MALFORMED_QUESTION;
    }

    uint16_t qtype = (static_cast<uint16_t>(buffer[qtype_offset]) << 8) | buffer[qtype_offset + 1];
    uint16_t qclass = (static_cast<uint16_t>(buffer[qtype_offset + 2]) << 8) | buffer[qtype_offset + 3];

    ParsedQuestion q;
    q.qname = qname;
    q.qtype = static_cast<QType>(qtype);
    q.qclass = static_cast<QClass>(qclass);
    q.wire_bytes_consumed = qname_bytes + 4;

    ParsedPacket packet;
    packet.header = hdr;
    packet.question = std::move(q);
    packet.raw_packet = buffer;

    return packet;
}

} // namespace dataplane::dns
