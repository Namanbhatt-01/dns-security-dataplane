#include "test_framework.h"
#include "dns/parser.h"
#include <vector>

using namespace dataplane;
using namespace dataplane::dns;

// Helper: constructs an RFC 1035 wire query for a simple uncompressed domain
static std::vector<uint8_t> make_query_packet(uint16_t id, const std::string& domain, uint16_t qtype = 1, uint16_t qclass = 1) {
    std::vector<uint8_t> packet;
    packet.resize(12);

    // Header: ID
    packet[0] = static_cast<uint8_t>(id >> 8);
    packet[1] = static_cast<uint8_t>(id & 0xFF);
    // Flags: standard query, RD=1
    packet[2] = 0x01;
    packet[3] = 0x00;
    // QDCOUNT = 1
    packet[4] = 0x00;
    packet[5] = 0x01;
    // ANCOUNT, NSCOUNT, ARCOUNT = 0

    // Encode QNAME
    size_t start = 0;
    while (start < domain.size()) {
        size_t dot = domain.find('.', start);
        if (dot == std::string::npos) dot = domain.size();
        size_t len = dot - start;
        packet.push_back(static_cast<uint8_t>(len));
        for (size_t i = start; i < dot; ++i) {
            packet.push_back(static_cast<uint8_t>(domain[i]));
        }
        start = dot + 1;
    }
    packet.push_back(0x00); // Null terminator

    // QTYPE
    packet.push_back(static_cast<uint8_t>(qtype >> 8));
    packet.push_back(static_cast<uint8_t>(qtype & 0xFF));
    // QCLASS
    packet.push_back(static_cast<uint8_t>(qclass >> 8));
    packet.push_back(static_cast<uint8_t>(qclass & 0xFF));

    return packet;
}

TEST_CASE(parser_valid_standard_query) {
    auto pkt = make_query_packet(0x1234, "example.com", 1, 1);
    auto res = DnsParser::parse(ByteSpan(pkt.data(), pkt.size()));

    ASSERT_TRUE(res.is_ok());
    const auto& parsed = res.value();
    ASSERT_EQ(parsed.header.id, 0x1234);
    ASSERT_TRUE(parsed.header.is_query());
    ASSERT_EQ(parsed.header.qdcount, 1);
    ASSERT_EQ(parsed.question.qname, "example.com");
    ASSERT_EQ(static_cast<uint16_t>(parsed.question.qtype), 1);
    ASSERT_EQ(static_cast<uint16_t>(parsed.question.qclass), 1);
}

TEST_CASE(parser_normalizes_to_lowercase) {
    auto pkt = make_query_packet(0xABCD, "WwW.ExAmPlE.CoM", 28, 1); // AAAA query
    auto res = DnsParser::parse(ByteSpan(pkt.data(), pkt.size()));

    ASSERT_TRUE(res.is_ok());
    ASSERT_EQ(res.value().question.qname, "www.example.com");
    ASSERT_EQ(static_cast<uint16_t>(res.value().question.qtype), 28);
}

TEST_CASE(parser_rejects_truncated_header) {
    uint8_t short_pkt[11] = {0}; // Less than 12 bytes
    auto res = DnsParser::parse(ByteSpan(short_pkt, sizeof(short_pkt)));

    ASSERT_TRUE(res.is_err());
    ASSERT_EQ(static_cast<uint8_t>(res.error()), static_cast<uint8_t>(ErrorCode::PACKET_TOO_SHORT));
}

TEST_CASE(parser_rejects_invalid_qdcount_zero) {
    auto pkt = make_query_packet(0x1111, "example.com");
    pkt[4] = 0x00;
    pkt[5] = 0x00; // QDCOUNT = 0

    auto res = DnsParser::parse(ByteSpan(pkt.data(), pkt.size()));
    ASSERT_TRUE(res.is_err());
    ASSERT_EQ(static_cast<uint8_t>(res.error()), static_cast<uint8_t>(ErrorCode::INVALID_QDCOUNT));
}

TEST_CASE(parser_rejects_invalid_qdcount_multiple) {
    auto pkt = make_query_packet(0x1111, "example.com");
    pkt[4] = 0x00;
    pkt[5] = 0x02; // QDCOUNT = 2 (Attacker injection vector)

    auto res = DnsParser::parse(ByteSpan(pkt.data(), pkt.size()));
    ASSERT_TRUE(res.is_err());
    ASSERT_EQ(static_cast<uint8_t>(res.error()), static_cast<uint8_t>(ErrorCode::INVALID_QDCOUNT));
}

TEST_CASE(parser_rejects_label_length_overflow) {
    auto pkt = make_query_packet(0x2222, "example.com");
    // Offset 12 is first label length octet. Protocol max is 63 (0x3F).
    // Set to 64 (0x40) without compression pointer bits.
    pkt[12] = 64;

    auto res = DnsParser::parse(ByteSpan(pkt.data(), pkt.size()));
    ASSERT_TRUE(res.is_err());
    ASSERT_EQ(static_cast<uint8_t>(res.error()), static_cast<uint8_t>(ErrorCode::INVALID_LABEL_LENGTH));
}

TEST_CASE(parser_rejects_compression_pointer_loop) {
    // Construct packet with circular pointer: pointer at 12 points to 12
    std::vector<uint8_t> pkt(16, 0);
    pkt[0] = 0x33; pkt[1] = 0x33;
    pkt[5] = 0x01; // QDCOUNT = 1
    // Offset 12: pointer to offset 12 -> 0xC00C
    pkt[12] = 0xC0;
    pkt[13] = 0x0C;
    // QTYPE & QCLASS
    pkt[14] = 0x00; pkt[15] = 0x01;

    auto res = DnsParser::parse(ByteSpan(pkt.data(), pkt.size()));
    ASSERT_TRUE(res.is_err());
    ASSERT_EQ(static_cast<uint8_t>(res.error()), static_cast<uint8_t>(ErrorCode::POINTER_LOOP_DETECTED));
}

TEST_CASE(parser_rejects_compression_pointer_oob) {
    std::vector<uint8_t> pkt(16, 0);
    pkt[0] = 0x44; pkt[1] = 0x44;
    pkt[5] = 0x01; // QDCOUNT = 1
    // Offset 12: pointer to offset 50 (beyond packet size 16) -> 0xC032
    pkt[12] = 0xC0;
    pkt[13] = 0x32;

    auto res = DnsParser::parse(ByteSpan(pkt.data(), pkt.size()));
    ASSERT_TRUE(res.is_err());
    ASSERT_EQ(static_cast<uint8_t>(res.error()), static_cast<uint8_t>(ErrorCode::POINTER_OUT_OF_BOUNDS));
}

TEST_CASE(parser_rejects_unsupported_opcode) {
    auto pkt = make_query_packet(0x5555, "example.com");
    // Set Opcode = 5 (UPDATE, RFC 2136) in flags byte 2
    pkt[2] = (5 << 3);

    auto res = DnsParser::parse(ByteSpan(pkt.data(), pkt.size()));
    ASSERT_TRUE(res.is_err());
    ASSERT_EQ(static_cast<uint8_t>(res.error()), static_cast<uint8_t>(ErrorCode::UNSUPPORTED_OPCODE));
}

TEST_CASE(parser_rejects_control_characters_in_label) {
    auto pkt = make_query_packet(0x6666, "bad\x07site.com"); // Embedded bell / control char
    auto res = DnsParser::parse(ByteSpan(pkt.data(), pkt.size()));
    ASSERT_TRUE(res.is_err());
    ASSERT_EQ(static_cast<uint8_t>(res.error()), static_cast<uint8_t>(ErrorCode::INVALID_LABEL_LENGTH));
}
