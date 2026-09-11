#include "test_framework.h"
#include "dns/parser.h"
#include "dns/response.h"

using namespace dataplane;
using namespace dataplane::dns;

static ParsedPacket create_synthetic_query(uint16_t id, const std::string& domain) {
    // Generate RFC 1035 query packet to parse into ParsedPacket structure
    std::vector<uint8_t> pkt(12, 0);
    pkt[0] = static_cast<uint8_t>(id >> 8);
    pkt[1] = static_cast<uint8_t>(id & 0xFF);
    pkt[5] = 0x01; // QDCOUNT = 1

    size_t start = 0;
    while (start < domain.size()) {
        size_t dot = domain.find('.', start);
        if (dot == std::string::npos) dot = domain.size();
        size_t len = dot - start;
        pkt.push_back(static_cast<uint8_t>(len));
        for (size_t i = start; i < dot; ++i) pkt.push_back(static_cast<uint8_t>(domain[i]));
        start = dot + 1;
    }
    pkt.push_back(0x00);
    pkt.push_back(0x00); pkt.push_back(0x01); // QTYPE A
    pkt.push_back(0x00); pkt.push_back(0x01); // QCLASS IN

    auto res = DnsParser::parse(ByteSpan(pkt.data(), pkt.size()));
    return res.value();
}

TEST_CASE(response_builder_nxdomain) {
    auto query = create_synthetic_query(0x9999, "blocked.test");
    auto resp = ResponseBuilder::build_error_response(query, Rcode::NXDOMAIN);

    ASSERT_TRUE(resp.size() >= 12);
    auto hdr = WireHeader::parse(resp.data());
    ASSERT_EQ(hdr.id, 0x9999);
    ASSERT_TRUE(hdr.is_response());
    ASSERT_EQ(hdr.rcode(), static_cast<uint8_t>(Rcode::NXDOMAIN));
    ASSERT_EQ(hdr.qdcount, 1);
    ASSERT_EQ(hdr.ancount, 0);
}

TEST_CASE(response_builder_refused) {
    auto query = create_synthetic_query(0x7777, "evil.com");
    auto resp = ResponseBuilder::build_error_response(query, Rcode::REFUSED);

    auto hdr = WireHeader::parse(resp.data());
    ASSERT_EQ(hdr.id, 0x7777);
    ASSERT_EQ(hdr.rcode(), static_cast<uint8_t>(Rcode::REFUSED));
}

TEST_CASE(response_builder_sinkhole) {
    auto query = create_synthetic_query(0x8888, "malware.test");
    // Sinkhole IPv4: 127.0.0.1 in network byte order -> 0x7F000001
    uint32_t sinkhole_ip = htonl(0x7F000001);
    auto resp = ResponseBuilder::build_sinkhole_response(query, sinkhole_ip, 60);

    auto hdr = WireHeader::parse(resp.data());
    ASSERT_EQ(hdr.id, 0x8888);
    ASSERT_TRUE(hdr.is_response());
    ASSERT_EQ(hdr.rcode(), static_cast<uint8_t>(Rcode::NOERROR));
    ASSERT_EQ(hdr.qdcount, 1);
    ASSERT_EQ(hdr.ancount, 1);

    // Verify injected answer record: name pointer (2 bytes), type A (2 bytes), class IN (2 bytes), TTL (4 bytes), RDLENGTH (2 bytes), RDATA (4 bytes)
    size_t q_end = 12 + query.question.wire_bytes_consumed;
    ASSERT_TRUE(resp.size() == q_end + 16);
    // Compression pointer to QNAME at offset 12 -> 0xC00C
    ASSERT_EQ(resp[q_end], 0xC0);
    ASSERT_EQ(resp[q_end + 1], 0x0C);
    // Type A (1)
    ASSERT_EQ(resp[q_end + 2], 0x00);
    ASSERT_EQ(resp[q_end + 3], 0x01);
    // Class IN (1)
    ASSERT_EQ(resp[q_end + 4], 0x00);
    ASSERT_EQ(resp[q_end + 5], 0x01);
    // TTL = 60 -> 0x0000003C
    ASSERT_EQ(resp[q_end + 6], 0x00);
    ASSERT_EQ(resp[q_end + 7], 0x00);
    ASSERT_EQ(resp[q_end + 8], 0x00);
    ASSERT_EQ(resp[q_end + 9], 0x3C);
    // RDLENGTH = 4
    ASSERT_EQ(resp[q_end + 10], 0x00);
    ASSERT_EQ(resp[q_end + 11], 0x04);
    // RDATA = 127.0.0.1
    ASSERT_EQ(resp[q_end + 12], 127);
    ASSERT_EQ(resp[q_end + 13], 0);
    ASSERT_EQ(resp[q_end + 14], 0);
    ASSERT_EQ(resp[q_end + 15], 1);
}

TEST_CASE(response_translate_txid) {
    std::vector<uint8_t> wire_pkt(12, 0);
    wire_pkt[0] = 0xAA; wire_pkt[1] = 0xBB; // Original TxID 0xAABB

    bool ok = ResponseBuilder::translate_txid(MutableByteSpan(wire_pkt.data(), wire_pkt.size()), 0x1122);
    ASSERT_TRUE(ok);
    ASSERT_EQ(wire_pkt[0], 0x11);
    ASSERT_EQ(wire_pkt[1], 0x22);
}
