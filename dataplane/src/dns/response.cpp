#include "dns/response.h"
#include <cstring>
#include <arpa/inet.h>

namespace dataplane::dns {

std::vector<uint8_t> ResponseBuilder::build_error_response(
    const ParsedPacket& query, Rcode rcode) {
    
    // An error response echoes the 12-byte header and the question section
    size_t resp_size = kDnsHeaderSize + query.question.wire_bytes_consumed;
    std::vector<uint8_t> resp(resp_size);

    // Copy original header ID
    resp[0] = static_cast<uint8_t>(query.header.id >> 8);
    resp[1] = static_cast<uint8_t>(query.header.id & 0xFF);

    // Flags: QR=1 (Response), Opcode=QUERY (0), AA=1, RA=1, RCODE=rcode
    uint16_t flags = 0x8180 | (static_cast<uint16_t>(rcode) & 0x000F);
    if (query.header.rd()) {
        flags |= 0x0100; // Preserve RD flag
    }
    resp[2] = static_cast<uint8_t>(flags >> 8);
    resp[3] = static_cast<uint8_t>(flags & 0xFF);

    // QDCOUNT = 1, ANCOUNT = 0, NSCOUNT = 0, ARCOUNT = 0
    resp[4] = 0x00; resp[5] = 0x01;
    resp[6] = 0x00; resp[7] = 0x00;
    resp[8] = 0x00; resp[9] = 0x00;
    resp[10] = 0x00; resp[11] = 0x00;

    // Copy Question section directly from raw packet
    std::memcpy(resp.data() + kDnsHeaderSize,
                query.raw_packet.data() + kDnsHeaderSize,
                query.question.wire_bytes_consumed);

    return resp;
}

std::vector<uint8_t> ResponseBuilder::build_sinkhole_response(
    const ParsedPacket& query, uint32_t sinkhole_ipv4_be, uint32_t ttl_sec) {

    // Echo header + question + 1 Answer RR (16 bytes)
    size_t q_size = query.question.wire_bytes_consumed;
    size_t resp_size = kDnsHeaderSize + q_size + 16;
    std::vector<uint8_t> resp(resp_size);

    // ID
    resp[0] = static_cast<uint8_t>(query.header.id >> 8);
    resp[1] = static_cast<uint8_t>(query.header.id & 0xFF);

    // Flags: QR=1, AA=1, RA=1, NOERROR (0)
    uint16_t flags = 0x8580;
    if (query.header.rd()) flags |= 0x0100;
    resp[2] = static_cast<uint8_t>(flags >> 8);
    resp[3] = static_cast<uint8_t>(flags & 0xFF);

    // QDCOUNT = 1, ANCOUNT = 1, NSCOUNT = 0, ARCOUNT = 0
    resp[4] = 0x00; resp[5] = 0x01;
    resp[6] = 0x00; resp[7] = 0x01;
    resp[8] = 0x00; resp[9] = 0x00;
    resp[10] = 0x00; resp[11] = 0x00;

    // Question section
    std::memcpy(resp.data() + kDnsHeaderSize,
                query.raw_packet.data() + kDnsHeaderSize,
                q_size);

    // Answer section at offset (12 + q_size)
    uint8_t* ans = resp.data() + kDnsHeaderSize + q_size;
    // NAME: compression pointer to offset 12 (QNAME)
    ans[0] = 0xC0;
    ans[1] = 0x0C;
    // TYPE: A (1)
    ans[2] = 0x00;
    ans[3] = 0x01;
    // CLASS: IN (1)
    ans[4] = 0x00;
    ans[5] = 0x01;
    // TTL
    uint32_t net_ttl = htonl(ttl_sec);
    std::memcpy(ans + 6, &net_ttl, 4);
    // RDLENGTH = 4 (IPv4 address)
    ans[10] = 0x00;
    ans[11] = 0x04;
    // RDATA
    std::memcpy(ans + 12, &sinkhole_ipv4_be, 4);

    return resp;
}

bool ResponseBuilder::translate_txid(MutableByteSpan response_buffer, uint16_t client_txid) {
    if (response_buffer.size() < 2) {
        return false;
    }
    response_buffer[0] = static_cast<uint8_t>(client_txid >> 8);
    response_buffer[1] = static_cast<uint8_t>(client_txid & 0xFF);
    return true;
}

} // namespace dataplane::dns
