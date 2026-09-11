#pragma once

#include <cstdint>
#include <arpa/inet.h>

namespace dataplane::dns {

// Standard DNS limits
inline constexpr size_t kDnsHeaderSize = 12;
inline constexpr size_t kMaxUdpPayloadSize = 512;
inline constexpr size_t kMaxEdns0PayloadSize = 4096;
inline constexpr size_t kMaxDomainNameLength = 253;
inline constexpr size_t kMaxLabelLength = 63;
inline constexpr size_t kMaxCompressionDepth = 8;

// DNS Opcodes (RFC 1035)
enum class Opcode : uint8_t {
    QUERY = 0,
    IQUERY = 1,
    STATUS = 2,
    NOTIFY = 4,
    UPDATE = 5
};

// DNS Response Codes (RCODE)
enum class Rcode : uint8_t {
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
    YXDOMAIN = 6,
    YXRRSET = 7,
    NXRRSET = 8,
    NOTAUTH = 9,
    NOTZONE = 10
};

// DNS QTYPEs
enum class QType : uint16_t {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    OPT = 41,
    ANY = 255
};

// DNS QCLASS
enum class QClass : uint16_t {
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4,
    ANY = 255
};

// RFC 1035 Header Format (12 bytes)
struct Header {
    uint16_t id;
    uint8_t rd : 1;
    uint8_t tc : 1;
    uint8_t aa : 1;
    uint8_t opcode : 4;
    uint8_t qr : 1;

    uint8_t rcode : 4;
    uint8_t cd : 1;
    uint8_t ad : 1;
    uint8_t z : 1;
    uint8_t ra : 1;

    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

// Helper for wire header decoding
struct WireHeader {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;

    static WireHeader parse(const uint8_t* buf) {
        WireHeader h;
        h.id = (static_cast<uint16_t>(buf[0]) << 8) | buf[1];
        h.flags = (static_cast<uint16_t>(buf[2]) << 8) | buf[3];
        h.qdcount = (static_cast<uint16_t>(buf[4]) << 8) | buf[5];
        h.ancount = (static_cast<uint16_t>(buf[6]) << 8) | buf[7];
        h.nscount = (static_cast<uint16_t>(buf[8]) << 8) | buf[9];
        h.arcount = (static_cast<uint16_t>(buf[10]) << 8) | buf[11];
        return h;
    }

    bool is_query() const { return (flags & 0x8000) == 0; }
    bool is_response() const { return (flags & 0x8000) != 0; }
    uint8_t opcode() const { return (flags >> 11) & 0x0F; }
    bool tc() const { return (flags & 0x0200) != 0; }
    bool rd() const { return (flags & 0x0100) != 0; }
    uint8_t rcode() const { return flags & 0x000F; }
};

} // namespace dataplane::dns
