#pragma once

#include "protocol.h"
#include "parser.h"
#include "../common/types.h"
#include <vector>

namespace dataplane::dns {

class ResponseBuilder {
public:
    // Synthesizes an error response (REFUSED, NXDOMAIN, FORMERR, SERVFAIL)
    static std::vector<uint8_t> build_error_response(
        const ParsedPacket& query, Rcode rcode);

    // Synthesizes a Sinkhole response with a static IPv4 (e.g. 0.0.0.0 or 127.0.0.1)
    static std::vector<uint8_t> build_sinkhole_response(
        const ParsedPacket& query, uint32_t sinkhole_ipv4_be, uint32_t ttl_sec = 60);

    // Translates TxID on an upstream raw response to the client TxID
    static bool translate_txid(MutableByteSpan response_buffer, uint16_t client_txid);
};

} // namespace dataplane::dns
