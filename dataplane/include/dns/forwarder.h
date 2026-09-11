#pragma once

#include "protocol.h"
#include "parser.h"
#include "../common/types.h"
#include "../common/result.h"
#include <netinet/in.h>
#include <unordered_map>
#include <chrono>
#include <mutex>

namespace dataplane::dns {

struct PendingTransaction {
    uint16_t client_txid;
    sockaddr_in client_addr;
    std::string expected_qname;
    QType expected_qtype;
    std::chrono::steady_clock::time_point timestamp;
};

class UpstreamForwarder {
public:
    UpstreamForwarder(const std::string& upstream_ip, uint16_t upstream_port);
    ~UpstreamForwarder();

    bool init();

    // Dispatches query to upstream with a fresh random TxID
    Result<uint16_t> forward_query(
        const ParsedPacket& packet, const sockaddr_in& client_addr);

    // Processes an incoming packet from upstream, validates it against pending table
    Result<PendingTransaction> validate_response(
        ByteSpan response_buffer, const sockaddr_in& from_addr);

    int socket_fd() const { return socket_fd_; }

private:
    uint16_t generate_unique_txid();

    std::string upstream_ip_;
    uint16_t upstream_port_;
    int socket_fd_{-1};
    sockaddr_in upstream_addr_{};

    std::mutex mutex_;
    std::unordered_map<uint16_t, PendingTransaction> pending_tx_;
};

} // namespace dataplane::dns
