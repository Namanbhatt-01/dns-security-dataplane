#include "dns/forwarder.h"
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <random>
#include <iostream>

namespace dataplane::dns {

UpstreamForwarder::UpstreamForwarder(const std::string& upstream_ip, uint16_t upstream_port)
    : upstream_ip_(upstream_ip), upstream_port_(upstream_port) {}

UpstreamForwarder::~UpstreamForwarder() {
    if (socket_fd_ >= 0) {
        ::close(socket_fd_);
    }
}

bool UpstreamForwarder::init() {
    socket_fd_ = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd_ < 0) {
        return false;
    }

    // Set non-blocking
    int flags = ::fcntl(socket_fd_, F_GETFL, 0);
    if (flags < 0 || ::fcntl(socket_fd_, F_SETFL, flags | O_NONBLOCK) < 0) {
        ::close(socket_fd_);
        socket_fd_ = -1;
        return false;
    }

    std::memset(&upstream_addr_, 0, sizeof(upstream_addr_));
    upstream_addr_.sin_family = AF_INET;
    upstream_addr_.sin_port = htons(upstream_port_);
    if (::inet_pton(AF_INET, upstream_ip_.c_str(), &upstream_addr_.sin_addr) <= 0) {
        ::close(socket_fd_);
        socket_fd_ = -1;
        return false;
    }

    return true;
}

uint16_t UpstreamForwarder::generate_unique_txid() {
    static thread_local std::random_device rd;
    static thread_local std::mt19937 gen(rd());
    static thread_local std::uniform_int_distribution<uint16_t> dis(1, 65535);

    uint16_t txid = 0;
    while (txid == 0 || pending_tx_.find(txid) != pending_tx_.end()) {
        txid = dis(gen);
    }
    return txid;
}

Result<uint16_t> UpstreamForwarder::forward_query(
    const ParsedPacket& packet, const sockaddr_in& client_addr) {

    if (socket_fd_ < 0) {
        return ErrorCode::UPSTREAM_ERROR;
    }

    uint16_t upstream_txid = 0;
    std::vector<uint8_t> forward_buf;

    {
        std::lock_guard<std::mutex> lock(mutex_);
        // Prune expired transactions (> 2 seconds)
        auto now = std::chrono::steady_clock::now();
        for (auto it = pending_tx_.begin(); it != pending_tx_.end();) {
            if (std::chrono::duration_cast<std::chrono::milliseconds>(now - it->second.timestamp).count() > 2000) {
                it = pending_tx_.erase(it);
            } else {
                ++it;
            }
        }

        if (pending_tx_.size() >= 2048) {
            return ErrorCode::BUFFER_OVERFLOW;
        }

        upstream_txid = generate_unique_txid();

        PendingTransaction tx;
        tx.client_txid = packet.header.id;
        tx.client_addr = client_addr;
        tx.expected_qname = packet.question.qname;
        tx.expected_qtype = packet.question.qtype;
        tx.timestamp = now;

        pending_tx_[upstream_txid] = tx;
    }

    // Prepare packet with new TxID
    forward_buf.assign(packet.raw_packet.begin(), packet.raw_packet.end());
    forward_buf[0] = static_cast<uint8_t>(upstream_txid >> 8);
    forward_buf[1] = static_cast<uint8_t>(upstream_txid & 0xFF);

    ssize_t sent = ::sendto(socket_fd_, forward_buf.data(), forward_buf.size(), 0,
                            reinterpret_cast<const sockaddr*>(&upstream_addr_), sizeof(upstream_addr_));
    if (sent < 0) {
        std::lock_guard<std::mutex> lock(mutex_);
        pending_tx_.erase(upstream_txid);
        return ErrorCode::UPSTREAM_ERROR;
    }

    return upstream_txid;
}

Result<PendingTransaction> UpstreamForwarder::validate_response(
    ByteSpan response_buffer, const sockaddr_in& from_addr) {

    if (response_buffer.size() < kDnsHeaderSize) {
        return ErrorCode::PACKET_TOO_SHORT;
    }

    // Verify source IP and Port match configured upstream
    if (from_addr.sin_addr.s_addr != upstream_addr_.sin_addr.s_addr ||
        from_addr.sin_port != upstream_addr_.sin_port) {
        return ErrorCode::UNEXPECTED_RESPONSE;
    }

    WireHeader hdr = WireHeader::parse(response_buffer.data());
    if (!hdr.is_response()) {
        return ErrorCode::UNEXPECTED_RESPONSE;
    }

    PendingTransaction matched_tx;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = pending_tx_.find(hdr.id);
        if (it == pending_tx_.end()) {
            return ErrorCode::UNEXPECTED_RESPONSE; // Unknown or expired TxID
        }
        matched_tx = it->second;
        pending_tx_.erase(it);
    }

    // Parse question section in response and verify question match
    auto parsed_resp = DnsParser::parse(response_buffer);
    if (parsed_resp.is_err()) {
        return parsed_resp.error(); // Reject malformed upstream response!
    }

    const auto& q = parsed_resp.value().question;
    if (q.qname != matched_tx.expected_qname || q.qtype != matched_tx.expected_qtype) {
        return ErrorCode::UNEXPECTED_RESPONSE; // Question mismatch (spoofing attempt)
    }

    return matched_tx;
}

} // namespace dataplane::dns
