#include "dns/protocol.h"
#include "dns/parser.h"
#include "dns/response.h"
#include "dns/forwarder.h"
#include "engine/decision.h"
#include "engine/cache.h"
#include "detection/entropy.h"
#include "runtime/atomic_snapshot.h"
#include "runtime/ipc_server.h"
#include <iostream>
#include <vector>
#include <csignal>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>

using namespace dataplane;
using namespace dataplane::dns;
using namespace dataplane::engine;
using namespace dataplane::detection;
using namespace dataplane::runtime;

static volatile std::sig_atomic_t g_running = 1;

static void handle_signal(int) {
    g_running = 0;
}

int main(int argc, char* argv[]) {
    uint16_t listen_port = 1053;
    std::string upstream_ip = "8.8.8.8";
    uint16_t upstream_port = 53;
    std::string ipc_sock = "/tmp/dns_dataplane_control.sock";
    bool quiet = false;

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            listen_port = static_cast<uint16_t>(std::atoi(argv[++i]));
        } else if (std::strcmp(argv[i], "--upstream") == 0 && i + 1 < argc) {
            std::string u = argv[++i];
            size_t colon = u.find(':');
            if (colon != std::string::npos) {
                upstream_ip = u.substr(0, colon);
                upstream_port = static_cast<uint16_t>(std::atoi(u.substr(colon + 1).c_str()));
            } else {
                upstream_ip = u;
            }
        } else if (std::strcmp(argv[i], "--ipc") == 0 && i + 1 < argc) {
            ipc_sock = argv[++i];
        } else if (std::strcmp(argv[i], "--quiet") == 0) {
            quiet = true;
        }
    }

    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    std::cout << "======================================================\n";
    std::cout << "  ARM64 DNS Security Dataplane (Stage 3 Appliance)\n";
    std::cout << "  Listening on: 127.0.0.1:" << listen_port << " (UDP)\n";
    std::cout << "  Upstream:     " << upstream_ip << ":" << upstream_port << "\n";
    std::cout << "  Control IPC:  " << ipc_sock << "\n";
    std::cout << "  Features:     Lock-Free RCU Swapping + IPC Control\n";
    std::cout << "======================================================\n";

    // 1. Initialize listening UDP socket
    int server_fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (server_fd < 0) {
        std::cerr << "Failed to create listening socket\n";
        return 1;
    }

    int opt = 1;
    ::setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_REUSEPORT
    ::setsockopt(server_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    server_addr.sin_port = htons(listen_port);

    if (::bind(server_fd, reinterpret_cast<const sockaddr*>(&server_addr), sizeof(server_addr)) < 0) {
        std::cerr << "Failed to bind listening socket to port " << listen_port << "\n";
        ::close(server_fd);
        return 1;
    }

    // 2. Initialize Upstream Forwarder
    UpstreamForwarder forwarder(upstream_ip, upstream_port);
    if (!forwarder.init()) {
        std::cerr << "Failed to initialize upstream forwarder\n";
        ::close(server_fd);
        return 1;
    }

    // 3. Initialize IPC server for Go control plane
    IpcServer ipc_server(ipc_sock);
    if (!ipc_server.start()) {
        std::cerr << "Failed to initialize IPC server on " << ipc_sock << "\n";
        ::close(server_fd);
        return 1;
    }

    // Seed initial default policy rules
    {
        auto seed = std::make_unique<PolicySnapshot>();
        seed->generation = 1;
        seed->version_hash = "bootstrap_v1";
        seed->suffix_trie.insert("blocked.test", 1);
        seed->suffix_trie.insert("doubleclick.net", 2);
        seed->exact_blocks.insert("sinkhole.test");
        seed->allowlist.insert("safe.doubleclick.net");
        SnapshotManager::instance().apply_candidate(std::move(seed));
    }

    DnsCache cache(10000); // 10,000 entry TTL cache

    std::vector<uint8_t> rx_buf(kMaxEdns0PayloadSize);

    struct pollfd fds[2];
    fds[0].fd = server_fd;
    fds[0].events = POLLIN;
    fds[1].fd = forwarder.socket_fd();
    fds[1].events = POLLIN;

    std::cout << "Dataplane running. Waiting for queries & IPC commands...\n";

    while (g_running) {
        int ret = ::poll(fds, 2, 500);
        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }

        // Event on client listening socket
        if (fds[0].revents & POLLIN) {
            sockaddr_in client_addr{};
            socklen_t addr_len = sizeof(client_addr);
            ssize_t n = ::recvfrom(server_fd, rx_buf.data(), rx_buf.size(), 0,
                                   reinterpret_cast<sockaddr*>(&client_addr), &addr_len);
            if (n > 0) {
                auto parse_res = DnsParser::parse(ByteSpan(rx_buf.data(), static_cast<size_t>(n)));
                if (parse_res.is_err()) {
                    std::cerr << "Malformed packet rejected: " << error_string(parse_res.error()) << "\n";
                } else {
                    const auto& query = parse_res.value();
                    const std::string& qname = query.question.qname;
                    uint16_t qtype = static_cast<uint16_t>(query.question.qtype);
                    uint16_t qclass = static_cast<uint16_t>(query.question.qclass);

                    // 1. Lock-free load of active immutable policy snapshot
                    auto snapshot = SnapshotManager::instance().get_active_snapshot();
                    uint64_t current_gen = SnapshotManager::instance().current_generation();

                    // Anomaly detection: Shannon Entropy check (ALERT_AND_ALLOW mode)
                    if (EntropyCalculator::is_suspicious_entropy(qname)) {
                        if (!quiet) {
                            std::cout << "[SECURITY ALERT: SUSPICIOUS ENTROPY] Domain: " << qname
                                      << " (H=" << EntropyCalculator::calculate(qname) << ")\n";
                        }
                    }

                    Decision decision = snapshot->evaluate(qname);

                    if (decision.action == Action::BLOCK_NXDOMAIN) {
                        auto resp = ResponseBuilder::build_error_response(query, Rcode::NXDOMAIN);
                        ::sendto(server_fd, resp.data(), resp.size(), 0,
                                 reinterpret_cast<const sockaddr*>(&client_addr), addr_len);
                        if (!quiet) std::cout << "[BLOCKED: NXDOMAIN] " << qname << " (gen=" << current_gen << ")\n";
                    } else if (decision.action == Action::BLOCK_REFUSED) {
                        auto resp = ResponseBuilder::build_error_response(query, Rcode::REFUSED);
                        ::sendto(server_fd, resp.data(), resp.size(), 0,
                                 reinterpret_cast<const sockaddr*>(&client_addr), addr_len);
                        if (!quiet) std::cout << "[REFUSED] " << qname << "\n";
                    } else if (qname == "sinkhole.test") {
                        uint32_t sinkhole_ip = inet_addr("127.0.0.1");
                        auto resp = ResponseBuilder::build_sinkhole_response(query, sinkhole_ip);
                        ::sendto(server_fd, resp.data(), resp.size(), 0,
                                 reinterpret_cast<const sockaddr*>(&client_addr), addr_len);
                        if (!quiet) std::cout << "[SINKHOLE] " << qname << " -> 127.0.0.1\n";
                    } else {
                        // 2. Query is ALLOWED: Check Generation-Tagged TTL Cache
                        auto cached_opt = cache.lookup(qname, qtype, qclass, current_gen);
                        if (cached_opt.has_value()) {
                            // CACHE HIT: Re-stamp client TxID and return immediately
                            std::vector<uint8_t> resp = cached_opt->response;
                            ResponseBuilder::translate_txid(
                                MutableByteSpan(resp.data(), resp.size()), query.header.id);
                            ::sendto(server_fd, resp.data(), resp.size(), 0,
                                     reinterpret_cast<const sockaddr*>(&client_addr), addr_len);
                            if (!quiet) std::cout << "[CACHE HIT] " << qname << " (0ms, gen=" << current_gen << ")\n";
                        } else {
                            // CACHE MISS: Forward to upstream resolver
                            auto fwd_res = forwarder.forward_query(query, client_addr);
                            if (fwd_res.is_err()) {
                                auto resp = ResponseBuilder::build_error_response(query, Rcode::SERVFAIL);
                                ::sendto(server_fd, resp.data(), resp.size(), 0,
                                         reinterpret_cast<const sockaddr*>(&client_addr), addr_len);
                                if (!quiet) std::cerr << "Upstream forward error: " << error_string(fwd_res.error()) << "\n";
                            }
                        }
                    }
                }
            }
        }

        // Event on upstream forwarder socket
        if (fds[1].revents & POLLIN) {
            sockaddr_in from_addr{};
            socklen_t from_len = sizeof(from_addr);
            ssize_t n = ::recvfrom(forwarder.socket_fd(), rx_buf.data(), rx_buf.size(), 0,
                                   reinterpret_cast<sockaddr*>(&from_addr), &from_len);
            if (n > 0) {
                auto val_res = forwarder.validate_response(
                    ByteSpan(rx_buf.data(), static_cast<size_t>(n)), from_addr);
                if (val_res.is_ok()) {
                    const auto& matched_tx = val_res.value();
                    uint64_t current_gen = SnapshotManager::instance().current_generation();

                    // Insert authentic upstream response into cache
                    std::vector<uint8_t> resp_copy(rx_buf.data(), rx_buf.data() + n);
                    cache.insert(matched_tx.expected_qname,
                                 static_cast<uint16_t>(matched_tx.expected_qtype), 1,
                                 resp_copy, 60, current_gen);

                    // Restore client TxID
                    ResponseBuilder::translate_txid(
                        MutableByteSpan(rx_buf.data(), static_cast<size_t>(n)), matched_tx.client_txid);

                    ::sendto(server_fd, rx_buf.data(), static_cast<size_t>(n), 0,
                             reinterpret_cast<const sockaddr*>(&matched_tx.client_addr), sizeof(matched_tx.client_addr));
                    if (!quiet) std::cout << "[RESOLVED] " << matched_tx.expected_qname << " (Cached, gen=" << current_gen << ")\n";
                } else {
                    if (!quiet) std::cerr << "Spoofed / Invalid response dropped: " << error_string(val_res.error()) << "\n";
                }
            }
        }
    }

    std::cout << "\nShutting down gracefully.\n";
    ipc_server.stop();
    ::close(server_fd);
    return 0;
}
