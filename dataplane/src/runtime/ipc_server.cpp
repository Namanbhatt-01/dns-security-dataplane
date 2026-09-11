#include "runtime/ipc_server.h"
#include "runtime/atomic_snapshot.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <iostream>
#include <vector>
#include <sstream>

namespace dataplane::runtime {

IpcServer::IpcServer(std::string socket_path) : socket_path_(std::move(socket_path)) {}

IpcServer::~IpcServer() {
    stop();
}

bool IpcServer::start() {
    ::unlink(socket_path_.c_str());

    server_fd_ = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd_ < 0) {
        return false;
    }

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, socket_path_.c_str(), sizeof(addr.sun_path) - 1);

    if (::bind(server_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        ::close(server_fd_);
        server_fd_ = -1;
        return false;
    }

    if (::listen(server_fd_, 5) < 0) {
        ::close(server_fd_);
        server_fd_ = -1;
        return false;
    }

    running_.store(true);
    worker_thread_ = std::thread(&IpcServer::listen_loop, this);
    return true;
}

void IpcServer::stop() {
    if (running_.exchange(false)) {
        if (server_fd_ >= 0) {
            ::shutdown(server_fd_, SHUT_RDWR);
            ::close(server_fd_);
            server_fd_ = -1;
        }
        if (worker_thread_.joinable()) {
            worker_thread_.join();
        }
        ::unlink(socket_path_.c_str());
    }
}

// Simple JSON array parser for strings: extracts elements between ["..."]
static std::vector<std::string> extract_json_strings(const std::string& json, const std::string& key) {
    std::vector<std::string> result;
    size_t key_pos = json.find("\"" + key + "\"");
    if (key_pos == std::string::npos) return result;

    size_t start_bracket = json.find('[', key_pos);
    if (start_bracket == std::string::npos) return result;
    size_t end_bracket = json.find(']', start_bracket);
    if (end_bracket == std::string::npos) return result;

    size_t curr = start_bracket + 1;
    while (curr < end_bracket) {
        size_t open_quote = json.find('"', curr);
        if (open_quote == std::string::npos || open_quote >= end_bracket) break;
        size_t close_quote = json.find('"', open_quote + 1);
        if (close_quote == std::string::npos || close_quote >= end_bracket) break;

        result.push_back(json.substr(open_quote + 1, close_quote - open_quote - 1));
        curr = close_quote + 1;
    }
    return result;
}

static std::string extract_json_string(const std::string& json, const std::string& key) {
    size_t key_pos = json.find("\"" + key + "\"");
    if (key_pos == std::string::npos) return "";
    size_t open_quote = json.find('"', key_pos + key.size() + 2);
    if (open_quote == std::string::npos) return "";
    size_t close_quote = json.find('"', open_quote + 1);
    if (close_quote == std::string::npos) return "";
    return json.substr(open_quote + 1, close_quote - open_quote - 1);
}

static uint64_t extract_json_uint64(const std::string& json, const std::string& key) {
    size_t key_pos = json.find("\"" + key + "\"");
    if (key_pos == std::string::npos) return 0;
    size_t colon = json.find(':', key_pos);
    if (colon == std::string::npos) return 0;
    return std::strtoull(json.c_str() + colon + 1, nullptr, 10);
}

std::string IpcServer::handle_command(const std::string& req) {
    auto& mgr = SnapshotManager::instance();

    std::string cmd = extract_json_string(req, "command");

    if (cmd == "GET_STATUS") {
        auto snap = mgr.get_active_snapshot();
        std::ostringstream oss;
        oss << "{\"status\":\"OK\",\"generation\":" << mgr.current_generation()
            << ",\"version_hash\":\"" << snap->version_hash << "\""
            << ",\"rule_count\":" << snap->suffix_trie.size() + snap->exact_blocks.size() << "}\n";
        return oss.str();
    }

    if (cmd == "APPLY_POLICY") {
        uint64_t gen = extract_json_uint64(req, "generation");
        std::string hash = extract_json_string(req, "version_hash");

        auto candidate = std::make_unique<PolicySnapshot>();
        candidate->generation = gen;
        candidate->version_hash = hash;

        auto suffixes = extract_json_strings(req, "suffix_blocks");
        for (size_t i = 0; i < suffixes.size(); ++i) {
            candidate->suffix_trie.insert(suffixes[i], static_cast<uint32_t>(i + 1));
        }

        auto exacts = extract_json_strings(req, "exact_blocks");
        for (const auto& dom : exacts) {
            candidate->exact_blocks.insert(dom);
        }

        auto allows = extract_json_strings(req, "allowlist");
        for (const auto& dom : allows) {
            candidate->allowlist.insert(dom);
        }

        std::string err;
        bool ok = mgr.apply_candidate(std::move(candidate), &err);
        if (ok) {
            std::ostringstream oss;
            oss << "{\"status\":\"OK\",\"active_generation\":" << mgr.current_generation()
                << ",\"version_hash\":\"" << hash << "\"}\n";
            return oss.str();
        } else {
            // Rollback response
            std::ostringstream oss;
            oss << "{\"status\":\"REJECTED\",\"error\":\"" << err
                << "\",\"active_generation\":" << mgr.current_generation() << "}\n";
            return oss.str();
        }
    }

    return "{\"status\":\"ERROR\",\"error\":\"Unknown command\"}\n";
}

void IpcServer::listen_loop() {
    while (running_.load()) {
        sockaddr_un client_addr{};
        socklen_t client_len = sizeof(client_addr);
        int client_fd = ::accept(server_fd_, reinterpret_cast<sockaddr*>(&client_addr), &client_len);
        if (client_fd < 0) {
            if (!running_.load()) break;
            continue;
        }

        char buf[8192];
        ssize_t n = ::read(client_fd, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = '\0';
            std::string resp = handle_command(std::string(buf));
            ssize_t written = ::write(client_fd, resp.data(), resp.size());
            (void)written;
        }
        ::close(client_fd);
    }
}

} // namespace dataplane::runtime
