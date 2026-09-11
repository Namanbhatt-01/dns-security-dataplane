#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <list>
#include <chrono>
#include <optional>
#include <mutex>

namespace dataplane::engine {

struct CacheEntry {
    std::vector<uint8_t> response;
    std::chrono::steady_clock::time_point expires_at;
    uint64_t policy_generation{0};
    std::list<std::string>::iterator lru_it;
};

class DnsCache {
public:
    explicit DnsCache(size_t max_entries = 10000);

    // O(1) Look up cached response with LRU promotion and generation check
    std::optional<CacheEntry> lookup(
        const std::string& qname, uint16_t qtype, uint16_t qclass, uint64_t current_generation);

    // O(1) Insert response into cache with TTL, generation tag, and LRU eviction
    void insert(
        const std::string& qname, uint16_t qtype, uint16_t qclass,
        const std::vector<uint8_t>& response, uint32_t ttl_sec, uint64_t generation);

    size_t size() const;
    void clear();

private:
    static std::string make_key(const std::string& qname, uint16_t qtype, uint16_t qclass);

    size_t max_entries_;
    mutable std::mutex mutex_;
    std::unordered_map<std::string, CacheEntry> table_;
    std::list<std::string> lru_order_;
};

} // namespace dataplane::engine
