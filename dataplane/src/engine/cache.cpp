#include "engine/cache.h"
#include <algorithm>

namespace dataplane::engine {

DnsCache::DnsCache(size_t max_entries) : max_entries_(max_entries) {}

std::string DnsCache::make_key(const std::string& qname, uint16_t qtype, uint16_t qclass) {
    return qname + ":" + std::to_string(qtype) + ":" + std::to_string(qclass);
}

std::optional<CacheEntry> DnsCache::lookup(
    const std::string& qname, uint16_t qtype, uint16_t qclass, uint64_t current_generation) {

    std::lock_guard<std::mutex> lock(mutex_);
    auto key = make_key(qname, qtype, qclass);
    auto it = table_.find(key);
    if (it == table_.end()) {
        return std::nullopt;
    }

    auto now = std::chrono::steady_clock::now();

    // Check TTL expiration
    if (now >= it->second.expires_at) {
        lru_order_.erase(it->second.lru_it);
        table_.erase(it);
        return std::nullopt;
    }

    // Check Generation Tag (Closes Loophole #3)
    if (it->second.policy_generation != current_generation) {
        lru_order_.erase(it->second.lru_it);
        table_.erase(it); // Invalidate stale entry
        return std::nullopt;
    }

    // O(1) LRU promotion: move key to front of lru_order_
    lru_order_.splice(lru_order_.begin(), lru_order_, it->second.lru_it);

    return it->second;
}

void DnsCache::insert(
    const std::string& qname, uint16_t qtype, uint16_t qclass,
    const std::vector<uint8_t>& response, uint32_t ttl_sec, uint64_t generation) {

    uint32_t clamped_ttl = std::clamp(ttl_sec, 1u, 86400u);

    std::lock_guard<std::mutex> lock(mutex_);
    auto key = make_key(qname, qtype, qclass);

    auto it = table_.find(key);
    if (it != table_.end()) {
        // Key exists: update in place and promote to front
        it->second.response = response;
        it->second.expires_at = std::chrono::steady_clock::now() + std::chrono::seconds(clamped_ttl);
        it->second.policy_generation = generation;
        lru_order_.splice(lru_order_.begin(), lru_order_, it->second.lru_it);
        return;
    }

    // If cache is full, perform O(1) LRU eviction
    if (table_.size() >= max_entries_) {
        const std::string& oldest_key = lru_order_.back();
        table_.erase(oldest_key);
        lru_order_.pop_back();
    }

    // Push new key to front of LRU order
    lru_order_.push_front(key);

    CacheEntry entry;
    entry.response = response;
    entry.expires_at = std::chrono::steady_clock::now() + std::chrono::seconds(clamped_ttl);
    entry.policy_generation = generation;
    entry.lru_it = lru_order_.begin();

    table_[std::move(key)] = std::move(entry);
}

size_t DnsCache::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return table_.size();
}

void DnsCache::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    table_.clear();
    lru_order_.clear();
}

} // namespace dataplane::engine
