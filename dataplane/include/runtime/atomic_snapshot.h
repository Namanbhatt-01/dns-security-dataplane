#pragma once

#include "engine/suffix_trie.h"
#include "engine/decision.h"
#include <string>
#include <unordered_set>
#include <memory>
#include <atomic>
#include <string_view>

namespace dataplane::runtime {

struct PolicySnapshot {
    uint64_t generation{1};
    std::string version_hash{"init"};
    engine::DomainSuffixTrie suffix_trie;
    std::unordered_set<std::string> exact_blocks;
    std::unordered_set<std::string> allowlist;

    // Evaluates a normalized domain against this immutable snapshot
    engine::Decision evaluate(std::string_view normalized_domain) const {
        std::string dom(normalized_domain);

        // 1. Allowlist precedence
        if (allowlist.find(dom) != allowlist.end()) {
            return engine::Decision{engine::Action::ALLOW, "EXPLICIT_ALLOWLIST", 0};
        }

        // 2. Exact block
        if (exact_blocks.find(dom) != exact_blocks.end()) {
            return engine::Decision{engine::Action::BLOCK_NXDOMAIN, "EXACT_BLOCK", 0};
        }

        // 3. Suffix Trie match
        uint32_t rule_id = 0;
        if (suffix_trie.matches(normalized_domain, &rule_id)) {
            return engine::Decision{engine::Action::BLOCK_NXDOMAIN, "SUFFIX_TRIE_BLOCK", rule_id};
        }

        // 4. Default Allow
        return engine::Decision{engine::Action::ALLOW, "DEFAULT_ALLOW", 0};
    }
};

class SnapshotManager {
public:
    static SnapshotManager& instance();

    // Lock-free reader path: acquires shared ownership of active snapshot
    std::shared_ptr<const PolicySnapshot> get_active_snapshot() const {
        return std::atomic_load(&active_snapshot_);
    }

    uint64_t current_generation() const {
        return global_generation_.load(std::memory_order_acquire);
    }

    // Writer path: validates candidate, executes atomic swap, updates generation
    // Returns true on success; returns false and preserves active snapshot on failure (Rollback)
    bool apply_candidate(std::unique_ptr<PolicySnapshot> candidate, std::string* err_out = nullptr);

    // Resets to initial baseline state (useful for testing)
    void reset();

private:
    SnapshotManager();

    std::shared_ptr<const PolicySnapshot> active_snapshot_;
    std::atomic<uint64_t> global_generation_{1};
};

} // namespace dataplane::runtime
