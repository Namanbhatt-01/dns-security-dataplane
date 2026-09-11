#pragma once

#include "suffix_trie.h"
#include <string>
#include <unordered_set>
#include <string_view>
#include <cstdint>

namespace dataplane::engine {

enum class Action {
    ALLOW,
    BLOCK_NXDOMAIN,
    BLOCK_REFUSED,
    BLOCK_SINKHOLE
};

struct Decision {
    Action action{Action::ALLOW};
    std::string reason{"DEFAULT_ALLOW"};
    uint32_t matched_rule_id{0};
};

class PolicyEngine {
public:
    void add_allowlist(std::string domain) {
        allowlist_.insert(std::move(domain));
    }

    void add_exact_block(std::string domain, Action action = Action::BLOCK_NXDOMAIN) {
        exact_blocks_[std::move(domain)] = action;
    }

    void add_suffix_block(std::string_view domain, uint32_t rule_id = 0) {
        suffix_trie_.insert(domain, rule_id);
    }

    Decision evaluate(std::string_view normalized_domain) const {
        std::string dom(normalized_domain);

        // 1. Explicit Allowlist takes highest precedence
        if (allowlist_.find(dom) != allowlist_.end()) {
            return Decision{Action::ALLOW, "EXPLICIT_ALLOWLIST", 0};
        }

        // 2. Explicit Exact Block
        auto it = exact_blocks_.find(dom);
        if (it != exact_blocks_.end()) {
            return Decision{it->second, "EXACT_BLOCK", 0};
        }

        // 3. Suffix Trie Block
        uint32_t rule_id = 0;
        if (suffix_trie_.matches(normalized_domain, &rule_id)) {
            return Decision{Action::BLOCK_NXDOMAIN, "SUFFIX_TRIE_BLOCK", rule_id};
        }

        // 4. Default Allow / Forward
        return Decision{Action::ALLOW, "DEFAULT_ALLOW", 0};
    }

private:
    std::unordered_set<std::string> allowlist_;
    std::unordered_map<std::string, Action> exact_blocks_;
    DomainSuffixTrie suffix_trie_;
};

} // namespace dataplane::engine
