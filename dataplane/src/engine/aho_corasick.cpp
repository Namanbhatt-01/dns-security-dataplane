#include "engine/aho_corasick.h"
#include <cctype>

namespace dataplane::engine {

AhoCorasick::AhoCorasick() {
    nodes_.emplace_back(); // Root node at index 0
}

void AhoCorasick::insert(std::string_view pattern, uint32_t rule_id) {
    if (pattern.empty()) return;
    int curr = 0;

    for (char c : pattern) {
        char lower_c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        auto it = nodes_[curr].transitions.find(lower_c);
        if (it == nodes_[curr].transitions.end()) {
            int next_idx = static_cast<int>(nodes_.size());
            nodes_.emplace_back();
            nodes_[curr].transitions[lower_c] = next_idx;
            curr = next_idx;
        } else {
            curr = it->second;
        }
    }

    nodes_[curr].is_match = true;
    nodes_[curr].rule_id = rule_id;
    built_ = false;
}

void AhoCorasick::build() {
    std::queue<int> q;

    // Root's immediate children have failure link to root (0)
    for (auto& [c, child_idx] : nodes_[0].transitions) {
        nodes_[child_idx].fail_link = 0;
        q.push(child_idx);
    }

    // BFS failure transition propagation
    while (!q.empty()) {
        int u = q.front();
        q.pop();

        for (auto& [c, v] : nodes_[u].transitions) {
            int f = nodes_[u].fail_link;
            while (f > 0 && nodes_[f].transitions.find(c) == nodes_[f].transitions.end()) {
                f = nodes_[f].fail_link;
            }

            auto it = nodes_[f].transitions.find(c);
            if (it != nodes_[f].transitions.end() && it->second != v) {
                nodes_[v].fail_link = it->second;
            } else {
                nodes_[v].fail_link = 0;
            }

            // Inherit match status from failure link
            if (nodes_[nodes_[v].fail_link].is_match) {
                nodes_[v].is_match = true;
                nodes_[v].rule_id = nodes_[nodes_[v].fail_link].rule_id;
            }

            q.push(v);
        }
    }

    built_ = true;
}

bool AhoCorasick::search(std::string_view text, uint32_t* out_rule_id) const {
    if (!built_) return false;
    int curr = 0;

    for (char c : text) {
        char lower_c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

        while (curr > 0 && nodes_[curr].transitions.find(lower_c) == nodes_[curr].transitions.end()) {
            curr = nodes_[curr].fail_link;
        }

        auto it = nodes_[curr].transitions.find(lower_c);
        if (it != nodes_[curr].transitions.end()) {
            curr = it->second;
        } else {
            curr = 0;
        }

        if (nodes_[curr].is_match) {
            if (out_rule_id) {
                *out_rule_id = nodes_[curr].rule_id;
            }
            return true;
        }
    }

    return false;
}

} // namespace dataplane::engine
