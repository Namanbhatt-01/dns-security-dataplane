#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <queue>
#include <string_view>

namespace dataplane::engine {

struct AcNode {
    std::unordered_map<char, int> transitions;
    int fail_link{0};
    bool is_match{false};
    uint32_t rule_id{0};
};

class AhoCorasick {
public:
    AhoCorasick();

    // Adds a pattern to the trie before compilation
    void insert(std::string_view pattern, uint32_t rule_id = 0);

    // Builds failure links via BFS (Aho-Corasick automaton construction)
    void build();

    // Matches if text contains any pattern as a substring
    bool search(std::string_view text, uint32_t* out_rule_id = nullptr) const;

    size_t node_count() const { return nodes_.size(); }

private:
    std::vector<AcNode> nodes_;
    bool built_{false};
};

} // namespace dataplane::engine
