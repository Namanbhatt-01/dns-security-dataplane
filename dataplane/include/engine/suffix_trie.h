#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <string_view>
#include <cstdint>

namespace dataplane::engine {

struct TrieNode {
    std::unordered_map<std::string, std::unique_ptr<TrieNode>> children;
    bool is_terminal{false};
    uint32_t rule_id{0};
};

class DomainSuffixTrie {
public:
    DomainSuffixTrie();
    ~DomainSuffixTrie();

    // Insert domain (e.g. "example.com") into the reverse-label trie
    void insert(std::string_view domain, uint32_t rule_id = 0);

    // Matches if domain is an exact match or a subdomain of an inserted rule
    bool matches(std::string_view domain, uint32_t* out_rule_id = nullptr) const;

    size_t size() const { return size_; }

private:
    static std::vector<std::string> split_labels_reversed(std::string_view domain);

    std::unique_ptr<TrieNode> root_;
    size_t size_{0};
};

} // namespace dataplane::engine
