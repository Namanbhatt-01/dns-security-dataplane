#include "engine/suffix_trie.h"
#include <algorithm>
#include <cctype>

namespace dataplane::engine {

DomainSuffixTrie::DomainSuffixTrie() : root_(std::make_unique<TrieNode>()) {}
DomainSuffixTrie::~DomainSuffixTrie() = default;

std::vector<std::string> DomainSuffixTrie::split_labels_reversed(std::string_view domain) {
    std::vector<std::string> labels;
    if (domain.empty()) return labels;

    // Remove leading/trailing dots if any
    while (!domain.empty() && domain.front() == '.') domain.remove_prefix(1);
    while (!domain.empty() && domain.back() == '.') domain.remove_suffix(1);

    size_t start = 0;
    while (start < domain.size()) {
        size_t dot = domain.find('.', start);
        if (dot == std::string_view::npos) dot = domain.size();

        std::string label;
        label.reserve(dot - start);
        for (size_t i = start; i < dot; ++i) {
            label.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(domain[i]))));
        }
        if (!label.empty()) {
            labels.push_back(std::move(label));
        }
        start = dot + 1;
    }

    // Reverse labels: "sub.example.com" -> ["com", "example", "sub"]
    std::reverse(labels.begin(), labels.end());
    return labels;
}

void DomainSuffixTrie::insert(std::string_view domain, uint32_t rule_id) {
    auto labels = split_labels_reversed(domain);
    if (labels.empty()) return;

    TrieNode* curr = root_.get();
    for (const auto& label : labels) {
        auto it = curr->children.find(label);
        if (it == curr->children.end()) {
            auto new_node = std::make_unique<TrieNode>();
            TrieNode* ptr = new_node.get();
            curr->children[label] = std::move(new_node);
            curr = ptr;
        } else {
            curr = it->second.get();
        }
    }

    if (!curr->is_terminal) {
        curr->is_terminal = true;
        curr->rule_id = rule_id;
        size_++;
    }
}

bool DomainSuffixTrie::matches(std::string_view domain, uint32_t* out_rule_id) const {
    auto labels = split_labels_reversed(domain);
    if (labels.empty()) return false;

    const TrieNode* curr = root_.get();
    for (const auto& label : labels) {
        auto it = curr->children.find(label);
        if (it == curr->children.end()) {
            return false;
        }
        curr = it->second.get();

        // If an ancestor node is marked terminal, any sub-domain matches!
        if (curr->is_terminal) {
            if (out_rule_id) {
                *out_rule_id = curr->rule_id;
            }
            return true;
        }
    }

    return curr->is_terminal;
}

} // namespace dataplane::engine
