#include "test_framework.h"
#include "engine/suffix_trie.h"

using namespace dataplane::engine;

TEST_CASE(suffix_trie_exact_and_subdomain_match) {
    DomainSuffixTrie trie;
    trie.insert("example.com", 1);

    // Exact match
    ASSERT_TRUE(trie.matches("example.com"));

    // Subdomain match
    ASSERT_TRUE(trie.matches("www.example.com"));
    ASSERT_TRUE(trie.matches("a.b.c.example.com"));
}

TEST_CASE(suffix_trie_boundary_safety) {
    DomainSuffixTrie trie;
    trie.insert("example.com", 1);

    // NOT a subdomain: must NOT match
    ASSERT_FALSE(trie.matches("notexample.com"));
    ASSERT_FALSE(trie.matches("myexample.com"));
    ASSERT_FALSE(trie.matches("example.com.evil.test"));
    ASSERT_FALSE(trie.matches("com"));
}

TEST_CASE(suffix_trie_multiple_rules_and_wildcard) {
    DomainSuffixTrie trie;
    trie.insert("adservice.google.com", 101);
    trie.insert("doubleclick.net", 102);

    ASSERT_TRUE(trie.matches("adservice.google.com"));
    ASSERT_TRUE(trie.matches("sub.adservice.google.com"));
    ASSERT_FALSE(trie.matches("google.com")); // Apex google.com not blocked

    ASSERT_TRUE(trie.matches("doubleclick.net"));
    ASSERT_TRUE(trie.matches("ad.doubleclick.net"));
    ASSERT_FALSE(trie.matches("click.net"));
}

TEST_CASE(suffix_trie_empty_and_normalization) {
    DomainSuffixTrie trie;
    ASSERT_FALSE(trie.matches("anything.com"));

    trie.insert("UPPERCASE.TEST", 201);
    ASSERT_TRUE(trie.matches("uppercase.test"));
    ASSERT_TRUE(trie.matches("sub.uppercase.test"));
}
