#include "test_framework.h"
#include "engine/aho_corasick.h"
#include "detection/entropy.h"

using namespace dataplane::engine;
using namespace dataplane::detection;

TEST_CASE(aho_corasick_substring_match) {
    AhoCorasick ac;
    ac.insert("evil.com", 1);
    ac.insert("phish.org", 2);
    ac.build();

    uint32_t rule_id = 0;
    ASSERT_TRUE(ac.search("bad-evil.com-site", &rule_id));
    ASSERT_EQ(rule_id, 1);

    ASSERT_TRUE(ac.search("login.phish.org", &rule_id));
    ASSERT_EQ(rule_id, 2);

    ASSERT_FALSE(ac.search("clean-site.com"));
}

TEST_CASE(aho_corasick_false_boundary_flaw_identified) {
    AhoCorasick ac;
    ac.insert("example.com", 1);
    ac.build();

    // Aho-Corasick matches raw substrings, so 'notexample.com' matches 'example.com'!
    // In DNS security, this is a FALSE POSITIVE unless expensive boundary checking is performed.
    ASSERT_TRUE(ac.search("notexample.com")); // Proof of why Suffix Trie was preferred!
}

TEST_CASE(entropy_calculation_normal_vs_tunneling) {
    // Normal English domain has lower entropy (~2.2)
    double normal_entropy = EntropyCalculator::calculate("google");
    ASSERT_TRUE(normal_entropy < 3.0);
    ASSERT_FALSE(EntropyCalculator::is_suspicious_entropy("google.com"));

    // Random hexadecimal / Base32 tunneling payload has high entropy (> 3.8)
    std::string tunnel_label = "7f3b89a1c4e20d5f";
    double tunnel_entropy = EntropyCalculator::calculate(tunnel_label);
    ASSERT_TRUE(tunnel_entropy > 3.6);
    ASSERT_TRUE(EntropyCalculator::is_suspicious_entropy(tunnel_label + ".tunnel.test"));
}
