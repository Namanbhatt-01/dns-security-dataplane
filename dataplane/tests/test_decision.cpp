#include "test_framework.h"
#include "engine/decision.h"

using namespace dataplane::engine;

TEST_CASE(decision_precedence_allowlist_overrules_block) {
    PolicyEngine engine;
    // Suffix block *.example.com
    engine.add_suffix_block("example.com", 1);
    // Explicit allow safe.example.com
    engine.add_allowlist("safe.example.com");

    // safe.example.com must be ALLOWED because allowlist has higher precedence!
    auto d1 = engine.evaluate("safe.example.com");
    ASSERT_TRUE(d1.action == Action::ALLOW);
    ASSERT_EQ(d1.reason, "EXPLICIT_ALLOWLIST");

    // other.example.com must be BLOCKED
    auto d2 = engine.evaluate("other.example.com");
    ASSERT_TRUE(d2.action == Action::BLOCK_NXDOMAIN);
    ASSERT_EQ(d2.reason, "SUFFIX_TRIE_BLOCK");
    ASSERT_EQ(d2.matched_rule_id, 1);
}

TEST_CASE(decision_default_allow) {
    PolicyEngine engine;
    engine.add_suffix_block("bad.com", 2);

    auto d = engine.evaluate("good.org");
    ASSERT_TRUE(d.action == Action::ALLOW);
    ASSERT_EQ(d.reason, "DEFAULT_ALLOW");
}
