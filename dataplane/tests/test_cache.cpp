#include "test_framework.h"
#include "engine/cache.h"
#include <thread>
#include <chrono>

using namespace dataplane::engine;

TEST_CASE(cache_basic_insertion_and_hit) {
    DnsCache cache(100); // Capacity 100

    std::vector<uint8_t> synthetic_resp = {0x12, 0x34, 0x81, 0x80}; // Synthetic response payload
    uint64_t current_gen = 1;

    cache.insert("example.com", 1, 1, synthetic_resp, 10, current_gen); // TTL 10s

    auto entry = cache.lookup("example.com", 1, 1, current_gen);
    ASSERT_TRUE(entry.has_value());
    ASSERT_EQ(entry->response.size(), 4);
    ASSERT_EQ(entry->response[0], 0x12);
}

TEST_CASE(cache_ttl_expiration) {
    DnsCache cache(100);

    std::vector<uint8_t> synthetic_resp = {0x00};
    uint64_t current_gen = 1;

    // Short TTL (1 second)
    cache.insert("short.test", 1, 1, synthetic_resp, 1, current_gen);

    // Immediate lookup hits
    auto entry1 = cache.lookup("short.test", 1, 1, current_gen);
    ASSERT_TRUE(entry1.has_value());

    // Sleep 1.1s for expiration
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));

    auto entry2 = cache.lookup("short.test", 1, 1, current_gen);
    ASSERT_FALSE(entry2.has_value()); // Expired
}

TEST_CASE(cache_generation_invalidation_closes_loophole_3) {
    DnsCache cache(100);

    std::vector<uint8_t> allow_resp = {0xAA, 0xBB};
    uint64_t policy_gen1 = 1;

    // Query for 'malicious.test' cached as ALLOW under policy_gen1 with 3600s TTL
    cache.insert("malicious.test", 1, 1, allow_resp, 3600, policy_gen1);

    // Query hits under policy_gen1
    auto entry1 = cache.lookup("malicious.test", 1, 1, policy_gen1);
    ASSERT_TRUE(entry1.has_value());

    // Control plane pushes updated policy (e.g. emergency blocklist): increment generation to 2!
    uint64_t policy_gen2 = 2;

    // Lookup under policy_gen2 MUST return empty / stale miss to prevent bypassing the new block rule!
    auto entry2 = cache.lookup("malicious.test", 1, 1, policy_gen2);
    ASSERT_FALSE(entry2.has_value()); // Stale entry detected and invalidated!
}
