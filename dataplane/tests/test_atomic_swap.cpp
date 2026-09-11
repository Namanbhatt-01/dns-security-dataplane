#include "test_framework.h"
#include "runtime/atomic_snapshot.h"
#include <thread>
#include <vector>
#include <atomic>

using namespace dataplane::runtime;
using namespace dataplane::engine;

TEST_CASE(atomic_snapshot_basic_swap) {
    auto& mgr = SnapshotManager::instance();
    mgr.reset();

    ASSERT_EQ(mgr.current_generation(), 1);
    auto snap1 = mgr.get_active_snapshot();
    ASSERT_EQ(snap1->evaluate("blocked.com").action, Action::ALLOW);

    // Build candidate with rule blocking blocked.com
    auto cand = std::make_unique<PolicySnapshot>();
    cand->generation = 2;
    cand->version_hash = "sha256_v2";
    cand->suffix_trie.insert("blocked.com", 99);

    bool ok = mgr.apply_candidate(std::move(cand));
    ASSERT_TRUE(ok);
    ASSERT_EQ(mgr.current_generation(), 2);

    auto snap2 = mgr.get_active_snapshot();
    ASSERT_EQ(snap2->evaluate("blocked.com").action, Action::BLOCK_NXDOMAIN);
    ASSERT_EQ(snap2->version_hash, "sha256_v2");
}

TEST_CASE(atomic_snapshot_rollback_on_invalid_candidate) {
    auto& mgr = SnapshotManager::instance();
    mgr.reset();

    // Stale generation candidate (generation 1 <= current 1)
    auto stale_cand = std::make_unique<PolicySnapshot>();
    stale_cand->generation = 1;
    stale_cand->version_hash = "bad_gen";
    stale_cand->suffix_trie.insert("attack.com", 1);

    std::string err;
    bool ok = mgr.apply_candidate(std::move(stale_cand), &err);
    ASSERT_FALSE(ok);
    ASSERT_EQ(mgr.current_generation(), 1); // Generation unchanged!

    // Verify active snapshot is completely unchanged (Rollback)
    auto snap = mgr.get_active_snapshot();
    ASSERT_EQ(snap->evaluate("attack.com").action, Action::ALLOW);
    ASSERT_EQ(snap->version_hash, "bootstrap_v1");
}

TEST_CASE(atomic_snapshot_concurrent_readers_and_writer_stress) {
    auto& mgr = SnapshotManager::instance();
    mgr.reset();

    std::atomic<bool> running{true};
    std::atomic<uint64_t> total_queries{0};
    std::vector<std::thread> readers;

    // 4 reader worker threads constantly evaluating queries
    for (int t = 0; t < 4; ++t) {
        readers.emplace_back([&]() {
            while (running.load(std::memory_order_relaxed)) {
                auto snap = mgr.get_active_snapshot();
                auto dec = snap->evaluate("evil.com");
                // Invariant: decision must always be ALLOW or BLOCK_NXDOMAIN, never corrupt
                ASSERT_TRUE(dec.action == Action::ALLOW || dec.action == Action::BLOCK_NXDOMAIN);
                total_queries.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }

    // 1 writer thread rapidly pushing 100 atomic policy updates
    for (uint64_t gen = 2; gen <= 102; ++gen) {
        auto cand = std::make_unique<PolicySnapshot>();
        cand->generation = gen;
        cand->version_hash = "hash_" + std::to_string(gen);
        if (gen % 2 == 0) {
            cand->suffix_trie.insert("evil.com", static_cast<uint32_t>(gen));
        }
        bool ok = mgr.apply_candidate(std::move(cand));
        ASSERT_TRUE(ok);
        std::this_thread::yield();
    }

    running.store(false, std::memory_order_relaxed);
    for (auto& r : readers) {
        r.join();
    }

    ASSERT_EQ(mgr.current_generation(), 102);
    ASSERT_TRUE(total_queries.load() > 0);
}
