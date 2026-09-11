#include "runtime/atomic_snapshot.h"

namespace dataplane::runtime {

SnapshotManager& SnapshotManager::instance() {
    static SnapshotManager mgr;
    return mgr;
}

SnapshotManager::SnapshotManager() {
    auto initial = std::make_unique<PolicySnapshot>();
    initial->generation = 1;
    initial->version_hash = "bootstrap_v1";
    std::shared_ptr<const PolicySnapshot> ptr = std::move(initial);
    std::atomic_store(&active_snapshot_, ptr);
}

void SnapshotManager::reset() {
    auto initial = std::make_unique<PolicySnapshot>();
    initial->generation = 1;
    initial->version_hash = "bootstrap_v1";
    global_generation_.store(1, std::memory_order_release);
    std::shared_ptr<const PolicySnapshot> ptr = std::move(initial);
    std::atomic_store(&active_snapshot_, ptr);
}

bool SnapshotManager::apply_candidate(std::unique_ptr<PolicySnapshot> candidate, std::string* err_out) {
    if (!candidate) {
        if (err_out) *err_out = "Null candidate pointer";
        return false;
    }

    // Defensive self-check: verify candidate generation is strictly increasing
    uint64_t current_gen = global_generation_.load(std::memory_order_acquire);
    if (candidate->generation <= current_gen) {
        if (err_out) *err_out = "Candidate generation must be > active generation";
        return false; // Rollback
    }

    // Defensive check: empty version hash is rejected
    if (candidate->version_hash.empty()) {
        if (err_out) *err_out = "Candidate missing cryptographic version hash";
        return false; // Rollback
    }

    // Convert candidate to shared_ptr
    std::shared_ptr<const PolicySnapshot> new_snapshot = std::move(candidate);

    // 1. Atomic pointer swap (RCU update)
    std::atomic_store(&active_snapshot_, new_snapshot);

    // 2. Increment global policy generation counter
    global_generation_.store(new_snapshot->generation, std::memory_order_release);

    return true;
}

} // namespace dataplane::runtime
