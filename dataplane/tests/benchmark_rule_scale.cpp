#include "engine/suffix_trie.h"
#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include <iomanip>

using namespace dataplane::engine;

int main() {
    std::cout << "======================================================================\n";
    std::cout << "  ARM64 DNS Dataplane: Suffix Trie Rule-Scaling Benchmark\n";
    std::cout << "======================================================================\n";
    std::cout << std::left << std::setw(15) << "Rule Scale"
              << std::setw(18) << "Build Time (ms)"
              << std::setw(20) << "Lookup Latency (ns)"
              << std::setw(15) << "Lookups/Sec" << "\n";
    std::cout << "----------------------------------------------------------------------\n";

    std::vector<size_t> scales = {1000, 10000, 50000, 100000};

    for (size_t scale : scales) {
        DomainSuffixTrie trie;

        // 1. Measure Build Time
        auto t0 = std::chrono::steady_clock::now();
        for (size_t i = 0; i < scale; ++i) {
            std::string domain = "domain" + std::to_string(i) + ".rule.test";
            trie.insert(domain, static_cast<uint32_t>(i + 1));
        }
        auto t1 = std::chrono::steady_clock::now();
        double build_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

        // 2. Measure Lookup Latency across 500,000 lookups
        const size_t kLookups = 500000;
        std::vector<std::string> test_queries = {
            "sub.domain50.rule.test",
            "unmatched.domain.org",
            "domain500.rule.test",
            "deep.nested.sub.domain999.rule.test",
            "completely.innocent.com"
        };

        auto t2 = std::chrono::steady_clock::now();
        size_t matches = 0;
        for (size_t i = 0; i < kLookups; ++i) {
            const auto& q = test_queries[i % test_queries.size()];
            if (trie.matches(q)) {
                matches++;
            }
        }
        auto t3 = std::chrono::steady_clock::now();
        double lookup_ns_total = std::chrono::duration<double, std::nano>(t3 - t2).count();
        double ns_per_lookup = lookup_ns_total / kLookups;
        double lookups_per_sec = (static_cast<double>(kLookups) / (lookup_ns_total / 1e9));

        std::cout << std::left << std::setw(15) << scale
                  << std::setw(18) << std::fixed << std::setprecision(2) << build_ms
                  << std::setw(20) << std::fixed << std::setprecision(1) << ns_per_lookup
                  << std::setw(15) << static_cast<uint64_t>(lookups_per_sec) << "\n";
        (void)matches;
    }

    std::cout << "======================================================================\n\n";
    return 0;
}
