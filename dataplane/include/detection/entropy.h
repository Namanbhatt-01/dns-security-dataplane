#pragma once

#include <string_view>
#include <cmath>
#include <array>

namespace dataplane::detection {

class EntropyCalculator {
public:
    // Computes Shannon Entropy H = -sum(p * log2(p)) for domain string or label
    static double calculate(std::string_view str) {
        if (str.empty()) return 0.0;

        std::array<size_t, 256> freq{};
        for (unsigned char c : str) {
            freq[c]++;
        }

        double entropy = 0.0;
        double len = static_cast<double>(str.size());

        for (size_t count : freq) {
            if (count > 0) {
                double p = static_cast<double>(count) / len;
                entropy -= p * std::log2(p);
            }
        }

        return entropy;
    }

    // Evaluates whether domain indicates suspected DNS tunneling (Entropy > threshold)
    // NOTE: Loophole #7 mandate: This is strictly an operational heuristic (ALERT mode),
    // NEVER used for automated blocking.
    static bool is_suspicious_entropy(std::string_view domain, double threshold = 3.8) {
        // Extract leftmost subdomain label if present
        size_t first_dot = domain.find('.');
        std::string_view label = (first_dot != std::string_view::npos) ? domain.substr(0, first_dot) : domain;

        // Ignore very short labels (entropy requires sufficient sample length)
        if (label.size() < 8) {
            return false;
        }

        return calculate(label) >= threshold;
    }
};

} // namespace dataplane::detection
