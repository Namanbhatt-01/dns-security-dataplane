#pragma once

#include <iostream>
#include <vector>
#include <string>
#include <functional>
#include <chrono>

namespace tdd {

struct TestCase {
    std::string name;
    std::function<void()> func;
};

class TestRegistry {
public:
    static TestRegistry& instance() {
        static TestRegistry reg;
        return reg;
    }

    void add(const std::string& name, std::function<void()> func) {
        tests_.push_back({name, func});
    }

    int run_all() {
        int passed = 0;
        int failed = 0;
        std::cout << "\n======================================================\n";
        std::cout << "  ARM64 DNS Dataplane: TDD Test Suite Runner\n";
        std::cout << "======================================================\n";

        auto start = std::chrono::steady_clock::now();

        for (const auto& t : tests_) {
            try {
                t.func();
                std::cout << "  [PASS] " << t.name << "\n";
                passed++;
            } catch (const std::exception& e) {
                std::cout << "  [FAIL] " << t.name << "\n";
                std::cout << "         Error: " << e.what() << "\n";
                failed++;
            } catch (...) {
                std::cout << "  [FAIL] " << t.name << " (Unknown exception)\n";
                failed++;
            }
        }

        auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - start).count();

        std::cout << "------------------------------------------------------\n";
        std::cout << "Results: " << passed << " passed, " << failed << " failed in "
                  << elapsed << " us\n";
        std::cout << "======================================================\n\n";

        return failed == 0 ? 0 : 1;
    }

private:
    std::vector<TestCase> tests_;
};

struct AutoRegister {
    AutoRegister(const std::string& name, std::function<void()> func) {
        TestRegistry::instance().add(name, func);
    }
};

} // namespace tdd

#define TEST_CASE(name) \
    static void _test_##name(); \
    static tdd::AutoRegister _reg_##name(#name, _test_##name); \
    static void _test_##name()

#define ASSERT_TRUE(cond) \
    do { \
        if (!(cond)) { \
            throw std::runtime_error(std::string("Assertion failed: ") + #cond + \
                                     " at " + __FILE__ + ":" + std::to_string(__LINE__)); \
        } \
    } while (0)

#define ASSERT_FALSE(cond) ASSERT_TRUE(!(cond))

#define ASSERT_EQ(a, b) \
    do { \
        if ((a) != (b)) { \
            throw std::runtime_error(std::string("Assertion failed: ") + #a + " == " + #b + \
                                     " at " + __FILE__ + ":" + std::to_string(__LINE__)); \
        } \
    } while (0)

#define ASSERT_NE(a, b) \
    do { \
        if ((a) == (b)) { \
            throw std::runtime_error(std::string("Assertion failed: ") + #a + " != " + #b + \
                                     " at " + __FILE__ + ":" + std::to_string(__LINE__)); \
        } \
    } while (0)
