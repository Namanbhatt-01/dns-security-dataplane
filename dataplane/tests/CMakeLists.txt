add_executable(dns_tests
    test_main.cpp
    test_dns_parser.cpp
    test_response.cpp
    test_suffix_trie.cpp
    test_cache.cpp
    test_decision.cpp
    test_atomic_swap.cpp
    test_stage5.cpp
)

target_include_directories(dns_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

target_link_libraries(dns_tests PRIVATE dataplane_core)

add_executable(benchmark_rule_scale
    benchmark_rule_scale.cpp
)

target_include_directories(benchmark_rule_scale PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

target_link_libraries(benchmark_rule_scale PRIVATE dataplane_core)

add_executable(benchmark_matcher_comparison
    benchmark_matcher_comparison.cpp
)

target_include_directories(benchmark_matcher_comparison PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

target_link_libraries(benchmark_matcher_comparison PRIVATE dataplane_core)

add_executable(fuzz_dns_parser
    fuzz_dns_parser.cpp
)

target_include_directories(fuzz_dns_parser PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

target_link_libraries(fuzz_dns_parser PRIVATE dataplane_core)
