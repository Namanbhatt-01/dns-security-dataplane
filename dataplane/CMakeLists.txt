add_library(dataplane_core
    src/dns/parser.cpp
    src/dns/response.cpp
    src/dns/forwarder.cpp
    src/engine/suffix_trie.cpp
    src/engine/cache.cpp
    src/engine/aho_corasick.cpp
    src/runtime/atomic_snapshot.cpp
    src/runtime/ipc_server.cpp
)

target_include_directories(dataplane_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

add_executable(dns_dataplane
    src/main.cpp
)

target_link_libraries(dns_dataplane PRIVATE dataplane_core)

if(ENABLE_TESTS)
    add_subdirectory(tests)
endif()
