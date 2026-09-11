cmake_minimum_required(VERSION 3.16)
project(arm64_dns_security_dataplane VERSION 4.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Strict compilation flags
add_compile_options(-Wall -Wextra -Wpedantic -Werror)

option(ENABLE_TESTS "Enable building unit and regression tests" ON)
option(ENABLE_SANITIZERS "Enable UBSan" OFF)
option(ENABLE_ASAN "Enable AddressSanitizer (Linux / compatible runtime)" OFF)

if(ENABLE_SANITIZERS)
    add_compile_options(-fsanitize=undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=undefined)
    message(STATUS "UndefinedBehaviorSanitizer (UBSan) enabled")
endif()

if(ENABLE_ASAN)
    add_compile_options(-fsanitize=address)
    add_link_options(-fsanitize=address)
    message(STATUS "AddressSanitizer (ASan) enabled")
endif()

add_subdirectory(dataplane)
