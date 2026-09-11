#!/usr/bin/env bash
# ==============================================================================
# ARM64 DNS Security Dataplane: Interactive Live Empirical Demonstration
# Suitable for asciinema recording, portfolio showcases, and engineering demos.
# ==============================================================================

set -e

export TERM="${TERM:-xterm-256color}"

# Terminal colors
BOLD="\033[1m"
GREEN="\033[32m"
CYAN="\033[36m"
YELLOW="\033[33m"
BLUE="\033[34m"
MAGENTA="\033[35m"
RESET="\033[0m"

which clear >/dev/null 2>&1 && clear || true

echo -e "${BOLD}${CYAN}╔═══════════════════════════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}${CYAN}║                    ARM64 HIGH-PERFORMANCE DNS SECURITY DATAPLANE                  ║${RESET}"
echo -e "${BOLD}${CYAN}║             Live Empirical Verification, Architectural Benchmarks & TDD           ║${RESET}"
echo -e "${BOLD}${CYAN}╚═══════════════════════════════════════════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "${YELLOW}Host Platform:${RESET} $(uname -s) $(uname -m) ($(uname -v | cut -d: -f1))"
echo -e "${YELLOW}Compiler:${RESET}      $(${CXX:-clang++} --version | head -n 1)"
echo -e "${YELLOW}Target Arch:${RESET}   Apple Silicon ARM64 (AArch64 Zero-Copy Hot Path)"
echo ""
sleep 1

# ------------------------------------------------------------------------------
# STEP 1: Unit & Memory Safety Test Suite
# ------------------------------------------------------------------------------
echo -e "${BOLD}${BLUE}▶ [STEP 1/5] Executing TDD Test Suite (29 Test Cases with Bounded Checks)...${RESET}"
sleep 0.8
./build/dataplane/tests/dns_tests
echo ""
sleep 1

# ------------------------------------------------------------------------------
# STEP 2: Protocol Wire Fuzzer
# ------------------------------------------------------------------------------
echo -e "${BOLD}${BLUE}▶ [STEP 2/5] Running Hostile Wire Protocol Fuzzing (100,000 Corrupt Inputs)...${RESET}"
sleep 0.8
./build/dataplane/tests/fuzz_dns_parser 100000
echo ""
sleep 1

# ------------------------------------------------------------------------------
# STEP 3: Matcher Architectural Comparison Benchmark
# ------------------------------------------------------------------------------
echo -e "${BOLD}${BLUE}▶ [STEP 3/5] Benchmarking Matcher Architectures, LRU Cache & Shannon Entropy...${RESET}"
sleep 0.8
./build/dataplane/tests/benchmark_matcher_comparison
echo ""
sleep 1

# ------------------------------------------------------------------------------
# STEP 4: Live UDP Dataplane Socket Benchmark
# ------------------------------------------------------------------------------
echo -e "${BOLD}${BLUE}▶ [STEP 4/5] Launching Live C++ UDP Dataplane & Executing Concurrency Matrix...${RESET}"
sleep 0.8

# Start dataplane in background
./build/dataplane/dns_dataplane --port 1053 --quiet &
DP_PID=$!

# Ensure cleanup on exit
trap "kill -9 $DP_PID 2>/dev/null || true" EXIT

sleep 0.5
echo -e "${GREEN}✓ Dataplane process running (PID: $DP_PID, Port: 1053 UDP)${RESET}"
echo ""

# Run live benchmark runner
python3 offline/benchmarks/runner.py --port 1053

# Clean up dataplane
kill -9 $DP_PID 2>/dev/null || true
trap - EXIT
echo ""
sleep 1

# ------------------------------------------------------------------------------
# STEP 5: Evidence Artifacts & Visualizations
# ------------------------------------------------------------------------------
echo -e "${BOLD}${BLUE}▶ [STEP 5/5] Regenerating Performance Visualizations & Verifying Artifacts...${RESET}"
python3 offline/benchmarks/plot.py
echo ""

echo -e "${BOLD}${GREEN}╔═══════════════════════════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}${GREEN}║                    ALL EMPIRICAL VALIDATION GATES PASSED!                         ║${RESET}"
echo -e "${BOLD}${GREEN}║  All metrics captured live via OS kernel APIs & ARM64 hardware clock counters.    ║${RESET}"
echo -e "${BOLD}${GREEN}╚═══════════════════════════════════════════════════════════════════════════════════╝${RESET}"
echo ""
