CC ?= clang
CXX ?= clang++
BUILD_DIR ?= build

all: build controlplane

build:
	@mkdir -p $(BUILD_DIR)
	@cmake -B $(BUILD_DIR) -S . -DCMAKE_BUILD_TYPE=Release
	@cmake --build $(BUILD_DIR) --parallel

controlplane:
	@echo "=== Building Go Control Plane ==="
	@cd controlplane && go build -o controlplane_server main.go
	@echo "Control plane built: controlplane/controlplane_server"

test:
	@mkdir -p $(BUILD_DIR)
	@cmake -B $(BUILD_DIR) -S . -DCMAKE_BUILD_TYPE=Debug -DENABLE_TESTS=ON
	@cmake --build $(BUILD_DIR) --target dns_tests --parallel
	@echo "\n=== Running Unit & Malformed Input Test Suite ==="
	@./$(BUILD_DIR)/dataplane/tests/dns_tests

sanitize:
	@mkdir -p $(BUILD_DIR)_asan
	@cmake -B $(BUILD_DIR)_asan -S . -DCMAKE_BUILD_TYPE=Debug -DENABLE_TESTS=ON -DENABLE_SANITIZERS=ON
	@cmake --build $(BUILD_DIR)_asan --target dns_tests --parallel
	@echo "\n=== Running Tests under AddressSanitizer & UndefinedBehaviorSanitizer ==="
	@./$(BUILD_DIR)_asan/dataplane/tests/dns_tests

benchmark-trie:
	@mkdir -p $(BUILD_DIR)
	@cmake -B $(BUILD_DIR) -S . -DCMAKE_BUILD_TYPE=Release -DENABLE_TESTS=ON
	@cmake --build $(BUILD_DIR) --target benchmark_rule_scale --parallel
	@./$(BUILD_DIR)/dataplane/tests/benchmark_rule_scale

benchmark-matchers:
	@mkdir -p $(BUILD_DIR)
	@cmake -B $(BUILD_DIR) -S . -DCMAKE_BUILD_TYPE=Release -DENABLE_TESTS=ON
	@cmake --build $(BUILD_DIR) --target benchmark_matcher_comparison --parallel
	@./$(BUILD_DIR)/dataplane/tests/benchmark_matcher_comparison

fuzz:
	@mkdir -p $(BUILD_DIR)
	@cmake -B $(BUILD_DIR) -S . -DCMAKE_BUILD_TYPE=Release -DENABLE_TESTS=ON
	@cmake --build $(BUILD_DIR) --target fuzz_dns_parser --parallel
	@./$(BUILD_DIR)/dataplane/tests/fuzz_dns_parser 100000

benchmark: benchmark-trie benchmark-matchers
	@python3 offline/benchmarks/runner.py

clean:
	@rm -rf $(BUILD_DIR) $(BUILD_DIR)_asan
	@echo "Cleaned build artifacts."
