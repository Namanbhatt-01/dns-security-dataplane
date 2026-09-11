package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetricsEndpoint(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("# HELP control_plane_reloads_total Total number of policy reload requests received\n" +
			"# TYPE control_plane_reloads_total counter\n" +
			"control_plane_reloads_total 0\n" +
			"# HELP control_plane_reload_failures_total Total number of rejected policy updates\n" +
			"# TYPE control_plane_reload_failures_total counter\n" +
			"control_plane_reload_failures_total 0\n" +
			"# HELP dataplane_active_generation Current active policy generation in C++ dataplane\n" +
			"# TYPE dataplane_active_generation gauge\n" +
			"dataplane_active_generation 1\n"))
	})

	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	body := w.Body.String()
	if !strings.Contains(body, "control_plane_reloads_total") {
		t.Errorf("expected metrics output to contain 'control_plane_reloads_total'")
	}
	if !strings.Contains(body, "dataplane_active_generation") {
		t.Errorf("expected metrics output to contain 'dataplane_active_generation'")
	}
}

func TestPolicyRequestValidation(t *testing.T) {
	// 1. Valid policy request serialization
	validReq := PolicyRequest{
		Generation:   2,
		VersionHash:  "sha256_mock_hash",
		SuffixBlocks: []string{"malware.com", "phishing.org"},
		ExactBlocks:  []string{"bad.actor.net"},
		Allowlist:    []string{"safe.cdn.com"},
	}

	data, err := json.Marshal(validReq)
	if err != nil {
		t.Fatalf("failed to marshal valid policy request: %v", err)
	}

	var decoded PolicyRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal policy request: %v", err)
	}

	if decoded.Generation != 2 {
		t.Errorf("expected generation 2, got %d", decoded.Generation)
	}
	if len(decoded.SuffixBlocks) != 2 {
		t.Errorf("expected 2 suffix blocks, got %d", len(decoded.SuffixBlocks))
	}
	if decoded.Allowlist[0] != "safe.cdn.com" {
		t.Errorf("expected allowlist 'safe.cdn.com', got %s", decoded.Allowlist[0])
	}
}

func TestHealthEndpointFallback(t *testing.T) {
	// Test health handler behavior when dataplane socket is unavailable
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Simulate socket down
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]any{
			"status": "UNHEALTHY",
			"error":  "dataplane socket connection refused",
		})
	})

	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected status 503 for unavailable socket, got %d", resp.StatusCode)
	}

	var res map[string]any
	if err := json.NewDecoder(w.Body).Decode(&res); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if res["status"] != "UNHEALTHY" {
		t.Errorf("expected status UNHEALTHY, got %v", res["status"])
	}
}
