package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

type Config struct {
	HTTPPort   int
	SocketPath string
}

type PolicyRequest struct {
	Generation   uint64   `json:"generation"`
	VersionHash  string   `json:"version_hash"`
	SuffixBlocks []string `json:"suffix_blocks"`
	ExactBlocks  []string `json:"exact_blocks"`
	Allowlist    []string `json:"allowlist"`
}

type IpcRequest struct {
	Command      string   `json:"command"`
	Generation   uint64   `json:"generation,omitempty"`
	VersionHash  string   `json:"version_hash,omitempty"`
	SuffixBlocks []string `json:"suffix_blocks,omitempty"`
	ExactBlocks  []string `json:"exact_blocks,omitempty"`
	Allowlist    []string `json:"allowlist,omitempty"`
}

type IpcResponse struct {
	Status           string `json:"status"`
	ActiveGeneration uint64 `json:"active_generation,omitempty"`
	Generation       uint64 `json:"generation,omitempty"`
	VersionHash      string `json:"version_hash,omitempty"`
	RuleCount        int    `json:"rule_count,omitempty"`
	Error            string `json:"error,omitempty"`
}

var (
	reloadsTotal        uint64
	reloadFailuresTotal uint64
)

func sendIpcCommand(socketPath string, req IpcRequest) (*IpcResponse, error) {
	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to dataplane IPC at %s: %w", socketPath, err)
	}
	defer conn.Close()

	data, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	if _, err := conn.Write(append(data, '\n')); err != nil {
		return nil, err
	}

	buf := make([]byte, 8192)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		return nil, err
	}

	var resp IpcResponse
	if err := json.Unmarshal(buf[:n], &resp); err != nil {
		return nil, fmt.Errorf("invalid response from dataplane: %w", err)
	}

	return &resp, nil
}

func main() {
	httpPort := flag.Int("port", 8080, "HTTP REST API port")
	socketPath := flag.String("socket", "/tmp/dns_dataplane_control.sock", "Path to C++ dataplane Unix socket")
	flag.Parse()

	log.Printf("======================================================")
	log.Printf("  ARM64 DNS Security Dataplane: Go Control Plane")
	log.Printf("  Listening on HTTP: :%d", *httpPort)
	log.Printf("  Dataplane IPC:     %s", *socketPath)
	log.Printf("======================================================")

	// GET /health
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp, err := sendIpcCommand(*socketPath, IpcRequest{Command: "GET_STATUS"})
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]any{
				"status": "UNHEALTHY",
				"error":  err.Error(),
			})
			return
		}

		json.NewEncoder(w).Encode(map[string]any{
			"status":            "HEALTHY",
			"dataplane":         "CONNECTED",
			"active_generation": resp.Generation,
			"version_hash":      resp.VersionHash,
			"rule_count":        resp.RuleCount,
		})
	})

	// GET /metrics (Prometheus format)
	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		reloads := atomic.LoadUint64(&reloadsTotal)
		failures := atomic.LoadUint64(&reloadFailuresTotal)

		resp, err := sendIpcCommand(*socketPath, IpcRequest{Command: "GET_STATUS"})
		var gen uint64 = 0
		if err == nil {
			gen = resp.Generation
		}

		fmt.Fprintf(w, "# HELP control_plane_reloads_total Total number of policy reload requests received\n")
		fmt.Fprintf(w, "# TYPE control_plane_reloads_total counter\n")
		fmt.Fprintf(w, "control_plane_reloads_total %d\n", reloads)

		fmt.Fprintf(w, "# HELP control_plane_reload_failures_total Total number of rejected policy updates\n")
		fmt.Fprintf(w, "# TYPE control_plane_reload_failures_total counter\n")
		fmt.Fprintf(w, "control_plane_reload_failures_total %d\n", failures)

		fmt.Fprintf(w, "# HELP dataplane_active_generation Current active policy generation in C++ dataplane\n")
		fmt.Fprintf(w, "# TYPE dataplane_active_generation gauge\n")
		fmt.Fprintf(w, "dataplane_active_generation %d\n", gen)
	})

	// GET /api/v1/policies
	// POST /api/v1/policies
	http.HandleFunc("/api/v1/policies", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.Method == http.MethodGet {
			resp, err := sendIpcCommand(*socketPath, IpcRequest{Command: "GET_STATUS"})
			if err != nil {
				w.WriteHeader(http.StatusBadGateway)
				json.NewEncoder(w).Encode(map[string]any{"error": err.Error()})
				return
			}
			json.NewEncoder(w).Encode(resp)
			return
		}

		if r.Method == http.MethodPost {
			atomic.AddUint64(&reloadsTotal, 1)

			var policyReq PolicyRequest
			if err := json.NewDecoder(r.Body).Decode(&policyReq); err != nil {
				atomic.AddUint64(&reloadFailuresTotal, 1)
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]any{"error": "Malformed JSON payload: " + err.Error()})
				return
			}

			// Pre-validation checks
			if policyReq.Generation == 0 {
				atomic.AddUint64(&reloadFailuresTotal, 1)
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]any{"error": "Generation must be > 0"})
				return
			}
			if policyReq.VersionHash == "" {
				atomic.AddUint64(&reloadFailuresTotal, 1)
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]any{"error": "version_hash is required"})
				return
			}

			// Forward candidate to C++ dataplane over IPC
			ipcReq := IpcRequest{
				Command:      "APPLY_POLICY",
				Generation:   policyReq.Generation,
				VersionHash:  policyReq.VersionHash,
				SuffixBlocks: policyReq.SuffixBlocks,
				ExactBlocks:  policyReq.ExactBlocks,
				Allowlist:    policyReq.Allowlist,
			}

			resp, err := sendIpcCommand(*socketPath, ipcReq)
			if err != nil {
				atomic.AddUint64(&reloadFailuresTotal, 1)
				w.WriteHeader(http.StatusBadGateway)
				json.NewEncoder(w).Encode(map[string]any{"error": err.Error()})
				return
			}

			if resp.Status == "OK" {
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]any{
					"status":            "ACTIVATED",
					"active_generation": resp.ActiveGeneration,
					"version_hash":      resp.VersionHash,
				})
			} else {
				// Automatic Rollback in effect: C++ rejected the candidate
				atomic.AddUint64(&reloadFailuresTotal, 1)
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]any{
					"status":            "ROLLBACK",
					"reason":            resp.Error,
					"active_generation": resp.ActiveGeneration,
				})
			}
			return
		}

		w.WriteHeader(http.StatusMethodNotAllowed)
	})

	server := &http.Server{
		Addr:         fmt.Sprintf("127.0.0.1:%d", *httpPort),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	log.Printf("Control plane ready on 127.0.0.1:%d", *httpPort)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Control plane HTTP server error: %v", err)
	}
}
