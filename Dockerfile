# syntax=docker/dockerfile:1
# ==============================================================================
# Multi-Stage Production Dockerfile for ARM64 / AMD64 DNS Security Dataplane
# ==============================================================================

# --- Stage 1: Build C++ Dataplane ---
FROM debian:bookworm-slim AS cpp-builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    clang \
    cmake \
    ninja-build \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY CMakeLists.txt Makefile ./
COPY dataplane/ ./dataplane/

RUN cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DENABLE_TESTS=OFF -G Ninja \
    && cmake --build build --target dns_dataplane

# --- Stage 2: Build Go Control Plane ---
FROM golang:1.22-alpine AS go-builder
WORKDIR /src/controlplane
COPY controlplane/go.mod controlplane/go.sum* ./
COPY controlplane/*.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /src/controlplane_server main.go

# --- Stage 3: Minimal Production Runtime Image ---
FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=cpp-builder /src/build/dataplane/dns_dataplane /app/dns_dataplane
COPY --from=go-builder /src/controlplane_server /app/controlplane_server
COPY config/ /app/config/

# Non-root unprivileged service user
RUN useradd -u 10001 -m -s /bin/false appuser && \
    mkdir -p /tmp/sockets && \
    chown -R appuser:appuser /app /tmp/sockets

USER appuser

EXPOSE 1053/udp 8080/tcp

# Healthcheck targeting controlplane REST /health endpoint
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:8080/health || exit 1

ENTRYPOINT ["/app/dns_dataplane", "--port", "1053", "--ipc", "/tmp/sockets/dataplane.sock"]
