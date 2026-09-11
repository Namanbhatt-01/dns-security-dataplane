# ADR-005: High-Performance Datapath Scaling — recvmmsg vs. io_uring vs. AF_XDP

## Status
Accepted (Architectural Roadmap for Linux Datacenter Deployment)

## Context
Our baseline C++20 dataplane achieves **~18,000 QPS** on a single CPU core using POSIX non-blocking BSD sockets (`poll()` + `recvfrom()` + `sendto()`). While optimal for local edge devices, macOS laptops, and embedded ARM appliances, high-throughput DNS security gateways at scale (e.g., Cisco Umbrella, Cloudflare 1.1.1.1, Fastly) must service **1,000,000+ queries per second per host** across 40GbE/100GbE network interfaces.

In the standard Linux networking stack, servicing 1 million UDP packets/sec via single `recvfrom()` system calls results in:
1. **System Call Overhead:** 1,000,000 context switches/sec ($~1.5\ \mu\text{s}$ penalty per switch).
2. **Kernel SKB Allocation:** Allocation and freeing of `struct sk_buff` inside the kernel for every 64-byte DNS packet.
3. **Memory Bus Saturation:** Copying packet bytes from NIC DMA ring buffers into kernel memory, and then into userspace application buffers.

## Decision Options Evaluated

### Option 1: Multi-threaded BSD Sockets + `SO_REUSEPORT`
- **Mechanism:** Bind $N$ worker threads (one per CPU core) to the same UDP port using kernel socket load-balancing (`SO_REUSEPORT`).
- **Throughput:** Scales linearly up to ~120,000 QPS across 8 cores.
- **Limitation:** Still incurs 1 context switch per packet; does not eliminate kernel SKB allocation bottlenecks.

### Option 2: Syscall Batching via `recvmmsg()` and `sendmmsg()`
- **Mechanism:** Process up to 64 or 128 UDP packets per system call invocation using Linux vector buffers (`struct mmsghdr`).
- **Throughput:** Reaches **~250,000 to 350,000 QPS** per CPU core.
- **Pros:** Native POSIX extension in modern Linux kernels without requiring external drivers or root capabilities.
- **Cons:** Packet data still traverses the kernel IP stack and sk_buff allocation.

### Option 3: Linux `io_uring` Asynchronous Ring Buffers
- **Mechanism:** Submit batched `IORING_OP_RECVMSG` requests to a shared kernel-user submission queue (SQ) and reap from completion queue (CQ).
- **Throughput:** Reaches **~450,000 QPS** per CPU core with zero context switches when running with `IORING_SETUP_SQPOLL`.
- **Pros:** Flexible, supported in Linux kernel 5.10+.
- **Cons:** Higher setup complexity; memory buffer registration required.

### Option 4: eBPF / AF_XDP (XDP_REDIRECT) Zero-Copy Kernel Bypass
- **Mechanism:** Attach an eBPF program at the network driver level (`XDP_DRV`). Filter and inspect DNS packets directly in driver RX ring buffers. Redirect valid DNS queries into userspace memory (`UMEM`) using `AF_XDP` sockets.
- **Throughput:** Exceeds **1,200,000+ QPS per CPU core** with sub-microsecond packet transit.
- **Pros:** Zero sk_buff overhead, zero memory copies between NIC DMA and user space.
- **Cons:** Requires Linux kernel 5.4+, specific NIC driver support (Mellanox, Intel i40e, AWS ENA), and elevated CAP_NET_ADMIN privileges.

## Architectural Decision

We adopt a **Tri-Tier Layered Datapath Architecture**:
1. **Tier 1 (Universal Fallback / macOS Darwin):** Non-blocking BSD socket event loop (`poll()` / `kqueue`) for development, unit testing, CI/CD, and macOS ARM64 deployment.
2. **Tier 2 (Standard Linux Production):** `recvmmsg()` / `sendmmsg()` batching with `SO_REUSEPORT` affinity for standard containerized Linux deployments (AWS ECS, Kubernetes), achieving **~300,000 QPS**.
3. **Tier 3 (Ultra High-Performance Bare-Metal):** `AF_XDP` driver zero-copy socket backend for bare-metal edge nodes processing **>1M QPS**.

## Consequences
- **Positive:** Gives clear architectural progression for systems engineering interviews (Cisco / Cloudflare).
- **Zero Architectural Refactoring:** The core C++20 `ByteSpan` parser, Reverse-Label Suffix Trie, and Generation Cache are completely decoupled from the socket transport layer, allowing drop-in connection to `AF_XDP` or `mmsghdr` buffers.
