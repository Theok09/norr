# Norr — Complete Project Specification

## Build (Phase 0)

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build
ctest --test-dir build --output-on-failure
./build/norr version
./build/norr check deployment/config-example.toml
```

For local memory-safety checks, add `-DNORR_ENABLE_SANITIZERS=ON` during configuration.

## Platform

Linux is the target. The datapath (`src/tun.cpp`, `src/udp_transport.cpp`) uses
`/dev/net/tun`, `recvmmsg` and `sendmmsg`.

The project still builds and tests on macOS so it can be developed there, but
every datapath entry point reports `unsupported_platform` on a non-Linux host
rather than pretending to work. To exercise the real datapath from a macOS
machine, build inside a Linux container with TUN access:

```sh
docker run --rm --cap-add=NET_ADMIN --device=/dev/net/tun \
  -v "$PWD":/src -w /src silkeh/clang:19 bash -c '
    apt-get update -qq && apt-get install -y -qq cmake ninja-build
    cmake -S . -B build-linux -G Ninja -DCMAKE_BUILD_TYPE=Debug
    cmake --build build-linux
    ctest --test-dir build-linux --output-on-failure'
```

Without `--cap-add=NET_ADMIN` the TUN portion of the datapath test reports
itself as skipped instead of failing.

To build the parser fuzz targets, configure with `-DNORR_BUILD_FUZZERS=ON`.
There is one target per untrusted-input parser: `parse_packet`,
`parse_handshake_frame` and `parse_config`.

Linux/Clang builds use libFuzzer. macOS/Xcode does not ship the libFuzzer
runtime, so it builds deterministic smoke drivers over the same entry points
instead. A macOS run is a rot check, not fuzz coverage; real campaigns run in
CI on Linux under ASan and UBSan. Build them with `-DNORR_BUILD_FUZZERS=ON`.

Norr is a Linux-first, high-performance encrypted Layer-3 tunnel designed around a small common core and three transport families:

1. UDP — primary performance path
2. QUIC v1 — adaptive secondary path
3. TLS 1.3 over TCP — compatibility fallback

## Non-goals

Norr does not implement:
- custom cryptographic primitives for production
- IP spoofing
- traffic-classification evasion mechanisms
- TCP-over-TCP
- mandatory application multiplexing
- WebSocket transport in core
- KCP in core

## Language and toolchain

- C++23
- Clang
- CMake + Ninja
- Linux-first
- Boost.Asio for control-plane orchestration where useful
- native Linux sockets / TUN / GSO/GRO for the hot path
- optional io_uring backend after measurement
- optional DPDK backend only as a later acceleration path

## Specification status

This repository is an implementation-oriented specification. Every protocol feature must have:
- wire format
- state machine
- error behavior
- invariants
- tests
- benchmark or operational evidence where performance-sensitive

The byte-level wire format is defined by `include/norr/packet.hpp` and `include/norr/handshake_frame.hpp`, and is frozen before interoperability work begins.
