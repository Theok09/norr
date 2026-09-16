<h1 align="center">Norr</h1>

<p align="center"><strong>An encrypted Layer&nbsp;3 tunnel for Linux.</strong></p>

<p align="center">
  <img alt="licence AGPL-3.0" src="https://img.shields.io/badge/licence-AGPL--3.0-1B4332?style=flat-square">
  <img alt="Noise IKpsk2" src="https://img.shields.io/badge/Noise-IKpsk2-2D6A4F?style=flat-square">
  <img alt="C++23" src="https://img.shields.io/badge/C%2B%2B-23-40916C?style=flat-square">
  <img alt="platform Linux" src="https://img.shields.io/badge/platform-Linux-52B788?style=flat-square">
</p>

---

Peers are identified by X25519 static keys and authenticated with the Noise
`IKpsk2` pattern. Traffic is sealed with ChaCha20-Poly1305 behind an 8192-entry
replay window.

Norr carries IP packets, not ports. Each peer is assigned inner prefixes, and a
packet is accepted only from a peer authorised to send that source address.

| | |
|---|---|
| **Carriers** | UDP, QUIC (RFC 9221 DATAGRAM), TCP + TLS 1.3 |
| **Fallback** | Automatic — moves off a blocked carrier without operator action |
| **Loss recovery** | XOR forward error correction, measured 20% → 8% |
| **Shaping** | Congestion control on a measured round trip; traffic profiles |

## Install

One command on Debian or Ubuntu. It installs dependencies, builds, runs the
test suite, installs, and creates the service account — and refuses to install
if the tests fail.

```sh
sudo sh scripts/install.sh
```

<details>
<summary>By hand</summary>

```sh
sudo apt-get install -y cmake ninja-build pkg-config \
    libsodium-dev libgnutls28-dev libngtcp2-dev libngtcp2-crypto-gnutls-dev

cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr
cmake --build build
sudo cmake --install build

sudo useradd --system --no-create-home --shell /usr/sbin/nologin norr
sudo mkdir -p /etc/norr && sudo chown root:norr /etc/norr && sudo chmod 0750 /etc/norr
```

This installs `/usr/bin/norr`, a systemd unit, and an example configuration
under `/usr/share/doc/norr/`.
</details>

## Configure

Generate a key. The private half goes to stdout and the public half to stderr,
so a redirect captures the secret alone.

```sh
sudo sh -c 'norr keygen > /etc/norr/private.key'
sudo chown root:norr /etc/norr/private.key
sudo chmod 0640 /etc/norr/private.key
```

Norr refuses to start if the key file is readable by anyone else.

**Server** — `/etc/norr/norr.toml`:

```toml
[node]
listen_port = 51820
tun = "norr0"

[identity]
key_file = "/etc/norr/private.key"

[network]
address = "10.99.0.1/32"

[[peer]]
name = "client"
public_key = "<client public key>"
preshared_key = "<shared 64-hex secret>"
allowed_ips = "10.99.0.2/32"
```

**Client** — same, plus the endpoint it dials:

```toml
[network]
address = "10.99.0.2/32"

[[peer]]
name = "server"
public_key = "<server public key>"
preshared_key = "<the same shared secret>"
endpoint = "203.0.113.10:51820"
allowed_ips = "10.99.0.1/32"
```

Validate before starting — this catches every error the runtime would hit:

```sh
norr check /etc/norr/norr.toml
```

<details>
<summary>Optional: carriers, loss recovery, shaping</summary>

```toml
[transport]
mode = "auto"        # udp, quic, tcp-tls, or auto to fall back between them
profile = "quic"     # pad to sizes a QUIC flow produces; standard, quic, dns

[fec]
mode = "moderate"    # off, light, moderate, aggressive

[qos]
enabled = true
rate_bytes = 12500000
```

`mode = "auto"` builds every carrier the host supports and moves to one that
works when the active carrier stops carrying. `[qos]` also enables congestion
control, which lowers the rate below `rate_bytes` when the path says so and
never above it.
</details>

## Run

```sh
sudo systemctl enable --now norr
```

Or with the wrapper, which also brings the interface up:

```sh
sudo norr-quick up norr
sudo norr-quick status norr
sudo norr-quick down norr
```

A bare name means `/etc/norr/<name>.toml`; a path is used as given.

The daemon never configures addresses or routes — that needs privileges it
drops at startup. `norr-quick` is the other half; `norr interface <file>`
prints what a configuration implies if you would rather apply it yourself.

```sh
sudo ip addr add 10.99.0.1/32 dev norr0
sudo ip link set norr0 up
sudo ip route add 10.99.0.2/32 dev norr0

ping -I 10.99.0.2 10.99.0.1
```

The unit runs unprivileged with only `CAP_NET_ADMIN`, which Norr drops once the
TUN device exists. Core dumps are disabled: a core file from a tunnel contains
session keys.

## Observe

```toml
[observability]
metrics = true
listen = "127.0.0.1:9101"
```

Exports packets encrypted and decrypted, drops labelled by reason, handshake
and cookie counters, and session counts. The endpoint is unauthenticated, so
bind it to loopback or a management address.

## Status

Verified end to end on Linux against a private test suite: every carrier,
automatic fallback under a blocked UDP path, multi-peer routing, rekey without
loss, recovery after a peer restart, IPv6, FEC recovery under induced loss,
reload without restart, and QoS pacing.

Norr has **not** been run outside a container. Every measurement here comes
from network namespaces, where latency is near zero and there is no NAT and no
censorship. Treat field maturity as zero.

`docs/known-limitations.md` records each gap: what was observed, and what
closing it would need.

## Design

Linux-first. The datapath uses `/dev/net/tun` with `recvmmsg` and `sendmmsg`.
The project builds on macOS for development, but every datapath entry point
reports `unsupported_platform` there rather than pretending to work.

The wire format is defined by `include/norr/packet.hpp` and
`include/norr/handshake_frame.hpp`.

Norr deliberately does not implement custom cryptographic primitives, IP
spoofing, or TCP-over-TCP.

## Development

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build
```

Add `-DNORR_ENABLE_SANITIZERS=ON` for AddressSanitizer and
UndefinedBehaviorSanitizer, or `-DNORR_BUILD_FUZZERS=ON` for one libFuzzer
target per untrusted-input parser.

The test suite is not distributed with this repository.

## Licence

GNU AGPL v3 or later. Copyright © 2026 Theok09 &lt;chariset38@gmail.com&gt;.

You may use, study, modify and redistribute Norr. If you redistribute it, or
run a modified version as a network service others connect to, you must release
your complete corresponding source under the same licence. Running an
unmodified copy privately carries no such obligation.

See [`LICENSE`](LICENSE) for the full terms, and for the licences of the
libraries Norr links against.
