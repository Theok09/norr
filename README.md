# Norr

An encrypted Layer-3 tunnel for Linux. Peers are identified by X25519 static
keys and authenticated with the Noise IKpsk2 pattern; traffic is sealed with
ChaCha20-Poly1305 behind an 8192-entry replay window.

Norr carries IP packets, not ports. Each peer is assigned inner prefixes, and
a packet is only accepted from a peer authorised to send that source address.

## Install

One command, on Debian or Ubuntu. It installs dependencies, builds, runs the
test suite, installs, and creates the service account:

    sudo sh scripts/install.sh

It refuses to install if the tests fail. What it does by hand:

    sudo apt-get install -y cmake ninja-build pkg-config \
        libsodium-dev libgnutls28-dev libngtcp2-dev libngtcp2-crypto-gnutls-dev

    cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr
    cmake --build build
    sudo cmake --install build

That installs the binary at `/usr/bin/norr`, a systemd unit at
`/usr/lib/systemd/system/norr.service`, and an example configuration under
`/usr/share/doc/norr/`.

Create the service account and configuration directory:

    sudo useradd --system --no-create-home --shell /usr/sbin/nologin norr
    sudo mkdir -p /etc/norr
    sudo chown root:norr /etc/norr
    sudo chmod 0750 /etc/norr

## Configure

Generate a key. The private half goes to stdout and the public half to stderr,
so a redirect captures the secret without the public key landing in the file:

    sudo sh -c 'norr keygen > /etc/norr/private.key' 
    sudo chown root:norr /etc/norr/private.key
    sudo chmod 0640 /etc/norr/private.key

Norr refuses to start if the key file is readable by anyone else.

Copy the example and edit it:

    sudo cp /usr/share/doc/norr/norr.toml.example /etc/norr/norr.toml

A minimal two-peer configuration. On the server:

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

On the client, add the server's endpoint so it dials:

    [network]
    address = "10.99.0.2/32"

    [[peer]]
    name = "server"
    public_key = "<server public key>"
    preshared_key = "<the same shared secret>"
    endpoint = "203.0.113.10:51820"
    allowed_ips = "10.99.0.1/32"

Validate before starting. This catches every configuration error the runtime
would otherwise hit at startup:

    norr check /etc/norr/norr.toml

## Run

    sudo systemctl enable --now norr
    systemctl status norr

The unit runs as an unprivileged user with only `CAP_NET_ADMIN`, which Norr
needs to create the TUN device and drops once it exists. Core dumps are
disabled, because a core file from a tunnel contains session keys.

Norr does not configure the interface address or routes. Doing so needs
privileges the process gives up at startup, so it is left to the system. On
the server:

    sudo ip addr add 10.99.0.1/32 dev norr0
    sudo ip link set norr0 up
    sudo ip route add 10.99.0.2/32 dev norr0

And correspondingly on the client. Make these persistent through your
distribution's network configuration rather than by hand.

Verify traffic is flowing:

    ping -I 10.99.0.2 10.99.0.1

## Observe

Set an address to expose Prometheus metrics:

    [observability]
    metrics = true
    listen = "127.0.0.1:9101"

The endpoint is unauthenticated and reports traffic counters, so bind it to
loopback or a management address. It exports packets encrypted and decrypted,
drops labelled by reason, handshake and cookie counters, and session counts.

## What works, and what does not

Verified end to end on Linux: the UDP carrier, multi-peer hub-and-spoke
routing, rekey without packet loss, keepalive through NAT, QoS pacing, the
metrics endpoint, and TLS 1.3 over the TCP carrier.

Not finished, and refused at startup rather than silently ignored: QUIC and
TCP carrier selection, and FEC. Setting `transport.mode` to `quic` or
`tcp-tls`, or `fec.mode` to anything but `off`, fails with a message saying
why.

`docs/known-limitations.md` records each gap, what was observed, and what
closing it needs.

## Design

Linux-first. The datapath uses `/dev/net/tun` with `recvmmsg` and `sendmmsg`.
The project builds on macOS for development, but every datapath entry point
reports `unsupported_platform` there rather than pretending to work.

The byte-level wire format is defined by `include/norr/packet.hpp` and
`include/norr/handshake_frame.hpp`.

Norr deliberately does not implement custom cryptographic primitives, IP
spoofing, traffic-classification evasion, or TCP-over-TCP.

## Development

    cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug
    cmake --build build
    ctest --test-dir build --output-on-failure

Add `-DNORR_ENABLE_SANITIZERS=ON` for AddressSanitizer and UndefinedBehaviorSanitizer.

The datapath tests need a real TUN device. From a macOS host, run them in a
container with the capability granted, or they report themselves as skipped:

    docker run --rm --cap-add=NET_ADMIN --device=/dev/net/tun \
      -v "$PWD":/src -w /src silkeh/clang:19 bash -c '
        apt-get update -qq && apt-get install -y -qq cmake ninja-build pkg-config \
            libsodium-dev libgnutls28-dev libngtcp2-dev libngtcp2-crypto-gnutls-dev
        cmake -S . -B build-linux -G Ninja -DCMAKE_BUILD_TYPE=Debug
        cmake --build build-linux
        ctest --test-dir build-linux --output-on-failure'

Two integration scripts run real tunnels between network namespaces:
`scripts/e2e_tunnel.sh` for two nodes, `scripts/e2e_multipeer.sh` for a hub
with two spokes. Both need root.

Fuzz targets are built with `-DNORR_BUILD_FUZZERS=ON`, one per untrusted-input
parser. Linux and Clang use libFuzzer; macOS lacks the runtime and builds
deterministic smoke drivers over the same entry points instead, which is a rot
check rather than fuzz coverage.

## Licence

MIT. See `LICENSE`, which also records the terms of the libraries Norr links.
