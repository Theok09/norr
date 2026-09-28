# Norr

Norr connects two Linux machines over a private, encrypted tunnel and forwards ports from
the server to the client. Users reach a service through the server as if it were running
there, while the service itself stays on the client.

- Encrypted and mutually authenticated with the Noise protocol framework
- Forward error correction for links that lose packets
- Kernel port forwarding that keeps each user's real address
- Either side can open the connection, so only one machine needs to accept it
- Falls back from UDP to TLS over TCP or QUIC when UDP is unavailable
- One static binary for `amd64` and `arm64`

## Install

On both machines, as root:

```sh
bash <(curl -fsSL https://raw.githubusercontent.com/Theok09/norr/main/install.sh)
```

## Usage

On the server:

```sh
norr server --forward 443,2052
```

This prints a join code. On the client:

```sh
norr client <code>
```

Ports 443 and 2052 on the server now lead to the same ports on the client. To have the
server open the connection instead, use `norr server --reverse --client-ip=<ip>`.

```sh
norr status                  # tunnels and their state
norr forward add 8443        # forward another port
norr forward ls              # list forwarded ports
norr up | down               # start or stop a tunnel
norr --help                  # all commands
```

## Configuration

Tunnels are stored in `/etc/norr`. See [docs/configuration.md](docs/configuration.md) for
every setting.

## Building

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

Requires a C++23 compiler, CMake, libsodium, OpenSSL 3 and GnuTLS.

## License

[GNU Affero General Public License v3.0](LICENSE)
