# Configuration

Each tunnel is described by one file, `/etc/norr/<name>.toml`. The `norr` command creates
and maintains these files; this reference describes every setting.

Check a file before starting it:

```sh
norrd check /etc/norr/norr0.toml
```

## Example

```toml
[node]
role = "server"
listen_port = 51820
tun = "norr0"

[identity]
key_file = "/etc/norr/norr0.key"

[network]
address = "10.99.0.1/30"

[fec]
mode = "auto"

[[peer]]
name = "client"
public_key = "0f1e...64 hexadecimal characters"
preshared_key = "9a8b...64 hexadecimal characters"
allowed_ips = "10.99.0.2/32"

[[forward]]
listen_port = 443
target = "10.99.0.2:443"
preserve_source = true
```

## `[node]`

| Key | Description | Default |
| --- | --- | --- |
| `role` | `server` or `client`. | `server` |
| `listen_port` | UDP port for tunnel traffic. Required. | |
| `tun` | Interface name, up to 15 characters. | `norr0` |
| `user` | Account the service runs as after start-up. | `nobody` |

## `[identity]`

| Key | Description |
| --- | --- |
| `key_file` | Private key produced by `norrd keygen`. Must not be readable by group or others. |

## `[network]`

| Key | Description | Default |
| --- | --- | --- |
| `address` | Tunnel address of this server, with prefix length. | |
| `mtu` | Interface MTU, or `auto`. | `1420` |
| `forward` | Route traffic from the peer to the internet with NAT. | `false` |
| `fwmark` | Firewall mark for sending all traffic through the tunnel. | |
| `return_via_tunnel` | Send replies to connections that arrived through the tunnel back through it. Required on the client when user addresses are preserved. | `false` |
| `offload` | Use kernel segmentation offload on the tunnel interface. | `true` |

## `[transport]`

| Key | Description | Default |
| --- | --- | --- |
| `mode` | `udp`, `tcp-tls`, `quic`, or `auto` to fall back automatically. | `auto` |
| `connections` | Parallel TCP connections for the `tcp-tls` carrier, 1 to 8. More connections avoid head-of-line blocking on a clean TCP path. | `1` |
| `spoof_source_ips` | Comma-separated source addresses the `udp` carrier forges on outbound datagrams, rotated per packet. The peer replies to the real endpoint learned in the handshake, so a stateful middlebox sees only unidirectional flows. Requires `CAP_NET_ADMIN`. | |

## `[fec]`

| Key | Description | Default |
| --- | --- | --- |
| `mode` | `auto`, `off`, `light`, `moderate` or `aggressive`. `auto` measures loss and adapts. | `off` |

## `[[peer]]`

| Key | Description | Default |
| --- | --- | --- |
| `name` | Label. | |
| `public_key` | The peer's public key. Required. | |
| `preshared_key` | Shared secret mixed into the key exchange. | |
| `endpoint` | `address:port` to connect to. Omit on the side that waits. | |
| `allowed_ips` | Addresses the peer may send from, comma separated. Required. | |
| `routes` | Add routes for `allowed_ips`. Set to `false` when the list only authorises addresses. | `true` |

## `[[forward]]`

| Key | Description | Default |
| --- | --- | --- |
| `listen_port` | Port on this server. Required. | |
| `target` | `address:port` on the other side of the tunnel. Required. | |
| `protocol` | `tcp`, `udp` or `both`. | `both` |
| `preserve_source` | Keep the user's address for TCP instead of translating it. | `false` |

## `[qos]` and `[observability]`

| Key | Description |
| --- | --- |
| `qos.enabled`, `qos.rate_bytes`, `qos.burst_bytes` | Rate limit and prioritise traffic entering the tunnel. |
| `observability.metrics`, `observability.listen` | Expose Prometheus metrics on the given address. Bind to a private address. |
