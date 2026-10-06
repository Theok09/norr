# NORR vs PenguTunnel v3.21.0 — full comparison

Reviewed from PenguTunnel source at `pengutunnel-src-v3.21.0` (Go, ~30k lines
across internal/{transport,tunnel,crypto,config,l4,license,tun,forward,bansync,tuning}).
NORR is C++23. Date: 2026-10-06.

## 1. Transport framing (the wire bytes DPI sees)

All raw-IP carriers are byte-for-byte identical between the two.

| Carrier | proto | NORR frame | Pengu frame | Verdict |
|---|---|---|---|---|
| GRE | 47 | `20 00 08 00` + u32 key(tag low16) | same | identical |
| ESP | 50 | SPI(PSK-derived) + u16 tag | SPI `de ad be ef` fixed + tag | **NORR better** (per-tunnel SPI, no fixed fingerprint) |
| AH | 51 | `3b 04 00 00` + tag | same | identical |
| ipip | 4 | `45 00 len tag 40 00 64 fd +cksum` | same (proto 253) | identical (NORR receive also checks proto 253) |
| OSPF | 89 | v2 Hello 24B, tag in Router ID | same | identical |
| ICMP | 1 | type/code, tag in id, type 8 option | same | identical |
| DNS | 53/udp | TXT, flags `0100`/`8180`, length-trailer | same | identical |
| SSH | tcp | `SSH-2.0-OpenSSH_9.6p1 ...` + RFC4253 §6 binary packets | same banner | identical banner; **NORR better** (full binary-packet framing; Pengu's sftp is banner-only) |

TCP length prefix: Pengu 4-byte BE (`MaxWireMessage`), NORR 2-byte (max 65535).
No practical difference — tunnel MTU ~1380, and the prefix is never on the wire
in the clear (TLS/SSH/obfuscation wraps it).

UDP: Pengu bare (encryption only). NORR adds obfuscation (header-mask, junk
padding, length bucketing, priming). **NORR better.**

## 2. Carrier catalogue

| Carrier | NORR | Pengu | Note |
|---|---|---|---|
| udp, tcp, icmp, gre, ipip, esp, ah, ospf, dns | ✅ | ✅ | parity |
| ssh | ✅ full RFC4253 | ✅ banner (sftp) + full (ssh) | NORR ssh == Pengu ssh |
| pop3 / smtp / xmpp greeting | ✅ (camouflage=) | ✅ (PGP×3) | parity, same greetings |
| fake-tls / real-tls camo | ✅ | ✅ (tcp carrier) | parity |
| sftp | — | ✅ | = weaker ssh; NORR ssh covers it |
| ipx | — | ✅ | dead protocol, negligible value |
| L4 tcpfwd / tcpmux (no-TUN port forward) | — | ✅ | different architecture (NORR is full L3 TUN) |

NORR unique: REALITY carrier; richer obfuscation.

## 3. Crypto / security

| | NORR | Pengu |
|---|---|---|
| Key exchange | Noise handshake, X25519 | none — static PSK |
| Forward secrecy | ✅ (ephemeral + rekey) | ❌ (PSK → HKDF → fixed key) |
| Cipher | ChaCha20-Poly1305 | ChaCha20-Poly1305 / AES-GCM / XChaCha (toggle) |
| Key derivation | handshake transcript | HKDF-SHA256 over PSK |
| Rekey / rotation | ✅ time-based (now configurable) | ✅ carrier rotation (rekey_interval) |
| Replay / anti-DoS | ✅ session replay window, cookie, rate limiter | basic |

**NORR materially stronger** (real handshake + FS vs a single PSK-derived key).

## 4. Multi-carrier / pool

| Feature | NORR | Pengu |
|---|---|---|
| Multiple connections | ✅ (target_/extra_/adopt/reap) | ✅ (PooledConn mux) |
| Flow pinning (no cross-carrier reorder) | ✅ flow%count | ✅ HRW/indexed + Ticket turnstile |
| Keepalive | ✅ echo, 25s, all carriers | ✅ separate ka lane + reaper |
| Dead-carrier reap | ✅ silence timeout | ✅ idle reaper |
| **make-before-break rotation** | ❌ | ✅ retireAllBut / RotateAll (1-RTT swap, new identity each rekey) |
| **keepalive on its own lane** (never starved by bulk) | ❌ (shares send path) | ✅ kaSendCh |
| lock-free send snapshot | N/A (single-thread) | ✅ (goroutine arch needs it) |
| Ticket ordering across consumers | N/A (single-thread, in-order) | ✅ (goroutine arch needs it) |

Pengu's pool is 1392 lines; most of it (lock-free snapshot, ticket turnstile,
lanes, goroutine orchestration) exists only because Go uses many goroutines.
NORR's single-threaded poll gets the same ordering for free. **Two Pengu items
have real value NORR lacks:** make-before-break rotation (new on-wire identity
each rekey, zero-gap) and a dedicated keepalive lane (liveness never silenced by
a congested bulk queue).

## 5. Spoofing (source-IP forging)

| | NORR | Pengu |
|---|---|---|
| Transport | UDP (SpoofSender) | raw-IP only (IP_HDRINCL) |
| Sources | multiple, HRW rotation + quarantine | single static (SpoofSource) |
| Feedback | receipt loop (per-source confirmed bitmap) | none — peer told via spoof_peer config |
| Handshake safety | real source for handshake/control, spoof data only | peer pre-knows forged source, so never breaks |
| Status | engine complete, **wiring incomplete / gated** | simple, works |

**NORR's design is far more advanced** (dynamic multi-source + feedback) but is
**not live** — the dynamic handshake-return path is why it is gated, and finishing
it is complex. **Pengu's static model is simpler and actually works**: one forged
source, peer knows it in advance, so the return path is never confused. If spoof
is wanted, Pengu's static-on-raw-IP model is the lower-risk path.

Both are moot on the current Iran ISP: live test showed strict egress uRPF drops
every forged source (only the real source was delivered).

## 6. Congestion / loss

| | NORR | Pengu |
|---|---|---|
| Congestion control | ✅ delay+loss controller, Brutal-style rate option | ❌ (relies on kernel TCP / none for datagram) |
| FEC | ✅ adaptive (off/light/moderate/aggressive/auto) | ✅ fec + reorder_ms config |
| Loss reporting | ✅ control frame feedback | — |

**NORR better** (explicit CC + adaptive FEC with feedback).

## 7. CLI / operations

| | NORR | Pengu |
|---|---|---|
| Interface | `norr` + 18 subcommands + interactive menu | `pengutunnel -config file.toml` only |
| Make a tunnel | `norr server` → auto keys/IP/port + **join code** | hand-write TOML (keys, peer, addrs) |
| Join a client | `norr client <code>` | hand-write TOML, copy pubkey/psk/endpoint |
| status / logs / doctor / edit / failover | ✅ all built-in | ❌ (systemctl / journalctl by hand) |
| Installer | `install.sh` (curl\|bash, checksum, arch-detect, source fallback) | separate (telegram bot, not in this source) |
| Colour/UX | ✅ step/good/warn, banner | emoji logs |

**NORR's CLI is far cleaner and more complete.** Pengu's binary is config-file
only; its "clean" operator experience lives in a separate installer/bot not in
this tree.

## 8. What Pengu does that NORR could still take

1. **make-before-break carrier rotation** — new on-wire identity (source port /
   raw tag) each rekey with no data-plane gap. Sheds a per-flow throttle or DPI
   fingerprint that builds up against an aged carrier. (§4)
2. **dedicated keepalive lane** — liveness beacon that a congested bulk queue
   can never silence, so a slow-but-alive carrier is not falsely reaped. (§4)
3. **load-time config Notes** — warn on removed/renamed/migrated settings at
   load, for clean upgrades. (config)
4. **static raw-IP spoof model** — if spoofing is wanted at all, simpler and
   handshake-safe vs NORR's gated dynamic engine. (§5)
5. **L4 tcpfwd/tcpmux** — no-TUN port-forward mode (architecture choice, not a
   transport gap).

## 9. Where NORR already leads

- Real Noise handshake + X25519 + forward secrecy + rekey (vs static PSK). (§3)
- ESP SPI derived from PSK (no fixed `deadbeef` fingerprint). (§1)
- Full RFC 4253 SSH binary-packet framing (vs banner-only sftp). (§1,§2)
- UDP obfuscation: header-mask, junk, length bucketing, priming. (§1)
- Explicit congestion control + adaptive FEC with loss feedback. (§6)
- Complete operator CLI: menu, join codes, status/logs/doctor/edit/failover,
  install.sh. (§7)
- REALITY carrier.

## Bottom line

Transport framing is byte-identical; NORR is ahead on crypto, SSH framing, ESP
fingerprint, UDP obfuscation, congestion control, and operator CLI. Pengu is
ahead only on make-before-break rotation, a dedicated keepalive lane, load-time
config Notes, a working (if simpler) spoof, and the no-TUN L4 forward mode.
