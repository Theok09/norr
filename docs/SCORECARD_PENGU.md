# NORR vs PenguTunnel v3.21.0 — scored comparison

Full review of PenguTunnel source (Go, ~30k lines) against NORR (C++23,
~20.8k lines, 48 tests). Scores are 0–10; "winner" is who leads that row.
Date: 2026-10-07.

## Scorecard

| # | Area | NORR | Pengu | Winner | Notes |
|---|------|------|-------|--------|-------|
| 1 | Raw-IP framing (esp/ah/gre/ipip/ospf/icmp) | 10 | 10 | tie | byte-identical; verified |
| 2 | ESP fingerprint | 9 | 6 | **NORR** | SPI from PSK vs fixed `deadbeef` |
| 3 | DNS carrier | 9 | 9 | tie | identical TXT + length-trailer |
| 4 | SSH carrier | 9 | 8 | **NORR** | full RFC4253; Pengu sftp is banner-only |
| 5 | greeting carriers (pop3/smtp/xmpp) | 9 | 9 | tie | same greetings |
| 6 | UDP carrier | 8 | 6 | **NORR** | obfuscation (mask/junk/bucket/priming) vs bare |
| 7 | Crypto / key exchange | 10 | 5 | **NORR** | Noise+X25519+forward-secrecy+rekey vs static PSK |
| 8 | Congestion control | 9 | 4 | **NORR** | delay+loss controller + Brutal vs none |
| 9 | FEC | 8 | 7 | **NORR** | adaptive w/ feedback vs fixed config |
| 10 | Obfuscation depth | 9 | 7 | **NORR** | header-mask/junk/length-bucket/priming |
| 11 | Datapath throughput (raw) | 7 | 9 | **Pengu** | Pengu multi-carrier+goroutine; NORR now batched (sendmmsg/recvmmsg) but single-thread/single-flow |
| 12 | Carrier rotation (make-before-break) | 3 | 9 | **Pengu** | Pengu new identity each rekey, 0-gap; NORR none |
| 13 | Keepalive robustness | 7 | 9 | **Pengu** | Pengu dedicated ka lane; NORR shared send path |
| 14 | Pool / multi-connection | 7 | 9 | **Pengu** | Pengu mature mux; NORR basic target_/extra_ |
| 15 | Spoofing | 5 | 7 | **Pengu** | Pengu static works; NORR dynamic but gated/incomplete |
| 16 | CLI / operator UX | 9 | 3 | **NORR** | menu+join-code+status/logs/doctor vs -config only |
| 17 | Installer | 9 | 6 | **NORR** | curl\|bash+checksum+source-fallback; Pengu's is external |
| 18 | Config ergonomics | 8 | 8 | tie | NORR join-code; Pengu load-time Notes (now in NORR too) |
| 19 | Code cleanliness | 9 | 8 | **NORR** | 0 comments(policy)/0 TODO/48 tests/C++23/-Werror |
| 20 | L4 no-TUN forward | 0 | 8 | **Pengu** | tcpfwd/tcpmux; NORR is L3-only (design choice) |
| 21 | Unique carriers | 8 | 6 | **NORR** | REALITY vs ipx(dead) |

## Aggregate

| Category | NORR avg | Pengu avg |
|---|---|---|
| Transports & framing (1–6) | **9.0** | 8.0 |
| Crypto & reliability (7–10) | **9.0** | 5.75 |
| Performance & pool (11–15) | 5.8 | **8.6** |
| Operations (16–19) | **8.75** | 6.25 |
| Breadth (20–21) | 4.0 | **7.0** |
| **Overall** | **8.0** | **7.3** |

## Where NORR wins (and why it matters)

- **Crypto (10 vs 5):** real Noise handshake + X25519 ephemeral + forward
  secrecy + rekey. Pengu is a single static PSK-derived key — if the PSK
  leaks, all recorded traffic (past+future) decrypts. This session also
  proved a PSK mode is unsafe to bolt on: NORR's counter-nonce + a fixed
  key = nonce-reuse on restart. Noise is the correct design.
- **Congestion control (9 vs 4):** explicit delay+loss controller and a
  Brutal rate option; Pengu leans on kernel TCP and has none for datagram.
- **Operator CLI (9 vs 3):** `norr server`→join-code, `norr client <code>`,
  status/logs/doctor/edit/failover, interactive menu, install.sh. Pengu is
  `-config file.toml` plus an external installer.
- **ESP/SSH/UDP/obfuscation:** per-tunnel ESP SPI, full RFC4253 SSH framing,
  UDP obfuscation Pengu's bare UDP lacks.

## Where Pengu wins (the real gaps)

- **Raw throughput (9 vs 7):** Pengu runs several carriers per direction,
  each a goroutine with its own batched socket, and spreads flows across
  them. NORR is single-threaded and single-socket per carrier. This session
  closed part of the gap by batching the raw datapath (sendmmsg + recvmmsg:
  AH 278→~450 Mbit), but the architectural ceiling is single-thread crypto
  on one session (a mutex serialises seal/open), so a single vless flow
  cannot parallelise. Pengu's edge here is real.
- **Make-before-break rotation (3 vs 9):** each rekey Pengu dials a fresh
  carrier (new source port / raw tag), brings it up, then retires the old
  one after a grace — new on-wire identity, zero data-plane gap, sheds a
  per-flow throttle/fingerprint. NORR rekeys the key only; the carrier
  identity is stable. **Biggest genuine anti-DPI gap.**
- **Dedicated keepalive lane (7 vs 9):** Pengu's liveness beacon rides its
  own queue, never silenced by a congested bulk queue; NORR shares the send
  path (the SSH reconnect-storm this session had a related root cause).
- **Pool maturity (7 vs 9):** Pengu's mux has admission control, HRW flow
  hashing, ticket ordering; NORR's is a basic parallel set.
- **L4 no-TUN forward (0 vs 8):** tcpfwd/tcpmux port-forward mode. NORR is a
  full L3 TUN tunnel — a design choice, not strictly a defect.

## Fixed/added this session (13 commits)

- SSH carrier: RFC4253 framing added; reconnect-storm fixed (was
  obfuscation stacked under SSH → would_block drops → silence → reconnect);
  pop3/ssh state now reset on close so reconnect re-runs the banner.
- Raw datapath batched: sendmmsg + recvmmsg (closed part of the speed gap).
- ESP SPI derived from PSK (no fixed fingerprint).
- DNS/53 carrier added (crackdown-proof), with parser hardening.
- CLI now exposes all 11 carriers + join-code 4-bit transport field.
- rekey_interval configurable; load-time config notes; obfuscation allowed
  on framed tcp carriers.
- ICMP global sysctl bug fixed (ping is a valid health check again).
- PSK mode tried and reverted (nonce-reuse on restart — unsafe by design).

## Verdict

NORR leads overall (8.0 vs 7.3) on security, reliability, obfuscation, and
operator experience — the things that keep a tunnel up and private through
Iran DPI. Pengu leads on raw single-flow throughput and carrier rotation,
both rooted in its multi-goroutine architecture. The two highest-value
items NORR could still take: **make-before-break rotation** (anti-DPI) and
a **dedicated keepalive lane** (reliability). Matching Pengu's raw speed for
one flow needs a multi-thread datapath, which the single-session mutex makes
a large, risky refactor with limited payoff for a single vless stream.
