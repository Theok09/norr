# NORR — Full Problem Review, Competitor Comparison, Capability Roadmap

Date: 2026-10-04. Live-verified on ir (94.183.218.24) ↔ ex2 (45.135.195.61).

## 1. Live carrier status (measured, both directions, same session)

| Carrier | Up (ir→ex) | Down (ex→ir) | State |
|---|---|---|---|
| udp + obfuscation | 610–626 Mbit | 356 Mbit | healthy — champion |
| icmp | 393 Mbit | 250 Mbit | healthy |
| tcp-tls (real TLS 1.3 PSK) | 281 Mbit | 258 Mbit | healthy |
| camo (was fake-TLS) | 256 Mbit | 268 Mbit | healthy — FIXED this session |

Path ceiling is the Iran↔abroad link (single-stream ~637 Mbit), not the code.

## 2. Fixed this session

- **camo collapse (0 → 256 Mbit).** Three stacked causes: frame-drop under backpressure, unbounded RX buffer defeating TCP flow control, and the real killer — fake-TLS data records were not TLS 1.3 on the wire (0x17 header + raw payload, fixed 16384 chunking, no AEAD expansion), so Iran DPI fingerprinted and throttled them. Switched camo to real TLS 1.3 (the same path tcp-tls uses, never throttled). Key finding: a forged SNI whose IP does not match (microsoft.com → non-Microsoft IP) is itself throttled; SNI must match the endpoint or be omitted.
- **obfuscation junk-padding security bug.** Padding applied only to the first 64 packets, then vanished — a stronger fingerprint than none. Now every packet is padded (tapered after the window, never zero).
- **REALITY-on-camo made loud.** Since camo is real TLS now, REALITY cannot ride it; a camo+reality config is refused with an explicit error instead of silently degrading.

## 3. Problems that remain

### Critical (network/physics, not code)
1. **Spoofing is impossible from the current Iran server.** Live test: spoofed source IPs (same-/24, foreign, unrelated) were all dropped; only the real IP crossed. This ISP (papiliohost) enforces strict uRPF / BCP38 egress filtering. Bidirectional spoof needs an Iran ISP with loose uRPF. No code fix helps.
2. **REALITY is compromised in Iran.** DPI RST-floods at TLS-handshake completion and fingerprints the transcript. Any distinctive handshake shape is at risk. Mitigation = real TLS (undetected today) + strong obfuscation, not REALITY alone.

### Important (code, solvable)
3. **Spoof engine is not wired to any carrier.** SpoofPool / SpoofFeedback / SpoofEnvelope / SpoofSender are complete and tested but referenced by nothing in runtime/carrier/config. Activation needs: a `kSpoofReceipt` control frame (peer reports which spoofed sources arrived), SpoofSender wired into UdpCarrier, and config parsing for a spoof-source list. Pointless until problem 1 is solved.
4. **No CAP_NET_RAW.** Raw-socket spoofing needs it; `drop_privileges` keeps only CAP_NET_ADMIN. Either open the raw fd before the privilege drop or retain CAP_NET_RAW.
5. **`tests/` is in .gitignore (line 17).** No tests are tracked, so CI and fresh clones have none. Our new spoof tests are force-added; the directory-wide ignore should be removed.
6. **Work is on branch `spoof-capabilities`, not main.** The camo fix (the biggest real win) and the spoof engine live on the branch; main does not have them yet.

### Healthy
- 47 unit tests pass on the Linux servers (4 spoof suites included). The 15 failing tests are e2e only and fail for environmental reasons (scripts not synced / production tunnels hold the netns), not code.
- All four carriers up; norr-doctor all PASS.

## 4. Comparison with other spoofing / evasion tools

Researched: Candy-Spoof (AmiRCandy/Candy-Spoof, archived), ParsaKSH/spoof-tunnel (our public ancestor), QUICochet (private design, benchmarked on stated properties), hysteria2, Phantun/udp2raw, XTLS/REALITY.

| Dimension | NORR | QUICochet | Candy-Spoof | spoof-tunnel | hysteria2 / Phantun |
|---|---|---|---|---|---|
| Layer | L3 TUN (any protocol) | L4/QUIC | SOCKS5 + raw | SOCKS + raw | L4 / FakeTCP |
| Encryption | Noise IKpsk2 + real TLS 1.3 | ChaCha+TLS | none (PSK auth only) | ChaCha20-Poly1305 | varies / none |
| Source selection | HRW flow-stable | FNV hash | random per-session | round-robin per-packet | n/a (port hop) |
| Per-source health | death-streak + exp cooldown + quarantine, overflow-safe | death-streak + cooldown | none | loss% threshold | none |
| Blame signal | peer-receipt bitmap | implicit timeout | none | loss% per IP | none |
| BCP38 probing | SpoofEnvelope class sweep | none | none | CIDR tester | none |
| Spoof-source rotation over time | epoch re-roll | no | no | no | port hop (dest) |
| Raw send | IP_TRANSPARENT + sendmmsg | IP_TRANSPARENT + sendmmsg | sendto (single) | gopacket/pcap | raw |
| Failover between carriers | yes (udp/icmp/tcp/camo) | no | no | no | no |
| FEC | yes | no | no | no | no |

### Where NORR already leads
- HRW selection: when a source is quarantined only its flows move, not all (QUICochet's FNV-modulo remaps everything).
- Peer-receipt bitmap: solves the CensorSpoofer "sender can't see replies to a forged source" problem that Candy-Spoof and the academic design never solved.
- SpoofEnvelope: the only tool here that measures which source classes egress a given ISP instead of assuming spoofing works.
- epoch re-roll: a long flow migrates sources over time (defeats IP-reputation/volume blocking); none of the others do this on source IP.
- Strongest crypto + L3 generality + cross-carrier failover + FEC.

### Where NORR is behind / unproven
- The spoof engine is not wired in yet (QUICochet/spoof-tunnel actually ship a working datapath).
- Bidirectional spoof unproven from Iran (confirmed from China in the literature, not Iran; and dead on the current ISP).

## 5. Capabilities to add (ranked by real value)

### A. Highest value now (works today, no new server needed)
1. **Merge the camo fix + obfuscation fix to main and deploy.** Biggest shipped win; currently isolated on a branch.
2. **Strengthen obfuscation.** Current junk padding is a length taper. Add real length randomization / packet-size shaping so the on-wire size distribution doesn't fingerprint, since obfuscation (not REALITY) is what beats Iranian DPI now.
3. **Remove `tests/` from .gitignore** so the suite is tracked and runs in CI.

### B. Spoof activation (prepare for a spoof-capable Iran server)
4. `kSpoofReceipt` control frame — peer reports received spoofed sources; drives SpoofFeedback blame/reward.
5. Wire SpoofSender (IP_TRANSPARENT + sendmmsg) into UdpCarrier; call SpoofPool::pick per flow.
6. CAP_NET_RAW retention (or open the raw fd before privilege drop).
7. Config parsing for `transport.spoof` + `transport.spoof_sources`, gated to udp + IPv4, with the uRPF-reachability probe run first.

### C. Longer-term evasion
8. Re-home REALITY as post-handshake in-band auth so it works over real TLS (optional cover-site fronting).
9. IPv6 spoofing (current raw builder is IPv4-only); the ICMP carrier already runs over IPv6.
10. sendmmsg batching on the plain udp carrier too (not just spoof) for throughput headroom.

## 6. Honest bottom line
Spoofing is a flow-state / IP-reputation evasion, not a content/handshake evasion, and it is dead from the current Iran ISP. The winning posture against Iran today is **real TLS or udp+obfuscation on the wire, with a strong obfuscation layer and no distinctive handshake** — which is exactly what the camo fix and the obfuscation fix deliver. Keep the spoof engine ready for a loose-uRPF server, but do not block on it.
