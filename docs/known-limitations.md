# Known limitations

Verified by testing, not inferred. Each entry says what was observed and what
would be needed to close it.

## Rekey (fixed)

Previously a tunnel left running past the 120-second rekey timer stopped
carrying traffic entirely: a 150-second soak showed 100% packet loss after the
rekey and eight drops counted as `no session for peer or key id`.

Two causes, both now fixed:

- The responder holds its replacement keys provisionally until a frame
  authenticates under them, and that provisional state expires after the
  handshake timeout. The initiator installed its half and then sent nothing, so
  the responder's keys expired before any traffic arrived. The initiator now
  sends a sealed control frame as soon as it reads message 2, which is the
  CONFIRM step `protocol/handshake.md` describes.
- `SessionTable::install` erased a peer's previous session the instant the
  replacement was installed, so packets already in flight under the old key
  arrived naming a key id that no longer existed. The previous session is now
  retained for `kRetireAfter` and remains receivable.

Verified: the same soak now reports 0% packet loss, both nodes report
`completed 2`, and no `no_session` drops. Run it with
`NORR_SOAK=1 bash scripts/e2e_tunnel.sh`.

## Peer restart (fixed)

Previously a node whose peer restarted stayed on a dead session. Only the
dialing side can re-initiate, and nothing re-armed a handshake except the
120-second rekey timer, so a server restart meant up to two minutes of silence
before traffic resumed. Observed: 100% packet loss after the restart, the
restarted server counting `no session for peer or key id`, and the client
reporting `handshakes started 1` rather than 2.

`Session` now records when it last opened an authenticated frame, and the
runtime sweeps for sessions silent past `kDeadPeerTimeout`, drops them, and
re-handshakes. Verified: `NORR_RESTART=1 bash scripts/e2e_tunnel.sh` kills the
server, brings it back, and the tunnel recovers on its own.

Still true: only a peer with a configured `endpoint` can re-initiate. A
listen-only node cannot dial back, so a restart on that side is recovered by
the peer that dials, not by itself.

## QUIC carrier (working)

`transport.mode = "quic"` now carries a tunnel. Norr's own handshake rides
inside DATAGRAM frames rather than beside them on the socket, so the two
protocols never contend for it — the collision that made this unusable is gone.

The listening side needs no separate socket: `Ngtcp2Connection::accept` takes
the first Initial as a datagram, so the carrier accepts it from the shared
socket and answers. The Noise handshake waits for the QUIC handshake to finish
rather than being dialled into a connection that does not exist yet.

Verified end to end: ICMP inside QUIC DATAGRAM at 0% loss, both sides reporting
a completed handshake. `scripts/e2e_quic.sh`.

Limits by design: QUIC carries a connection between two endpoints, so the
carrier serves one peer. A configuration with more than one peer and
`transport.mode = "quic"` is refused rather than silently carrying only the
first.

## TCP carrier (working)

`transport.mode = "tcp-tls"` now carries a tunnel. A node with a configured
peer endpoint dials; one without listens. TLS 1.3 with the peer's pre-shared
key protects the connection before any Norr frame crosses it, and the Noise
handshake waits for that rather than being sent at startup into a connection
that does not exist yet.

Verified end to end: ICMP across the TLS-protected carrier at 0% loss, with
both sides reporting a completed handshake. `scripts/e2e_tcp.sh`.

Two bugs this exposed, both now fixed. Handshakes were written to the raw UDP
socket rather than the active carrier, so they went nowhere when UDP was not
carrying. And the dial happened before the carrier existed, so the first
handshake was dropped and the tunnel sat dead until the rekey timer fired two
minutes later.

Limits by design: TCP is a stream between two endpoints, so the carrier serves
exactly one peer. A configuration with more than one peer and
`transport.mode = "tcp-tls"` is refused rather than silently carrying only the
first. Head-of-line blocking is inherent — this is a compatibility carrier for
paths that block UDP, not a replacement for it.

## FEC in the datapath (fixed)

Previously `fec.mode` other than `"off"` was refused at startup: the encoder
and decoder existed, but nothing framed symbols on the wire.

A FEC symbol is now a Norr packet like any other. Its first byte carries the
protocol version and `FrameType::fec`, so a receiver tells a symbol from a
handshake by reading it rather than by knowing what the sender configured. That
tag is what lets one side enable FEC without the other side breaking, and it is
why the handshake — which does not go through the FEC encoder — still arrives.

Measured on a veth pair with `tc netem loss 20%` applied in both directions,
60 pings, `mode = "moderate"`:

| mode | end-to-end loss | symbols recovered |
|---|---|---|
| off | 38% | — |
| light | 10% | 10 |
| moderate | 0% | 25 |
| aggressive | 12% | 16 |

Two things had to be right for those numbers. A block that stops filling is
flushed after `kFecRecoveryDeadline`, or the last packets of every flow go
unprotected — this is why `light` (block size 32) recovered nothing before the
flush existed. And the parity symbol reports how many symbols the block
actually holds rather than the configured size, or the decoder waits for
symbols the sender never produced.

`scripts/e2e_fec.sh` is the standing proof: it fails if the decoder's
`recovered` counter is zero, so a run where FEC is merely framed and not
recovering is a failure even when the pings succeed.

Two honest limits remain. The parity is XOR, so one loss per block is
recoverable and a second in the same block is not — the `unrecoverable`
counter reports that. And `aggressive` measures worse than `moderate` here
because a block size of 4 puts one parity packet on the wire for every four
data packets, and at 20% loss the parity is lost as often as anything else.
The mode names describe parity density, not outcome.

## Multi-threaded datapath (removed)

There was a `WorkerPool` that opened a multi-queue TUN and ran a `Worker` per
thread. It was never wired into the runtime, and wiring it as written would
have been a vulnerability rather than a speedup.

Every worker shared one `SessionTable`, and `Session::seal` advances a
`PacketCounter` that is a plain `std::uint64_t` with no synchronisation. Two
threads sealing on the same session can be handed the same counter, and a
repeated counter under the same key is a repeated ChaCha20-Poly1305 nonce -
which discloses the XOR of two plaintexts and forfeits authentication. The
receive side has the same problem in the replay window.

Making it safe means giving each thread its own sessions, not locking a shared
table: a mutex on the datapath would cost more than the second core returns.
That is a design change, so the code was deleted rather than left in the tree
looking available. Throughput is one core's worth.

## Congestion control (wired)

Previously `CongestionController` was tested but unreachable: nothing in the
datapath constructed one, and it needed a round-trip time that nothing
measured. Feeding it a zero RTT would have been worse than leaving it out - with
no delay signal it can only ever back off and never probe back up, so the rate
would ratchet down and stay there.

The round trip is now measured rather than assumed. A keepalive carries an echo
request with an opaque token; the peer returns it in a control frame; the
sender times the difference. Both halves are inside the AEAD, so a forged echo
cannot move the estimate, and a reply claiming more than `kMaximumPlausibleRtt`
is discarded as a token that predates a restart. Measured on a veth pair the
tunnel reports `rtt 0.1 ms`, which is the right order for that link.

The controller runs only when `[qos] enabled = true`, because without a queue
there is no rate to lower. The configured `rate_bytes` is both the starting
rate and the ceiling: congestion control moves the real rate below what the
operator asked for, never above it.

The same measurement now feeds path selection, which previously scored every
path with a hardcoded RTT of zero.

## network.mtu (fixed)

Previously an explicit `network.mtu` was refused at startup and the datapath
used whatever the interface defaulted to.

`TunDevice::set_mtu` now applies it via SIOCSIFMTU, and `Runtime::start`
applies the configured value immediately after opening the device. Verified on
a real interface: a node configured with `mtu = 1380` reports `mtu 1380` under
`ip link show`.

The configuration floor was also wrong. It accepted values down to 576 while
the TUN device refuses anything below 1280, so a value in between parsed
cleanly at `norr check` and then failed at startup. The config bound is now
1280, which is IPv6's minimum link MTU, so the operator meets the limit at
check time.

PMTU discovery is still not implemented: the configured value is applied as
given and never probed or adjusted.

## Timers that are defined but never armed

`path_probe` exists in `TimerKind` and is handled as a no-op. Nothing schedules
it, so it cannot fire.

`dead_peer` and `session_expiry` are both enforced now, but by the runtime
liveness sweep rather than by scheduled timers: the sweep drops a session that
has been silent past `kDeadPeerTimeout` or that has exceeded either
`kSessionExpiry` or `kRejectAfterMessages`, then re-handshakes. The `TimerKind`
entries themselves remain unused.

## Handshake replay (fixed)

Previously the handshake payload carried only a version, a capability bitmap
and a key id. Nothing bound an initiation to a point in time, so a captured
INIT could be replayed: the responder would perform Diffie-Hellman, allocate a
key id, and build provisional state for a peer that had sent nothing. The
per-address rate limiter bounded how often that could happen but did not make
it wrong.

WireGuard solves this by keeping the greatest timestamp seen per peer and
discarding anything at or below it. Norr now does the same: the payload carries
a 64-bit nanosecond timestamp inside the Noise transcript, and the responder
rejects a stale one before allocating a key id or creating provisional state.
`replayed_initiations` counts them.

Verified by removing the check and watching `norr_control_plane_tests` fail.

## QUIC DATAGRAM sizing (fixed)

`max_datagram_size` returned `max_tx_udp_payload_size - 64`, a guess about
packet overhead rather than anything the peer had agreed to. RFC 9221 is
explicit: an endpoint MUST NOT send a DATAGRAM frame larger than the
`max_datagram_frame_size` its peer advertised, and that value covers the frame
type and length as well as the payload.

Two things were wrong. The advertised limit was never read, so the number bore
no relation to what the peer would accept. And the figure reported was not
actually sendable: a frame still has to fit inside a 1-RTT packet, which costs
a header, connection ids, a packet number and an AEAD tag on top of the frame
header. Measured against ngtcp2, a peer advertising 1200 accepted 1163 bytes of
payload while the old code offered 1191.

`max_datagram_size` now reads the peer's advertised value and subtracts both
the frame header and the packet overhead, taking the smaller of that and what
the path allows.

Known gap in this build: RFC 9221 permits zero-length datagrams, but ngtcp2
0.12 asserts rather than encoding one. Norr never sends an empty payload — a
keepalive is a sealed frame with a header and a tag — so this is not reachable,
and the test documents it rather than asserting behaviour the library does not
have.

## Traffic-analysis padding (fixed)

Norr sent each inner packet at its exact size, so the ciphertext length equalled
the plaintext length and an observer could read the size of every packet the
tunnel carried. WireGuard pads each inner plaintext to a multiple of 16 before
encryption for this reason; Norr now does the same.

No length field was added to undo it. An IP header carries its own total
length, so the receiver reads that and trims the rest. `declared_ip_length`
exists for exactly that step, because `parse_ip_packet` requires the declared
length to match the buffer exactly and a padded buffer never does.

Cost is at most 15 bytes per packet. Verified: two inner packets of different
sizes that fall in the same 16-byte block produce ciphertext of identical
length.

Not addressed: the padding is deterministic, so the *set* of possible sizes is
still 16-byte quantised and timing is untouched. Defeating a serious traffic
analyst needs random padding and cover traffic, which is a larger design
question than alignment.

## Live reload (added)

The systemd unit declared `ExecReload=/bin/kill -HUP $MAINPID`, but nothing
handled SIGHUP, so reloading killed the tunnel. That was worse than having no
reload at all.

SIGHUP now re-reads the configuration and applies the peer set: additions,
removals, changed keys, endpoints and prefixes. A peer is identified by its
static key rather than its position in the file, so a peer that is still
present keeps its id and its established session.

Refused rather than half-applied: the interface name, the listen port, the
transport mode, and any FEC setting. Changing those means recreating the
device or the socket, which drops every session — a restart by another name.

A malformed file changes nothing: the whole configuration is decoded before
anything is replaced.

Verified: adding a peer to a live tunnel reports `reload: 2 peers` and the
existing session continues at 0% packet loss; appending a broken key is
refused and the tunnel is unharmed. `NORR_RELOAD=1 bash scripts/e2e_tunnel.sh`.

Not covered: removing a peer stops new handshakes and drops its routes, but
leaves an established session until it times out. Tearing it down inside the
reload would drop packets already in flight.

## Limits follow WireGuard's timer state machine

Norr uses the same profile as WireGuard, so it uses the same bounds rather than
inventing its own:

| | WireGuard | Norr |
|---|---|---|
| REKEY_AFTER_MESSAGES | 2^60 | `kRekeyAfterMessages` |
| REJECT_AFTER_MESSAGES | 2^64 - 2^13 - 1 | `kRejectAfterMessages` |
| REKEY_AFTER_TIME | 120s | `kRekeyAfter` |
| REJECT_AFTER_TIME | 180s | `kSessionExpiry` |
| REKEY_TIMEOUT | 5s | `kHandshakeTimeout` |
| KEEPALIVE_TIMEOUT | 10s | `kKeepaliveInterval` is 25s |

Two deliberate differences. Norr's keepalive is 25s rather than 10s, chosen to
sit inside the shortest common NAT mapping timeout without generating traffic
every ten seconds. Norr has no equivalent of REKEY_ATTEMPT_TIME; a handshake
retries with bounded backoff up to `kHandshakeRetryMax` instead of giving up
after a fixed window.

The message bounds exist because the nonce is a counter: reaching its maximum
would repeat a nonce under one key, which is the failure the Noise
specification warns about. `Session::seal` refuses past
`kRejectAfterMessages`, well before the counter itself runs out.

## Not field-validated

No deployment outside a test harness. Every figure in `bench/` is loopback or
netem in a container. There is no packaging, no upgrade path that has been
exercised, and no rollback that has been performed.
