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

## QUIC is not a working tunnel carrier

Observed: `transport.mode = "quic"` is refused at startup.

The QUIC implementation itself works: `norr_quic_transport_tests` drives a full
client-server handshake and a DATAGRAM round-trip against ngtcp2. What is
missing is the integration. Norr's own Noise handshake is still sent on the raw
UDP socket that the QUIC connection owns, so the two protocols would collide,
and there is no QUIC listener, so a peer could not answer a dial.

Needed: a QUIC listener, and the Noise handshake carried inside QUIC DATAGRAM
rather than beside it.

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

## FEC is not in the datapath

Observed: `fec.mode` other than `"off"` is refused at startup.

The encoder and decoder are implemented and tested. What is missing is wire
framing: symbol headers, block identifiers, and the rule for how a block is
split across packets. That is a protocol change, not a wiring change.

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
