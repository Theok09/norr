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

## TCP carrier cannot be selected

Observed: `transport.mode = "tcp-tls"` is refused at startup.

TLS itself is now wired into the carrier and covered by `norr_tcp_tls_tests`:
frames traverse the TLS 1.3 record layer in both directions, and a frame
offered before the handshake completes is refused rather than written to the
raw socket.

What is still missing is the surrounding machinery: there is no TCP listener
and no carrier selection, so a peer has nothing to answer a dial with. The
refusal message says exactly this rather than claiming the carrier is
unprotected, which it no longer is.

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

`session_expiry` and `path_probe` exist in `TimerKind` and are handled as
no-ops. Nothing schedules them, so they cannot fire.

`dead_peer` is no longer among them in effect: liveness is now checked by the
runtime sweep described under "Peer restart", which uses `kDeadPeerTimeout`
directly rather than a scheduled timer. The `TimerKind` entry itself remains
unused.

## Not field-validated

No deployment outside a test harness. Every figure in `bench/` is loopback or
netem in a container. There is no packaging, no upgrade path that has been
exercised, and no rollback that has been performed.
