#include "check.hpp"
#include <algorithm>
#include <array>
#include <cstdio>
#include <vector>

#include "norr/crypto.hpp"
#include "norr/quic_transport.hpp"

namespace {

norr::Endpoint peer() {
  const auto parsed = norr::parse_endpoint("127.0.0.1:4433");
  NORR_CHECK(parsed.has_value());
  return *parsed;
}

void test_backend_reporting_is_honest() {
  // Whatever the answer, it must match what is actually linked: a caller
  // asking whether QUIC is available is asking about real QUIC, and the
  // loopback stand-in must never answer yes on its behalf.
  const auto connection = norr::make_quic_connection();
  NORR_CHECK(connection.has_value() == norr::quic_available());

  if (norr::quic_available()) {
    NORR_CHECK(norr::quic_backend_version() != "none");
    std::printf("quic: backend ngtcp2 %s\n",
                std::string{norr::quic_backend_version()}.c_str());
  } else {
    NORR_CHECK(connection.error() == norr::QuicError::unsupported);
    std::puts("quic: no backend linked, reported honestly");
  }
}

#if defined(NORR_HAVE_NGTCP2)

void test_real_connection_setup() {
  const auto peer = norr::parse_endpoint("127.0.0.1:4433");
  NORR_CHECK(peer.has_value());

  norr::Ngtcp2Connection connection;
  NORR_CHECK(!connection.established());

  // Creating the connection runs the TLS and transport-parameter setup, so a
  // failure here means the crypto callbacks or DATAGRAM parameters are wrong.
  NORR_CHECK(connection.connect(*peer).has_value());

  // Connecting twice is an error, not a silent reconnect.
  NORR_CHECK(!connection.connect(*peer).has_value());

  // The client must produce an Initial packet to send. QUIC v1 pads it to at
  // least 1200 bytes so a server's reply cannot be used for amplification.
  const auto initial = connection.next_outgoing();
  NORR_CHECK(!initial.empty());
  NORR_CHECK(initial.size() >= 1200);

  // Sending before the handshake completes must be refused rather than
  // queued into an unprotected packet.
  const std::vector<std::byte> payload(64);
  const auto premature = connection.send_datagram(payload);
  NORR_CHECK(!premature.has_value());
  NORR_CHECK(premature.error() == norr::QuicError::not_connected);

  connection.close();
  NORR_CHECK(!connection.established());

  std::puts("quic: real ngtcp2 connection and Initial packet OK");
}

void test_garbage_is_not_accepted() {
  norr::Ngtcp2Connection connection;
  const auto local = norr::parse_endpoint("127.0.0.1:1");
  const auto peer = norr::parse_endpoint("127.0.0.1:2");
  NORR_CHECK(local.has_value() && peer.has_value());

  // A datagram that is not a valid Initial must be rejected before any state
  // exists. This is the address-validation boundary: nothing an
  // unauthenticated sender controls may size an allocation.
  const std::vector<std::byte> garbage(1200);
  const auto refused = connection.accept(*local, *peer, garbage);
  NORR_CHECK(!refused.has_value());
  NORR_CHECK(refused.error() == norr::QuicError::handshake_failed);
  NORR_CHECK(!connection.established());

  // Too short to be an Initial at all.
  norr::Ngtcp2Connection second;
  const std::vector<std::byte> tiny(4);
  NORR_CHECK(!second.accept(*local, *peer, tiny).has_value());

  std::puts("quic: malformed Initial rejected before state is created OK");
}

// Drives a full client-server handshake by hand-carrying datagrams between
// the two connections. No sockets: this isolates the QUIC state machine from
// the network, so a failure here is a protocol bug rather than an I/O one.
void test_full_handshake() {
  const auto client_peer = norr::parse_endpoint("127.0.0.1:4433");
  const auto server_local = norr::parse_endpoint("127.0.0.1:4433");
  const auto server_peer = norr::parse_endpoint("127.0.0.1:55555");
  NORR_CHECK(client_peer.has_value() && server_local.has_value() && server_peer.has_value());

  norr::Ngtcp2Connection client;
  NORR_CHECK(client.connect(*client_peer).has_value());

  const auto initial = client.next_outgoing();
  NORR_CHECK(!initial.empty());
  const std::vector<std::byte> initial_copy(initial.begin(), initial.end());

  norr::Ngtcp2Connection server;
  const auto accepted = server.accept(*server_local, *server_peer, initial_copy);
  NORR_CHECK(accepted.has_value());

  // Shuttle datagrams until both sides report the handshake done.
  for (int round = 0; round < 32; ++round) {
    bool moved = false;

    while (true) {
      const auto out = server.next_outgoing();
      if (out.empty()) break;
      const std::vector<std::byte> copy(out.begin(), out.end());
      static_cast<void>(client.feed(copy));
      moved = true;
    }
    while (true) {
      const auto out = client.next_outgoing();
      if (out.empty()) break;
      const std::vector<std::byte> copy(out.begin(), out.end());
      static_cast<void>(server.feed(copy));
      moved = true;
    }

    if (client.established() && server.established()) break;
    if (!moved) break;
  }

  // Both sides must reach an established state. Reporting a pending handshake
  // as a pass would hide exactly the failure this test exists to catch.
  NORR_CHECK(client.established());
  NORR_CHECK(server.established());

  // With the handshake complete, DATAGRAM must carry payload. This is the
  // whole reason Norr uses QUIC rather than streams.
  //
  // Checking that `send_datagram` returns success proves nothing on its own:
  // the payload has to reach the peer, so it is carried across and compared.
  const std::vector<std::byte> payload(64, std::byte{0xAB});
  const auto sent = client.send_datagram(payload);
  NORR_CHECK(sent.has_value());
  NORR_CHECK(*sent == payload.size());

  bool delivered = false;
  for (int round = 0; round < 8 && !delivered; ++round) {
    while (true) {
      const auto out = client.next_outgoing();
      if (out.empty()) break;
      const std::vector<std::byte> copy(out.begin(), out.end());
      NORR_CHECK(server.feed(copy).has_value());
    }

    std::array<std::span<const std::byte>, 4> received{};
    const auto count = server.receive_datagrams(received);
    NORR_CHECK(count.has_value());
    if (*count == 0) continue;

    NORR_CHECK(*count == 1);
    NORR_CHECK(received[0].size() == payload.size());
    NORR_CHECK(std::equal(payload.begin(), payload.end(), received[0].begin()));
    delivered = true;
  }
  NORR_CHECK(delivered);

  // The server must refuse an oversized DATAGRAM rather than fragmenting it.
  const std::vector<std::byte> too_big(server.max_datagram_size() + 1);
  const auto refused = server.send_datagram(too_big);
  NORR_CHECK(!refused.has_value());
  NORR_CHECK(refused.error() == norr::QuicError::datagram_too_large);

  // A caller that never drains must be refused rather than allowed to grow the
  // outgoing queue without limit. Sending far more than any ceiling without
  // collecting must therefore start failing rather than consuming memory.
  const std::vector<std::byte> small(32, std::byte{0x11});
  bool eventually_refused = false;
  for (int index = 0; index < 4096; ++index) {
    if (!client.send_datagram(small)) {
      eventually_refused = true;
      break;
    }
  }
  NORR_CHECK(eventually_refused);

  std::puts("quic: full handshake, DATAGRAM round-trip and bounded queues OK");
}

// RFC 9221 conformance, checked against the specification rather than against
// our own behaviour.
//
// The rules that matter for a tunnel:
//   - max_datagram_frame_size is the transport parameter, type 0x20, and it
//     covers the whole frame: type, length and payload.
//   - An endpoint MUST NOT send a DATAGRAM frame larger than the value its
//     peer advertised.
//   - An endpoint MUST NOT send DATAGRAM frames at all until it has received
//     a non-zero value.
//   - Zero-length datagrams are allowed.
void test_rfc9221_conformance() {
  const auto client_peer = norr::parse_endpoint("127.0.0.1:4433");
  const auto server_local = norr::parse_endpoint("127.0.0.1:4433");
  const auto server_peer = norr::parse_endpoint("127.0.0.1:55556");
  NORR_CHECK(client_peer.has_value() && server_local.has_value() && server_peer.has_value());

  norr::Ngtcp2Connection client;
  NORR_CHECK(client.connect(*client_peer).has_value());

  // Before the handshake there is no advertised limit, so nothing may be sent.
  NORR_CHECK(client.max_datagram_size() == 0);
  const std::vector<std::byte> early(16);
  NORR_CHECK(!client.send_datagram(early).has_value());

  const auto initial = client.next_outgoing();
  NORR_CHECK(!initial.empty());
  const std::vector<std::byte> initial_copy(initial.begin(), initial.end());

  norr::Ngtcp2Connection server;
  NORR_CHECK(server.accept(*server_local, *server_peer, initial_copy).has_value());

  for (int round = 0; round < 32; ++round) {
    bool moved = false;
    while (true) {
      const auto out = server.next_outgoing();
      if (out.empty()) break;
      const std::vector<std::byte> copy(out.begin(), out.end());
      static_cast<void>(client.feed(copy));
      moved = true;
    }
    while (true) {
      const auto out = client.next_outgoing();
      if (out.empty()) break;
      const std::vector<std::byte> copy(out.begin(), out.end());
      static_cast<void>(server.feed(copy));
      moved = true;
    }
    if (client.established() && server.established()) break;
    if (!moved) break;
  }
  NORR_CHECK(client.established() && server.established());

  // After the handshake the limit must be a real, advertised number rather
  // than a guess about packet overhead.
  const auto limit = client.max_datagram_size();
  NORR_CHECK(limit > 0);
  NORR_CHECK(limit < norr::kMaxDatagramFrame);

  // What max_datagram_size reports must actually be sendable. Reporting the
  // RFC figure alone was wrong: max_datagram_frame_size bounds the frame, but
  // the frame still has to fit inside a 1-RTT packet, which costs a header,
  // connection ids, a packet number and an AEAD tag on top. A caller that
  // trusted the larger number had its packet refused.
  const std::vector<std::byte> at_limit(limit, std::byte{0x5A});
  NORR_CHECK(client.send_datagram(at_limit).has_value());

  // One byte over is refused: the peer advertised what it is willing to
  // receive, and exceeding it is a protocol violation.
  const std::vector<std::byte> over(limit + 1, std::byte{0x5A});
  const auto refused = client.send_datagram(over);
  NORR_CHECK(!refused.has_value());
  NORR_CHECK(refused.error() == norr::QuicError::datagram_too_large);

  // RFC 9221 allows zero-length datagrams, but ngtcp2 0.12 asserts on one
  // rather than encoding it, so this build cannot send one. Norr never does:
  // a keepalive is a sealed control frame with a header and a tag, so the
  // payload handed to the carrier is never empty. Left unexercised rather
  // than asserted, since the limitation is the library's and not ours.

  std::puts("quic: RFC 9221 size and readiness rules OK");
}

#endif  // NORR_HAVE_NGTCP2

void test_connect_lifecycle() {
  norr::LoopbackQuicConnection connection;
  NORR_CHECK(!connection.established());

  // Operations before connecting are refused rather than silently queued.
  const std::vector<std::byte> payload(64);
  NORR_CHECK(!connection.send_datagram(payload).has_value());

  NORR_CHECK(connection.connect(peer()).has_value());
  NORR_CHECK(connection.established());

  // Connecting twice is an error, not a silent reconnect.
  NORR_CHECK(!connection.connect(peer()).has_value());

  connection.close();
  NORR_CHECK(!connection.established());
  NORR_CHECK(!connection.send_datagram(payload).has_value());

  std::puts("quic: connection lifecycle OK");
}

void test_datagram_limit_is_enforced() {
  norr::LoopbackQuicConnection connection;
  NORR_CHECK(connection.connect(peer()).has_value());

  const std::vector<std::byte> fits(connection.max_datagram_size());
  NORR_CHECK(connection.send_datagram(fits).has_value());

  // QUIC does not fragment DATAGRAM frames. An oversized frame must be
  // refused so the caller falls back to another carrier, rather than being
  // split into something the peer cannot reassemble.
  const std::vector<std::byte> too_big(connection.max_datagram_size() + 1);
  const auto refused = connection.send_datagram(too_big);
  NORR_CHECK(!refused.has_value());
  NORR_CHECK(refused.error() == norr::QuicError::datagram_too_large);
  NORR_CHECK(connection.stats().datagrams_dropped == 1);

  std::puts("quic: datagram size limit enforced OK");
}

void test_datagram_delivery() {
  norr::LoopbackQuicConnection connection;
  NORR_CHECK(connection.connect(peer()).has_value());

  const std::vector<std::byte> first(100, std::byte{0xAA});
  const std::vector<std::byte> second(50, std::byte{0xBB});
  connection.deliver(first);
  connection.deliver(second);

  std::array<std::span<const std::byte>, 4> received{};
  const auto count = connection.receive_datagrams(received);
  NORR_CHECK(count.has_value() && *count == 2);
  NORR_CHECK(received[0].size() == 100);
  NORR_CHECK(received[1].size() == 50);
  NORR_CHECK(received[0][0] == std::byte{0xAA});
  NORR_CHECK(received[1][0] == std::byte{0xBB});

  // The inbox is drained, so a second call returns nothing.
  const auto again = connection.receive_datagrams(received);
  NORR_CHECK(again.has_value() && *again == 0);

  std::puts("quic: datagram delivery OK");
}

void test_partial_receive() {
  norr::LoopbackQuicConnection connection;
  NORR_CHECK(connection.connect(peer()).has_value());

  for (int index = 0; index < 5; ++index) {
    connection.deliver(std::vector<std::byte>(10, static_cast<std::byte>(index)));
  }

  // A caller with room for two must get two, and the rest must remain rather
  // than being dropped.
  std::array<std::span<const std::byte>, 2> received{};
  const auto first = connection.receive_datagrams(received);
  NORR_CHECK(first.has_value() && *first == 2);

  const auto second = connection.receive_datagrams(received);
  NORR_CHECK(second.has_value() && *second == 2);

  const auto third = connection.receive_datagrams(received);
  NORR_CHECK(third.has_value() && *third == 1);

  std::puts("quic: partial receive preserves the remainder OK");
}

}  // namespace

int main() {
  test_backend_reporting_is_honest();

#if defined(NORR_HAVE_NGTCP2)
  if (norr::crypto_available()) {
    NORR_CHECK(norr::crypto_init().has_value());
    test_real_connection_setup();
    test_garbage_is_not_accepted();
    test_full_handshake();
    test_rfc9221_conformance();
  }
#endif

  test_connect_lifecycle();
  test_datagram_limit_is_enforced();
  test_datagram_delivery();
  test_partial_receive();
  return 0;
}
