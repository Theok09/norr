// Gate G: transport failover between two real carriers.
//
// Until now the selector had nothing to select. With TLS over TCP working,
// this exercises the whole path: both carriers carry real Norr frames, the
// primary is broken, and the session continues on the secondary without
// changing peer identity or key state.

#include "check.hpp"
#include <chrono>
#include <cstdio>
#include <vector>

#include "norr/noise.hpp"
#include "norr/path_selector.hpp"
#include "norr/session.hpp"
#include "norr/tcp_transport.hpp"
#include "norr/tls.hpp"
#include "norr/udp_transport.hpp"

namespace {

norr::Address loopback() {
  const auto parsed = norr::parse_address("127.0.0.1");
  NORR_CHECK(parsed.has_value());
  return *parsed;
}

// One established Norr session, shared by both carriers. This is the property
// under test: `sessions/transport-migration.md` says a session is
// transport-independent and a transport is only a carrier.
struct Established {
  norr::TrafficKey send;
  norr::TrafficKey receive;
};

Established establish() {
  const auto initiator = norr::generate_keypair();
  const auto responder = norr::generate_keypair();
  NORR_CHECK(initiator.has_value() && responder.has_value());

  norr::PresharedKey psk{};
  psk.fill(std::byte{0x42});

  auto client = norr::NoiseHandshake::create(norr::HandshakeRole::initiator, *initiator,
                                             responder->public_key, psk);
  auto server = norr::NoiseHandshake::create(norr::HandshakeRole::responder, *responder,
                                             norr::PublicKey{}, psk);
  NORR_CHECK(client.has_value() && server.has_value());

  const std::array<std::byte, 6> payload{};
  std::vector<std::byte> message_1(norr::kNoiseMessage1Overhead + payload.size());
  const auto written_1 = client->write_message_1(payload, message_1);
  NORR_CHECK(written_1.has_value());

  std::vector<std::byte> out_1(payload.size());
  NORR_CHECK(server->read_message_1(std::span{message_1}.first(*written_1), out_1).has_value());

  std::vector<std::byte> message_2(norr::kNoiseMessage2Overhead + payload.size());
  const auto written_2 = server->write_message_2(payload, message_2);
  NORR_CHECK(written_2.has_value());

  std::vector<std::byte> out_2(payload.size());
  NORR_CHECK(client->read_message_2(std::span{message_2}.first(*written_2), out_2).has_value());

  const auto result = client->result();
  NORR_CHECK(result.has_value());
  return Established{.send = result->send, .receive = result->receive};
}

#if defined(__linux__) && defined(NORR_HAVE_GNUTLS)

void test_failover_between_carriers() {
  const auto keys = establish();

  // The session and its counters belong to Norr, not to either carrier.
  norr::Session session{2, 0x0001, 0x0002, norr::TrafficKeys{keys.send, 0},
                        norr::TrafficKeys{keys.receive, 0}};

  // Carrier one: UDP.
  norr::UdpTransport udp;
  NORR_CHECK(udp.start(norr::Endpoint{loopback(), 0}).has_value());
  const auto udp_port = udp.local_port();
  NORR_CHECK(udp_port.has_value());

  norr::UdpTransport udp_peer;
  NORR_CHECK(udp_peer.start(norr::Endpoint{loopback(), 0}).has_value());
  const auto udp_peer_port = udp_peer.local_port();
  NORR_CHECK(udp_peer_port.has_value());

  // Carrier two: TLS over TCP.
  norr::TcpListener listener;
  NORR_CHECK(listener.listen(norr::Endpoint{loopback(), 0}).has_value());
  const auto tcp_port = listener.local_port();
  NORR_CHECK(tcp_port.has_value());

  norr::TcpTransport tcp_client;
  NORR_CHECK(tcp_client.connect(norr::Endpoint{loopback(), *tcp_port}).has_value());
  for (int attempt = 0; attempt < 1000 && !tcp_client.connected(); ++attempt) {
    static_cast<void>(tcp_client.poll_connect());
  }
  NORR_CHECK(tcp_client.connected());

  std::optional<norr::TcpTransport> tcp_server;
  for (int attempt = 0; attempt < 1000 && !tcp_server.has_value(); ++attempt) {
    auto accepted = listener.accept();
    NORR_CHECK(accepted.has_value());
    if (accepted->has_value()) tcp_server = std::move(**accepted);
  }
  NORR_CHECK(tcp_server.has_value());

  const std::vector<std::byte> psk(32, std::byte{0x5A});
  norr::TlsSession tls_client;
  norr::TlsSession tls_server;
  NORR_CHECK(tls_client.start(tcp_client.descriptor(), norr::TlsRole::client, "norr", psk)
                 .has_value());
  NORR_CHECK(tls_server.start(tcp_server->descriptor(), norr::TlsRole::server, "norr", psk)
                 .has_value());

  bool tls_up = false;
  for (int attempt = 0; attempt < 5000 && !tls_up; ++attempt) {
    const auto client_done = tls_client.handshake();
    const auto server_done = tls_server.handshake();
    NORR_CHECK(client_done.has_value() && server_done.has_value());
    tls_up = *client_done && *server_done;
  }
  NORR_CHECK(tls_up);

  // Both carriers are live. The selector starts on UDP.
  norr::PathSelector selector;
  selector.add_path(norr::TransportKind::udp);
  selector.add_path(norr::TransportKind::tcp_tls);
  auto now = std::chrono::steady_clock::now();

  const norr::PathSample healthy{.rtt_microseconds = 20'000, .loss_fraction = 0.0};
  for (int index = 0; index < 10; ++index) {
    selector.observe(norr::TransportKind::udp, healthy);
    selector.observe(norr::TransportKind::tcp_tls, healthy);
  }
  NORR_CHECK(selector.active() == norr::TransportKind::udp);

  // Send a frame on the active carrier.
  const std::vector<std::byte> inner(200, std::byte{0xAB});
  std::vector<std::byte> wire(norr::kPacketHeaderSize + inner.size() + norr::kAeadTagSize);
  const auto sealed_udp = session.seal(norr::FrameType::data, inner, wire);
  NORR_CHECK(sealed_udp.has_value());

  const std::array<norr::OutboundDatagram, 1> datagram{
      norr::OutboundDatagram{.destination = norr::Endpoint{loopback(), *udp_peer_port},
                             .payload = std::span{wire}.first(*sealed_udp)}};
  NORR_CHECK(udp.send_batch(datagram).has_value());

  norr::ReceiveBuffers pool{norr::UdpTransport::kDefaultBatchSize,
                            norr::UdpTransport::kDefaultDatagramSize};
  std::array<norr::InboundDatagram, norr::UdpTransport::kDefaultBatchSize> inbound{};
  std::size_t received = 0;
  for (int attempt = 0; attempt < 1000 && received == 0; ++attempt) {
    const auto result = udp_peer.receive_batch(pool, inbound);
    NORR_CHECK(result.has_value());
    received = *result;
  }
  NORR_CHECK(received == 1);

  const auto counter_before = session.generation();

  // UDP dies. The selector sees it and moves to TLS.
  const norr::PathSample dead{.rtt_microseconds = 0, .loss_fraction = 1.0, .reachable = false};
  for (int index = 0; index < 5; ++index) {
    selector.observe(norr::TransportKind::udp, dead);
    selector.observe(norr::TransportKind::tcp_tls, healthy);
  }
  now += std::chrono::minutes{1};
  NORR_CHECK(selector.evaluate(now));
  NORR_CHECK(selector.active() == norr::TransportKind::tcp_tls);
  NORR_CHECK(selector.stats().failovers == 1);

  // The same session continues on the new carrier: identity, keys and the
  // counter domain are unchanged, which is what makes this a migration rather
  // than a reconnection.
  NORR_CHECK(session.generation() == counter_before);
  NORR_CHECK(session.peer() == 2);

  std::vector<std::byte> wire_tls(norr::kPacketHeaderSize + inner.size() + norr::kAeadTagSize);
  const auto sealed_tls = session.seal(norr::FrameType::data, inner, wire_tls);
  NORR_CHECK(sealed_tls.has_value());

  // The counter advanced across the switch rather than restarting, so a
  // replayed pre-failover packet cannot be accepted afterwards.
  const auto first = norr::parse_packet(std::span{wire}.first(*sealed_udp));
  const auto second = norr::parse_packet(std::span{wire_tls}.first(*sealed_tls));
  NORR_CHECK(first.has_value() && second.has_value());
  NORR_CHECK(second->header.counter > first->header.counter);

  // Only TLS writes to this descriptor. A raw framed write alongside it would
  // inject plaintext into the TLS record stream and desynchronise the peer.
  std::size_t sent = 0;
  for (int attempt = 0; attempt < 1000 && sent == 0; ++attempt) {
    const auto result = tls_client.send(std::span{wire_tls}.first(*sealed_tls));
    NORR_CHECK(result.has_value());
    sent = *result;
  }
  NORR_CHECK(sent > 0);

  std::vector<std::byte> tls_received(wire_tls.size());
  std::size_t got = 0;
  for (int attempt = 0; attempt < 1000 && got == 0; ++attempt) {
    const auto result = tls_server.receive(tls_received);
    NORR_CHECK(result.has_value());
    got = *result;
  }
  NORR_CHECK(got == sent);

  std::printf("failover: gate G, %s carried the session after UDP failed\n",
              std::string{norr::transport_kind_name(selector.active())}.c_str());
}

void test_no_failover_while_primary_is_healthy() {
  norr::PathSelector selector;
  selector.add_path(norr::TransportKind::udp);
  selector.add_path(norr::TransportKind::tcp_tls);
  auto now = std::chrono::steady_clock::now();

  const norr::PathSample healthy{.rtt_microseconds = 20'000, .loss_fraction = 0.0};
  const norr::PathSample better{.rtt_microseconds = 1'000, .loss_fraction = 0.0};
  for (int index = 0; index < 10; ++index) {
    selector.observe(norr::TransportKind::udp, healthy);
    selector.observe(norr::TransportKind::tcp_tls, better);
  }
  now += std::chrono::minutes{1};

  // TLS over TCP scores better here, and must still not win: TCP is a
  // compatibility carrier with head-of-line blocking, and switching to it
  // while UDP works would trade a real property for a better metric.
  NORR_CHECK(!selector.evaluate(now));
  NORR_CHECK(selector.active() == norr::TransportKind::udp);

  std::puts("failover: a healthy primary is not abandoned OK");
}

#endif  // __linux__ && NORR_HAVE_GNUTLS

}  // namespace

int main() {
#if defined(__linux__) && defined(NORR_HAVE_GNUTLS)
  if (!norr::crypto_available() || !norr::crypto_init() || !norr::tls_available()) {
    std::puts("failover: backends unavailable, skipped");
    return 0;
  }
  test_failover_between_carriers();
  test_no_failover_while_primary_is_healthy();
#else
  std::puts("failover: needs Linux and a TLS backend, skipped");
#endif
  return 0;
}
