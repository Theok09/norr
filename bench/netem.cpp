// Gates E and F: latency under load, and lossy paths.
//
// These need impairment the kernel actually applies, not impairment simulated
// inside the harness. Dropping packets in user space would measure the
// harness; `tc netem` on a veth pair drops them in the network stack, which is
// what `bench/methodology.md` and `testing/fault-injection.md` call for.
//
// The two tunnel endpoints live in one process but their traffic crosses a
// veth pair carrying a netem qdisc, so every datagram passes through real
// queueing, real delay and real loss.
//
// Both endpoints must be in different network namespaces. With both addresses
// in one namespace the kernel routes locally through loopback and never
// touches the veth, so any qdisc on it is silently ignored: an earlier version
// of this benchmark reported 0% loss at every configured rate for exactly that
// reason, and the figures were meaningless.
//
// Because a process cannot hold sockets in two namespaces, this runs as two
// processes. `--role responder` binds and echoes; `--role initiator` measures.
// `scripts/netem_bench.sh` wires them together.

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <span>
#include <string>
#include <vector>

#include "norr/bench.hpp"
#include "norr/flow_hash.hpp"
#include "norr/noise.hpp"
#include "norr/worker.hpp"

namespace {

norr::Address address_of(const std::string& text) {
  const auto parsed = norr::parse_address(text.c_str());
  return parsed.has_value() ? *parsed : norr::Address{};
}

norr::Prefix prefix_of(const char* text) {
  const auto parsed = norr::parse_prefix(text);
  return parsed.has_value() ? *parsed : norr::Prefix{};
}

std::vector<std::byte> make_ipv4(const char* source, const char* destination,
                                 std::size_t payload_bytes) {
  std::vector<std::byte> packet(norr::kIpv4HeaderSize + payload_bytes);
  packet[0] = std::byte{0x45};
  const auto total = static_cast<std::uint16_t>(packet.size());
  packet[2] = static_cast<std::byte>(total >> 8U);
  packet[3] = static_cast<std::byte>(total & 0xFFU);
  packet[8] = std::byte{64};
  packet[9] = static_cast<std::byte>(norr::kProtocolUdp);

  const auto from = address_of(source);
  const auto to = address_of(destination);
  const auto from_bytes = from.bytes();
  const auto to_bytes = to.bytes();
  std::copy_n(from_bytes.begin(), 4, packet.begin() + 12);
  std::copy_n(to_bytes.begin(), 4, packet.begin() + 16);

  if (payload_bytes >= 4) {
    packet[20] = std::byte{0x30};
    packet[21] = std::byte{0x39};
    packet[22] = std::byte{0x00};
    packet[23] = std::byte{0x50};
  }
  return packet;
}

struct Node {
  norr::UdpTransport transport;
  norr::RoutingTable routes;
  norr::SessionTable sessions;
  norr::KeyPair identity;
  norr::Endpoint endpoint;
};

bool start_node(Node& node, const std::string& bind_ip, norr::PeerId self, const char* own_prefix,
                norr::PeerId peer, const char* peer_prefix) {
  const auto identity = norr::generate_keypair();
  if (!identity) return false;
  node.identity = *identity;
  if (!node.routes.add(self, prefix_of(own_prefix))) return false;
  if (!node.routes.add(peer, prefix_of(peer_prefix))) return false;

  const auto address = address_of(bind_ip);
  if (!node.transport.start(norr::Endpoint{address, 0})) return false;
  const auto port = node.transport.local_port();
  if (!port) return false;
  node.endpoint = norr::Endpoint{address, *port};
  return true;
}

bool establish(Node& alice, Node& bob) {
  norr::PresharedKey psk{};
  psk.fill(std::byte{0x5A});

  auto initiator = norr::NoiseHandshake::create(norr::HandshakeRole::initiator, alice.identity,
                                                bob.identity.public_key, psk);
  auto responder = norr::NoiseHandshake::create(norr::HandshakeRole::responder, bob.identity,
                                                norr::PublicKey{}, psk);
  if (!initiator || !responder) return false;

  const std::array<std::byte, 6> payload{};
  std::vector<std::byte> message_1(norr::kNoiseMessage1Overhead + payload.size());
  const auto written_1 = initiator->write_message_1(payload, message_1);
  if (!written_1) return false;
  std::vector<std::byte> out_1(payload.size());
  if (!responder->read_message_1(std::span{message_1}.first(*written_1), out_1)) return false;

  std::vector<std::byte> message_2(norr::kNoiseMessage2Overhead + payload.size());
  const auto written_2 = responder->write_message_2(payload, message_2);
  if (!written_2) return false;
  std::vector<std::byte> out_2(payload.size());
  if (!initiator->read_message_2(std::span{message_2}.first(*written_2), out_2)) return false;

  const auto a = initiator->result();
  const auto b = responder->result();
  if (!a || !b) return false;

  auto installed_a = alice.sessions.install(2, 0x00A1, 0x00B1, norr::TrafficKeys{a->send, 0},
                                            norr::TrafficKeys{a->receive, 0});
  auto installed_b = bob.sessions.install(1, 0x00B1, 0x00A1, norr::TrafficKeys{b->send, 0},
                                          norr::TrafficKeys{b->receive, 0});
  if (!installed_a || !installed_b) return false;

  (*installed_a)->note_authenticated_endpoint(bob.endpoint);
  (*installed_b)->note_authenticated_endpoint(alice.endpoint);
  return true;
}


// Sends Norr-sealed datagrams and counts what comes back.
//
// The responder echoes the raw datagram, so a round trip exercises the
// impaired path in both directions and needs no clock synchronisation between
// the two namespaces.
struct Measurement {
  std::uint64_t sent{};
  std::uint64_t returned{};
  norr::Samples rtt;
};

Measurement measure(Node& node, const norr::Endpoint& peer, norr::Session& session,
                    std::size_t payload_bytes, std::uint64_t packets,
                    std::chrono::milliseconds drain_for) {
  Measurement result;
  result.rtt.reserve(static_cast<std::size_t>(packets));

  const auto inner = make_ipv4("10.1.0.5", "10.2.0.7", payload_bytes);
  std::vector<std::byte> wire(norr::kPacketHeaderSize + inner.size() + norr::kAeadTagSize);

  norr::ReceiveBuffers pool{norr::UdpTransport::kDefaultBatchSize,
                            norr::UdpTransport::kDefaultDatagramSize};
  std::array<norr::InboundDatagram, norr::UdpTransport::kDefaultBatchSize> inbound{};

  std::vector<std::chrono::steady_clock::time_point> sent_at;
  sent_at.reserve(static_cast<std::size_t>(packets));

  const auto drain = [&] {
    const auto received = node.transport.receive_batch(pool, inbound);
    if (!received) return;
    for (std::size_t slot = 0; slot < *received; ++slot) {
      const auto now = std::chrono::steady_clock::now();
      if (result.returned < sent_at.size()) {
        result.rtt.add(static_cast<double>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(now - sent_at[result.returned])
                .count()));
      }
      ++result.returned;
    }
  };

  for (std::uint64_t index = 0; index < packets; ++index) {
    const auto sealed = session.seal(norr::FrameType::data, inner, wire);
    if (!sealed) break;

    const std::array<norr::OutboundDatagram, 1> datagram{
        norr::OutboundDatagram{.destination = peer,
                               .payload = std::span{wire}.first(*sealed)}};
    sent_at.push_back(std::chrono::steady_clock::now());
    const auto out = node.transport.send_batch(datagram);
    if (out && *out > 0) ++result.sent;
    drain();
  }

  // The drain window must outlast the path's own delay, or packets still in
  // flight are counted as lost. An earlier version used a fixed window and
  // reported 50-60% "loss" on a 20ms path that was in fact dropping nothing.
  //
  // Waiting is extended whenever something arrives, so a slow path is followed
  // to completion while a genuinely lossy one still terminates.
  auto deadline = std::chrono::steady_clock::now() + drain_for;
  while (std::chrono::steady_clock::now() < deadline && result.returned < result.sent) {
    const auto before = result.returned;
    drain();
    if (result.returned > before) {
      deadline = std::chrono::steady_clock::now() + drain_for;
    }
  }
  return result;
}

void report_measurement(const char* label, Measurement& measurement) {
  const auto loss = measurement.sent > 0
                        ? 100.0 * (1.0 - static_cast<double>(measurement.returned) /
                                             static_cast<double>(measurement.sent))
                        : 0.0;
  std::printf("%-34s %9llu %9llu %8.2f%% %10.0f %10.0f %10.0f\n", label,
              static_cast<unsigned long long>(measurement.sent),
              static_cast<unsigned long long>(measurement.returned), loss,
              measurement.rtt.percentile(0.50) / 1000.0, measurement.rtt.percentile(0.99) / 1000.0,
              measurement.rtt.max() / 1000.0);
}

// Echoes every datagram back. Deliberately dumb: the point is to make traffic
// traverse the impaired link twice, not to model a peer.
int run_responder(const std::string& bind_ip, std::uint16_t port) {
  norr::UdpTransport transport;
  const auto address = address_of(bind_ip);
  if (!transport.start(norr::Endpoint{address, port})) {
    std::fprintf(stderr, "responder: bind failed\n");
    return 1;
  }
  std::printf("responder ready on %s:%u\n", bind_ip.c_str(), port);
  std::fflush(stdout);

  norr::ReceiveBuffers pool{norr::UdpTransport::kDefaultBatchSize,
                            norr::UdpTransport::kDefaultDatagramSize};
  std::array<norr::InboundDatagram, norr::UdpTransport::kDefaultBatchSize> inbound{};

  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{120};
  while (std::chrono::steady_clock::now() < deadline) {
    const auto received = transport.receive_batch(pool, inbound);
    if (!received || *received == 0) continue;
    for (std::size_t slot = 0; slot < *received; ++slot) {
      const std::array<norr::OutboundDatagram, 1> echo{
          norr::OutboundDatagram{.destination = inbound[slot].source,
                                 .payload = inbound[slot].payload}};
      static_cast<void>(transport.send_batch(echo));
    }
  }
  return 0;
}

}  // namespace

int main(int argc, char* argv[]) {
  if (!norr::UdpTransport::supported() || !norr::crypto_available() || !norr::crypto_init()) {
    std::fprintf(stderr, "norr_bench_netem: requires Linux and libsodium\n");
    return 1;
  }
  if (argc < 4) {
    std::fprintf(stderr,
                 "usage:\n"
                 "  norr_bench_netem responder <bind-ip> <port>\n"
                 "  norr_bench_netem initiator <bind-ip> <peer-ip> <peer-port> [label]\n");
    return 2;
  }

  const std::string role = argv[1];
  if (role == "responder") {
    return run_responder(argv[2], static_cast<std::uint16_t>(std::atoi(argv[3])));
  }
  if (role != "initiator" || argc < 5) {
    std::fprintf(stderr, "norr_bench_netem: bad arguments\n");
    return 2;
  }

  const std::string local_ip = argv[2];
  const std::string peer_ip = argv[3];
  const auto peer_port = static_cast<std::uint16_t>(std::atoi(argv[4]));

  Node alice;
  Node bob;
  if (!start_node(alice, local_ip, 1, "10.1.0.0/16", 2, "10.2.0.0/16") ||
      !start_node(bob, local_ip, 2, "10.2.0.0/16", 1, "10.1.0.0/16")) {
    std::fprintf(stderr, "norr_bench_netem: node setup failed\n");
    return 1;
  }
  // Keys are established locally: the remote end is an echo, so this measures
  // the path, not a second Norr instance. Sealing and the counter still run.
  if (!establish(alice, bob)) {
    std::fprintf(stderr, "norr_bench_netem: handshake failed\n");
    return 1;
  }
  auto* session = alice.sessions.find_by_peer(2);
  if (session == nullptr) return 1;

  const norr::Endpoint peer{address_of(peer_ip), peer_port};

  auto environment = norr::BenchEnvironment::detect();
  environment.notes = argc > 5 ? argv[5] : "veth pair with netem";

  std::printf("\n=== Norr impaired-path benchmark (gates E and F) ===\n");
  std::printf("kernel   : %s\n", environment.kernel.c_str());
  std::printf("build    : %s\n", environment.build_type.c_str());
  std::printf("path     : %s -> %s:%u (round trip)\n", local_ip.c_str(), peer_ip.c_str(),
              peer_port);
  std::printf("notes    : %s\n", environment.notes.c_str());
  std::printf("\nImpairment is applied by tc netem between two network namespaces,\n");
  std::printf("so delay and loss happen in the kernel, not in this process.\n");

  std::printf("\n%-34s %9s %9s %9s %10s %10s %10s\n", "scenario", "sent", "returned", "loss",
              "p50 (us)", "p99 (us)", "max (us)");
  std::printf("%-34s %9s %9s %9s %10s %10s %10s\n", "----------------------------------",
              "---------", "---------", "---------", "----------", "----------", "----------");

  // Gate E: a small latency-sensitive flow, idle and then behind bulk. This is
  // the scenario testing/gaming-load.md calls a first-class acceptance test.
  {
    auto idle = measure(alice, peer, *session, 60, 2'000, std::chrono::milliseconds{500});
    report_measurement("gate E: realtime, idle", idle);
  }
  for (const std::uint64_t bulk : {std::uint64_t{2'000}, std::uint64_t{10'000}}) {
    auto load = measure(alice, peer, *session, 1380, bulk, std::chrono::milliseconds{200});
    static_cast<void>(load);
    auto realtime = measure(alice, peer, *session, 60, 1'000, std::chrono::milliseconds{500});
    const auto label = "gate E: realtime after " + std::to_string(bulk) + " bulk";
    report_measurement(label.c_str(), realtime);
  }

  // Gate F: whatever the caller configured on the qdisc. The harness does not
  // know the rate; it reports what came back.
  {
    auto lossy = measure(alice, peer, *session, 1180, 5'000, std::chrono::milliseconds{750});
    report_measurement("gate F: 1200B, impaired path", lossy);
  }

  std::printf(
      "\n=== gate G: not measured ===\n"
      "Transport failover needs a second transport to fail over to. QUIC and\n"
      "TLS/TCP are phases 5 and 6, so there is nothing to switch to yet.\n");
  return 0;
}
