// End-to-end tunnel benchmark: two Norr nodes over real sockets.
//
// `performance/acceptance-gates.md` defines gates B through G, none of which
// per-component timing can reach: they need packets to actually traverse a
// tunnel. This harness builds two complete nodes in one process, runs a real
// handshake between them, and pushes traffic through the full datapath.
//
// What it still is not: two hosts, real NICs, and netem. Loopback has no
// serialisation delay and no loss, so the figures here bound what the software
// costs and say nothing about what a network will do. Gate F (lossy paths)
// is therefore simulated by dropping packets in the harness rather than in the
// network, and is labelled as such.

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "norr/bench.hpp"
#include "norr/control_plane.hpp"
#include "norr/flow_hash.hpp"
#include "norr/noise.hpp"
#include "norr/worker.hpp"

namespace {

norr::Address address_of(const char* text) {
  const auto parsed = norr::parse_address(text);
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

  // Vary the transport ports so flows are distinguishable.
  if (payload_bytes >= 4) {
    packet[20] = std::byte{0x30};
    packet[21] = std::byte{0x39};
    packet[22] = std::byte{0x00};
    packet[23] = std::byte{0x50};
  }
  return packet;
}

// One end of the tunnel.
struct Node {
  norr::UdpTransport transport;
  norr::RoutingTable routes;
  norr::SessionTable sessions;
  norr::KeyPair identity;
  std::uint16_t port{};
};

// Establishes a real session pair by running the Noise handshake, so the
// benchmark measures the keys the protocol actually produces.
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

  const auto loopback = address_of("127.0.0.1");

  auto* alice_session = [&]() -> norr::Session* {
    auto installed = alice.sessions.install(2, 0x00A1, 0x00B1, norr::TrafficKeys{a->send, 0},
                                            norr::TrafficKeys{a->receive, 0});
    return installed ? *installed : nullptr;
  }();
  auto* bob_session = [&]() -> norr::Session* {
    auto installed = bob.sessions.install(1, 0x00B1, 0x00A1, norr::TrafficKeys{b->send, 0},
                                          norr::TrafficKeys{b->receive, 0});
    return installed ? *installed : nullptr;
  }();
  if (alice_session == nullptr || bob_session == nullptr) return false;

  alice_session->note_authenticated_endpoint(norr::Endpoint{loopback, bob.port});
  bob_session->note_authenticated_endpoint(norr::Endpoint{loopback, alice.port});
  return true;
}

bool start_node(Node& node, norr::PeerId self, const char* own_prefix, norr::PeerId peer,
                const char* peer_prefix) {
  const auto identity = norr::generate_keypair();
  if (!identity) return false;
  node.identity = *identity;

  if (!node.routes.add(self, prefix_of(own_prefix))) return false;
  if (!node.routes.add(peer, prefix_of(peer_prefix))) return false;

  const auto loopback = address_of("127.0.0.1");
  if (!node.transport.start(norr::Endpoint{loopback, 0})) return false;
  const auto port = node.transport.local_port();
  if (!port) return false;
  node.port = *port;
  return true;
}

// Gate B and C: throughput through the full datapath, at one flow and at many.
// The receiving side is drained and verified, so this measures delivery rather
// than how fast packets can be thrown at a socket.
struct ThroughputResult {
  std::uint64_t sent{};
  std::uint64_t delivered{};
  std::chrono::nanoseconds elapsed{};
  std::size_t packet_bytes{};
  norr::Samples latency;
};

ThroughputResult run_throughput(Node& alice, Node& bob, norr::Worker& sender,
                                norr::Worker& receiver, std::size_t payload_bytes,
                                std::size_t flows, std::uint64_t packets) {
  ThroughputResult result;
  result.packet_bytes = norr::kIpv4HeaderSize + payload_bytes;
  result.latency.reserve(static_cast<std::size_t>(packets));

  // Pre-build one packet per flow so generation cost stays out of the loop.
  std::vector<std::vector<std::byte>> templates;
  templates.reserve(flows);
  for (std::size_t flow = 0; flow < flows; ++flow) {
    // Host octets run 1..254: 0 is the network address and 255 the broadcast,
    // and 256 does not exist at all. An earlier version used flow%256+1 and
    // silently generated "10.1.x.256", which the parser rejected and which
    // showed up as a small unexplained packet loss.
    const auto third = static_cast<unsigned>((flow / 254) % 254);
    const auto fourth = static_cast<unsigned>(flow % 254) + 1;
    const auto source = "10.1." + std::to_string(third) + "." + std::to_string(fourth);
    templates.push_back(make_ipv4(source.c_str(), "10.2.0.7", payload_bytes));
  }

  norr::ReceiveBuffers pool{norr::UdpTransport::kDefaultBatchSize,
                            norr::UdpTransport::kDefaultDatagramSize};
  std::array<norr::InboundDatagram, norr::UdpTransport::kDefaultBatchSize> inbound{};

  const auto start = std::chrono::steady_clock::now();

  for (std::uint64_t index = 0; index < packets; ++index) {
    const auto& packet = templates[index % templates.size()];

    const auto sent_at = std::chrono::steady_clock::now();
    if (sender.forward_from_tun(packet) == norr::DropReason::none) ++result.sent;

    // Drain whatever has arrived. The socket is non-blocking, so this is a
    // poll rather than a wait.
    const auto received = bob.transport.receive_batch(pool, inbound);
    if (received) {
      for (std::size_t slot = 0; slot < *received; ++slot) {
        const auto reason =
            receiver.forward_from_transport(inbound[slot].source, inbound[slot].payload);
        // Without a TUN device the final write fails; everything up to it,
        // which is all the protocol work, still ran.
        if (reason == norr::DropReason::none || reason == norr::DropReason::tun_write_failed) {
          ++result.delivered;
          const auto arrived = std::chrono::steady_clock::now();
          result.latency.add(
              static_cast<double>(
                  std::chrono::duration_cast<std::chrono::nanoseconds>(arrived - sent_at).count()));
        }
      }
    }
  }

  // Drain the tail.
  for (int attempt = 0; attempt < 1000; ++attempt) {
    const auto received = bob.transport.receive_batch(pool, inbound);
    if (!received || *received == 0) break;
    for (std::size_t slot = 0; slot < *received; ++slot) {
      const auto reason =
          receiver.forward_from_transport(inbound[slot].source, inbound[slot].payload);
      if (reason == norr::DropReason::none || reason == norr::DropReason::tun_write_failed) {
        ++result.delivered;
      }
    }
  }

  result.elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
      std::chrono::steady_clock::now() - start);
  return result;
}

void print_throughput(const char* label, const ThroughputResult& result) {
  const auto seconds = static_cast<double>(result.elapsed.count()) / 1e9;
  const auto pps = seconds > 0.0 ? static_cast<double>(result.delivered) / seconds : 0.0;
  const auto gbps = pps * static_cast<double>(result.packet_bytes) * 8.0 / 1e9;
  const auto loss =
      result.sent > 0
          ? 100.0 * (1.0 - static_cast<double>(result.delivered) / static_cast<double>(result.sent))
          : 0.0;

  std::printf("%-30s %10llu %10llu %9.2f%% %12.0f %10.3f\n", label,
              static_cast<unsigned long long>(result.sent),
              static_cast<unsigned long long>(result.delivered), loss, pps, gbps);
}

}  // namespace

int main(int argc, char* argv[]) {
  if (!norr::UdpTransport::supported()) {
    std::fprintf(stderr, "norr_bench_e2e: requires Linux sockets\n");
    return 1;
  }
  if (!norr::crypto_available() || !norr::crypto_init()) {
    std::fprintf(stderr, "norr_bench_e2e: requires libsodium\n");
    return 1;
  }

  Node alice;
  Node bob;
  if (!start_node(alice, 1, "10.1.0.0/16", 2, "10.2.0.0/16") ||
      !start_node(bob, 2, "10.2.0.0/16", 1, "10.1.0.0/16")) {
    std::fprintf(stderr, "norr_bench_e2e: node setup failed\n");
    return 1;
  }
  if (!establish(alice, bob)) {
    std::fprintf(stderr, "norr_bench_e2e: handshake failed\n");
    return 1;
  }

  norr::TunDevice alice_tun;
  norr::TunDevice bob_tun;
  norr::UdpCarrier alice_carrier{alice.transport};
  norr::UdpCarrier bob_carrier{bob.transport};
  norr::Worker sender{alice_tun, alice_carrier, alice.routes, alice.sessions};
  norr::Worker receiver{bob_tun, bob_carrier, bob.routes, bob.sessions};

  auto environment = norr::BenchEnvironment::detect();
  environment.notes = argc > 1 ? argv[1] : "loopback, single process";

  std::printf("\n=== Norr end-to-end tunnel benchmark ===\n");
  std::printf("hardware : %s\n", environment.hardware.c_str());
  std::printf("kernel   : %s\n", environment.kernel.c_str());
  std::printf("compiler : %s\n", environment.compiler.c_str());
  std::printf("build    : %s\n", environment.build_type.c_str());
  std::printf("offloads : %s\n", std::string{alice.transport.offloads().summary()}.c_str());
  std::printf("notes    : %s\n", environment.notes.c_str());

  std::printf("\n%-30s %10s %10s %10s %12s %10s\n", "scenario", "sent", "delivered", "loss",
              "packets/s", "Gb/s");
  std::printf("%-30s %10s %10s %10s %12s %10s\n", "------------------------------", "----------",
              "----------", "----------", "------------", "----------");

  // Gate B: single flow, across the packet-size matrix from
  // research/performance-research.md.
  norr::Samples single_flow_latency;
  for (const std::size_t payload : {std::size_t{44}, std::size_t{236}, std::size_t{1180},
                                    std::size_t{1380}}) {
    auto result = run_throughput(alice, bob, sender, receiver, payload, 1, 20'000);
    const auto label = "gate B: 1 flow, " + std::to_string(payload + norr::kIpv4HeaderSize) + "B";
    print_throughput(label.c_str(), result);
    if (payload == 1180) single_flow_latency = std::move(result.latency);
  }

  // Gate C: multi-flow aggregate. The flow count is what exercises the routing
  // table and, later, worker sharding.
  for (const std::size_t flows : {std::size_t{10}, std::size_t{100}, std::size_t{1000}}) {
    auto result = run_throughput(alice, bob, sender, receiver, 1180, flows, 20'000);
    const auto label = "gate C: " + std::to_string(flows) + " flows, 1200B";
    print_throughput(label.c_str(), result);
  }

  // Gate D: CPU efficiency is reported as cost per packet, since a portable
  // cycle counter is not available here. Deliberately not called cycles/byte.
  std::printf("\n=== gate D: cost per packet ===\n");
  norr::print_latency_report("1 flow, 1200B, end to end", single_flow_latency);

  std::printf(
      "\n=== gates E, F, G: not measured ===\n"
      "Gate E needs bulk traffic at controlled fractions of line rate, which\n"
      "loopback has no concept of. Gate F needs netem-induced loss on a real\n"
      "path; dropping packets inside this process would measure the harness,\n"
      "not the tunnel. Gate G needs failover timed across a real path; the\n"
      "QUIC and TCP carriers exist and are covered by norr_failover_tests,\n"
      "but the timing figure belongs on netem rather than loopback.\n");

  std::printf(
      "\nScope: one process over loopback. No serialisation delay, no real\n"
      "loss, no NIC. These figures bound software cost only, and are not a\n"
      "throughput claim: see bench/methodology.md and\n"
      "research/performance-research.md.\n");
  return 0;
}
