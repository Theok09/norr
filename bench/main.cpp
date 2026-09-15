// Norr benchmark harness.
//
// This exists because `performance/acceptance-gates.md` makes a repeatable
// benchmark report the exit criterion for Phase 3, and because
// `docs/design-principles.md` requires every optimisation be benchmarked. No
// per-core worker, GSO or multiqueue work should be attempted before there is
// a baseline to compare against.
//
// What this measures: per-component cost on one machine. What it does not
// measure: end-to-end tunnel throughput against WireGuard on real hardware,
// which is what `bench/methodology.md` describes and which needs two hosts, a
// NIC and netem. That remains to be built.

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <span>
#include <string>
#include <vector>

#include "norr/bench.hpp"
#include "norr/cookie.hpp"
#include "norr/crypto.hpp"
#include "norr/flow_hash.hpp"
#include "norr/noise.hpp"
#include "norr/replay_window.hpp"
#include "norr/routing.hpp"
#include "norr/session.hpp"

namespace {

norr::Address address_of(const char* text) {
  const auto parsed = norr::parse_address(text);
  return parsed.has_value() ? *parsed : norr::Address{};
}

norr::Prefix prefix_of(const char* text) {
  const auto parsed = norr::parse_prefix(text);
  return parsed.has_value() ? *parsed : norr::Prefix{};
}

std::vector<std::byte> make_ipv4(std::size_t payload) {
  std::vector<std::byte> packet(norr::kIpv4HeaderSize + payload);
  packet[0] = std::byte{0x45};
  const auto total = static_cast<std::uint16_t>(packet.size());
  packet[2] = static_cast<std::byte>(total >> 8U);
  packet[3] = static_cast<std::byte>(total & 0xFFU);
  packet[8] = std::byte{64};
  packet[9] = static_cast<std::byte>(norr::kProtocolUdp);

  const auto source = address_of("10.1.0.5");
  const auto destination = address_of("10.2.0.7");
  const auto source_bytes = source.bytes();
  const auto destination_bytes = destination.bytes();
  std::copy_n(source_bytes.begin(), 4, packet.begin() + 12);
  std::copy_n(destination_bytes.begin(), 4, packet.begin() + 16);
  return packet;
}

// The packet sizes from `research/performance-research.md`. Measuring one size
// only would hide the difference between per-packet and per-byte cost, which
// that document explicitly warns against.
constexpr std::array<std::size_t, 5> kPacketSizes{64, 256, 512, 1200, 1400};

void bench_aead(std::vector<norr::BenchResult>& results) {
  const std::vector<std::byte> secret(32, std::byte{0x2A});
  const auto key = norr::derive_traffic_key(secret, norr::kDataLabel,
                                            norr::KeyDirection::initiator_to_responder, 0);
  if (!key) return;
  const norr::TrafficKeys keys{*key, 0};

  const std::array<std::byte, norr::kPacketHeaderSize> aad{};

  for (const auto size : kPacketSizes) {
    const std::vector<std::byte> plaintext(size, std::byte{0x5A});
    std::vector<std::byte> ciphertext(size + norr::kAeadTagSize);
    std::uint64_t counter = 0;

    results.push_back(norr::run_benchmark(
        "aead seal " + std::to_string(size) + "B", 200'000, size,
        [&] { static_cast<void>(keys.seal(counter++, aad, plaintext, ciphertext)); }));

    // Seal once more so there is something valid to open repeatedly.
    static_cast<void>(keys.seal(0, aad, plaintext, ciphertext));
    std::vector<std::byte> recovered(size);
    results.push_back(norr::run_benchmark(
        "aead open " + std::to_string(size) + "B", 200'000, size,
        [&] { static_cast<void>(keys.open(0, aad, ciphertext, recovered)); }));
  }
}

void bench_session(std::vector<norr::BenchResult>& results) {
  const std::vector<std::byte> secret(32, std::byte{0x11});
  const auto send = norr::derive_traffic_key(secret, norr::kDataLabel,
                                             norr::KeyDirection::initiator_to_responder, 0);
  const auto receive = norr::derive_traffic_key(secret, norr::kDataLabel,
                                                norr::KeyDirection::responder_to_initiator, 0);
  if (!send || !receive) return;

  norr::Session sender{1, 1, 2, norr::TrafficKeys{*send, 0}, norr::TrafficKeys{*receive, 0}};

  for (const auto size : kPacketSizes) {
    const std::vector<std::byte> payload(size, std::byte{0x33});
    std::vector<std::byte> wire(norr::kPacketHeaderSize + size + norr::kAeadTagSize);

    // The full send path: counter, header serialisation and AEAD.
    results.push_back(norr::run_benchmark(
        "session seal " + std::to_string(size) + "B", 200'000, size,
        [&] { static_cast<void>(sender.seal(norr::FrameType::data, payload, wire)); }));
  }
}

void bench_replay_window(std::vector<norr::BenchResult>& results) {
  norr::ReplayWindow window;
  std::uint64_t counter = 0;

  results.push_back(norr::run_benchmark("replay accept in-order", 2'000'000, 0,
                                        [&] { static_cast<void>(window.accept(counter++)); }));

  // Reordered delivery exercises the bitmap rather than the fast path.
  norr::ReplayWindow reordered;
  static_cast<void>(reordered.accept(100'000));
  std::uint64_t offset = 0;
  results.push_back(norr::run_benchmark("replay accept reordered", 1'000'000, 0, [&] {
    static_cast<void>(reordered.accept(100'000 - (offset++ % 4096)));
  }));
}

void bench_routing(std::vector<norr::BenchResult>& results) {
  norr::RoutingTable table;
  // A realistic table rather than a single entry: lookup cost depends on how
  // many prefixes must be examined.
  for (std::uint32_t index = 0; index < 256; ++index) {
    std::array<std::byte, 4> octets{std::byte{10}, static_cast<std::byte>(index >> 8U),
                                    static_cast<std::byte>(index & 0xFFU), std::byte{0}};
    const auto prefix =
        norr::Prefix::create(norr::Address::from_bytes(norr::AddressFamily::ipv4, octets), 24);
    if (prefix) static_cast<void>(table.add(index + 1, *prefix));
  }
  static_cast<void>(table.add(1000, prefix_of("10.2.0.0/16")));

  const auto destination = address_of("10.2.0.7");
  results.push_back(norr::run_benchmark(
      "routing lookup (257 prefixes)", 1'000'000, 0,
      [&] { static_cast<void>(table.lookup(destination)); }));

  const auto packet = make_ipv4(64);
  const auto parsed = norr::parse_ip_packet(packet);
  if (parsed) {
    results.push_back(norr::run_benchmark(
        "routing classify", 1'000'000, 0,
        [&] { static_cast<void>(table.classify(*parsed, norr::kNoPeer)); }));
  }
}

void bench_parsing(std::vector<norr::BenchResult>& results) {
  const auto packet = make_ipv4(1200);
  results.push_back(norr::run_benchmark("parse_ip_packet 1220B", 2'000'000, packet.size(), [&] {
    static_cast<void>(norr::parse_ip_packet(packet));
  }));

  const auto parsed = norr::parse_ip_packet(packet);
  if (parsed) {
    results.push_back(norr::run_benchmark("flow_key + hash", 2'000'000, 0, [&] {
      const auto key = norr::flow_key_of(*parsed, packet);
      static_cast<void>(norr::hash_flow(key));
    }));
  }
}

void bench_handshake(std::vector<norr::BenchResult>& results) {
  const auto initiator_static = norr::generate_keypair();
  const auto responder_static = norr::generate_keypair();
  if (!initiator_static || !responder_static) return;

  norr::PresharedKey psk{};
  psk.fill(std::byte{0x7F});

  const std::array<std::byte, 6> payload{};

  // A full handshake is two Noise messages and four Diffie-Hellman operations.
  // This is the cost an attacker tries to impose, which is why cookies exist.
  results.push_back(norr::run_benchmark("noise handshake (full)", 2'000, 0, [&] {
    auto initiator = norr::NoiseHandshake::create(norr::HandshakeRole::initiator,
                                                  *initiator_static,
                                                  responder_static->public_key, psk);
    auto responder = norr::NoiseHandshake::create(norr::HandshakeRole::responder,
                                                  *responder_static, norr::PublicKey{}, psk);
    if (!initiator || !responder) return;

    std::array<std::byte, norr::kNoiseMessage1Overhead + 6> message_1{};
    const auto written_1 = initiator->write_message_1(payload, message_1);
    if (!written_1) return;

    std::array<std::byte, 6> out_1{};
    if (!responder->read_message_1(std::span{message_1}.first(*written_1), out_1)) return;

    std::array<std::byte, norr::kNoiseMessage2Overhead + 6> message_2{};
    const auto written_2 = responder->write_message_2(payload, message_2);
    if (!written_2) return;

    std::array<std::byte, 6> out_2{};
    static_cast<void>(initiator->read_message_2(std::span{message_2}.first(*written_2), out_2));
  }));
}

void bench_cookie(std::vector<norr::BenchResult>& results) {
  const auto responder_static = norr::generate_keypair();
  if (!responder_static) return;

  norr::CookieIssuer issuer{responder_static->public_key};
  const auto now = std::chrono::steady_clock::now();
  const auto peer = norr::parse_endpoint("203.0.113.5:51820");
  if (!peer) return;

  const std::array<std::byte, 64> message{};
  const auto mac1 = issuer.compute_mac1(message);

  // The point of the comparison: verifying mac1 must be orders of magnitude
  // cheaper than a handshake, otherwise the mitigation costs as much as the
  // attack it prevents.
  results.push_back(norr::run_benchmark("cookie verify mac1", 1'000'000, 0, [&] {
    static_cast<void>(issuer.verify_mac1(message, mac1));
  }));

  results.push_back(norr::run_benchmark("cookie build reply", 200'000, 0, [&] {
    static_cast<void>(issuer.build_reply(*peer, 1, mac1, now));
  }));
}

}  // namespace

int main(int argc, char* argv[]) {
  if (!norr::crypto_available()) {
    std::fprintf(stderr,
                 "norr_bench: crypto backend unavailable; build with libsodium to benchmark\n");
    return 1;
  }
  if (!norr::crypto_init()) {
    std::fprintf(stderr, "norr_bench: crypto initialisation failed\n");
    return 1;
  }

  auto environment = norr::BenchEnvironment::detect();
  if (argc > 1) environment.notes = argv[1];

  std::vector<norr::BenchResult> results;
  bench_parsing(results);
  bench_routing(results);
  bench_replay_window(results);
  bench_aead(results);
  bench_session(results);
  bench_cookie(results);
  bench_handshake(results);

  norr::print_report(environment, results);

  std::printf(
      "\nScope: per-component cost on this machine only. End-to-end tunnel\n"
      "throughput against a baseline, per bench/methodology.md, needs two hosts\n"
      "with real NICs and netem and is not measured here.\n");
  return 0;
}
