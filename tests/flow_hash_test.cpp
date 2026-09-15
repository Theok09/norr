#include <algorithm>
#include <array>
#include "check.hpp"
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>
#include <string_view>
#include <vector>

#include "norr/flow_hash.hpp"

namespace {

norr::Address address_of(std::string_view text) {
  const auto parsed = norr::parse_address(text);
  NORR_CHECK(parsed.has_value());
  return *parsed;
}

// An IPv4 packet with a TCP or UDP header carrying the given ports.
std::vector<std::byte> make_packet(std::string_view source, std::string_view destination,
                                   std::uint16_t source_port, std::uint16_t destination_port,
                                   std::uint8_t protocol = norr::kProtocolTcp,
                                   std::size_t transport_bytes = 4) {
  std::vector<std::byte> packet(norr::kIpv4HeaderSize + transport_bytes);
  packet[0] = std::byte{0x45};
  const auto total = static_cast<std::uint16_t>(packet.size());
  packet[2] = static_cast<std::byte>(total >> 8U);
  packet[3] = static_cast<std::byte>(total & 0xFFU);
  packet[8] = std::byte{64};
  packet[9] = static_cast<std::byte>(protocol);

  const auto from = address_of(source);
  const auto to = address_of(destination);
  const auto from_bytes = from.bytes();
  const auto to_bytes = to.bytes();
  std::copy_n(from_bytes.begin(), 4, packet.begin() + 12);
  std::copy_n(to_bytes.begin(), 4, packet.begin() + 16);

  if (transport_bytes >= 4) {
    packet[20] = static_cast<std::byte>(source_port >> 8U);
    packet[21] = static_cast<std::byte>(source_port & 0xFFU);
    packet[22] = static_cast<std::byte>(destination_port >> 8U);
    packet[23] = static_cast<std::byte>(destination_port & 0xFFU);
  }
  return packet;
}

norr::FlowKey key_of(const std::vector<std::byte>& packet) {
  const auto parsed = norr::parse_ip_packet(packet);
  NORR_CHECK(parsed.has_value());
  return norr::flow_key_of(*parsed, packet);
}

void test_key_extraction() {
  const auto packet = make_packet("10.0.0.1", "10.0.0.2", 1234, 80);
  const auto key = key_of(packet);

  NORR_CHECK(key.source == address_of("10.0.0.1"));
  NORR_CHECK(key.destination == address_of("10.0.0.2"));
  NORR_CHECK(key.source_port == 1234);
  NORR_CHECK(key.destination_port == 80);
  NORR_CHECK(key.protocol == norr::kProtocolTcp);

  std::puts("flow_hash: key extraction OK");
}

void test_ports_only_for_tcp_and_udp() {
  // ICMP has no ports; reading bytes 20-23 as ports would be meaningless.
  const auto icmp = make_packet("10.0.0.1", "10.0.0.2", 1234, 80, 1);
  const auto key = key_of(icmp);
  NORR_CHECK(key.source_port == 0 && key.destination_port == 0);
  NORR_CHECK(key.protocol == 1);

  const auto udp = make_packet("10.0.0.1", "10.0.0.2", 5000, 53, norr::kProtocolUdp);
  const auto udp_key = key_of(udp);
  NORR_CHECK(udp_key.source_port == 5000 && udp_key.destination_port == 53);

  std::puts("flow_hash: ports read only where they exist OK");
}

void test_truncated_transport_header() {
  // A packet whose transport header is not fully present must not be read past.
  // Under the sanitizer build this is where an overread would surface.
  for (std::size_t transport_bytes : {std::size_t{0}, std::size_t{1}, std::size_t{3}}) {
    const auto packet =
        make_packet("10.0.0.1", "10.0.0.2", 1234, 80, norr::kProtocolTcp, transport_bytes);
    const auto key = key_of(packet);
    NORR_CHECK(key.source_port == 0 && key.destination_port == 0);
  }

  std::puts("flow_hash: truncated transport header handled OK");
}

void test_bidirectional_affinity() {
  // A flow and its replies must land on the same worker, so session state
  // stays on one core.
  const auto forward = key_of(make_packet("10.0.0.1", "10.0.0.2", 1234, 80));
  const auto reverse = key_of(make_packet("10.0.0.2", "10.0.0.1", 80, 1234));

  NORR_CHECK(norr::hash_flow(forward) == norr::hash_flow(reverse));
  for (std::size_t workers : {2U, 3U, 4U, 8U, 16U}) {
    NORR_CHECK(norr::worker_for(forward, workers) == norr::worker_for(reverse, workers));
  }

  std::puts("flow_hash: both directions share a worker OK");
}

void test_distinct_flows_differ() {
  const auto base = key_of(make_packet("10.0.0.1", "10.0.0.2", 1234, 80));

  // Every component of the key must affect the hash, otherwise distinct flows
  // would collide systematically and defeat affinity.
  const auto other_port = key_of(make_packet("10.0.0.1", "10.0.0.2", 1235, 80));
  const auto other_address = key_of(make_packet("10.0.0.3", "10.0.0.2", 1234, 80));
  const auto other_protocol =
      key_of(make_packet("10.0.0.1", "10.0.0.2", 1234, 80, norr::kProtocolUdp));

  NORR_CHECK(norr::hash_flow(base) != norr::hash_flow(other_port));
  NORR_CHECK(norr::hash_flow(base) != norr::hash_flow(other_address));
  NORR_CHECK(norr::hash_flow(base) != norr::hash_flow(other_protocol));

  std::puts("flow_hash: distinct flows hash differently OK");
}

void test_determinism_and_distribution() {
  const auto key = key_of(make_packet("10.0.0.1", "10.0.0.2", 1234, 80));
  // The same key must always give the same answer, across calls.
  NORR_CHECK(norr::hash_flow(key) == norr::hash_flow(key));
  NORR_CHECK(norr::worker_for(key, 4) == norr::worker_for(key, 4));

  // With one worker everything lands on worker zero.
  NORR_CHECK(norr::worker_for(key, 1) == 0);
  NORR_CHECK(norr::worker_for(key, 0) == 0);

  // Across many flows every worker should see traffic. A hash that sent
  // everything to one core would silently destroy parallelism.
  constexpr std::size_t kWorkers = 8;
  std::array<std::size_t, kWorkers> counts{};
  for (std::uint16_t port = 1; port < 2000; ++port) {
    const auto flow = key_of(make_packet("10.0.0.1", "10.0.0.2", port, 80));
    ++counts[norr::worker_for(flow, kWorkers)];
  }
  for (const auto count : counts) {
    // Perfectly even distribution is not required, but no worker may be
    // starved: with ~250 expected each, fewer than 100 signals a bad hash.
    NORR_CHECK(count > 100);
  }

  std::puts("flow_hash: deterministic and well distributed OK");
}

void test_ipv6_flows() {
  const auto parsed_source = address_of("2001:db8::1");
  const auto parsed_destination = address_of("2001:db8::2");

  const norr::FlowKey forward{.source = parsed_source,
                              .destination = parsed_destination,
                              .source_port = 4000,
                              .destination_port = 443,
                              .protocol = norr::kProtocolTcp};
  const norr::FlowKey reverse{.source = parsed_destination,
                              .destination = parsed_source,
                              .source_port = 443,
                              .destination_port = 4000,
                              .protocol = norr::kProtocolTcp};

  NORR_CHECK(norr::hash_flow(forward) == norr::hash_flow(reverse));

  const norr::FlowKey different{.source = parsed_source,
                                .destination = address_of("2001:db8::3"),
                                .source_port = 4000,
                                .destination_port = 443,
                                .protocol = norr::kProtocolTcp};
  NORR_CHECK(norr::hash_flow(forward) != norr::hash_flow(different));

  std::puts("flow_hash: IPv6 flows OK");
}

}  // namespace

int main() {
  test_key_extraction();
  test_ports_only_for_tcp_and_udp();
  test_truncated_transport_header();
  test_bidirectional_affinity();
  test_distinct_flows_differ();
  test_determinism_and_distribution();
  test_ipv6_flows();
  return 0;
}
