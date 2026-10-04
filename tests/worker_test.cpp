
#include <algorithm>
#include <array>
#include "check.hpp"
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include "norr/noise.hpp"
#include "norr/worker.hpp"

namespace {
norr::Address address_of(std::string_view text) {
  const auto parsed = norr::parse_address(text);
  NORR_CHECK(parsed.has_value());
  return *parsed;
}

norr::Prefix prefix_of(std::string_view text) {
  const auto parsed = norr::parse_prefix(text);
  NORR_CHECK(parsed.has_value());
  return *parsed;
}

std::vector<std::byte> make_ipv4(std::string_view source, std::string_view destination,
                                 std::uint8_t ttl = 64, std::size_t payload = 0) {
  std::vector<std::byte> packet(norr::kIpv4HeaderSize + payload);
  packet[0] = std::byte{0x45};
  const auto total = static_cast<std::uint16_t>(packet.size());
  packet[2] = static_cast<std::byte>(total >> 8U);
  packet[3] = static_cast<std::byte>(total & 0xFFU);
  packet[8] = static_cast<std::byte>(ttl);
  packet[9] = std::byte{6};

  const auto source_address = address_of(source);
  const auto destination_address = address_of(destination);
  const auto from = source_address.bytes();
  const auto to = destination_address.bytes();
  std::copy_n(from.begin(), 4, packet.begin() + 12);
  std::copy_n(to.begin(), 4, packet.begin() + 16);
  return packet;
}

struct Node {
  norr::TunDevice tun;
  norr::UdpTransport transport;
  norr::RoutingTable routes;
  norr::SessionTable sessions;
  std::optional<norr::UdpCarrier> carrier;
  std::optional<norr::Worker> worker;

  void build() {
    carrier.emplace(transport);
    worker.emplace(tun, *carrier, routes, sessions);
  }
};

struct Established {
  norr::TrafficKey initiator_send;
  norr::TrafficKey initiator_receive;
};

Established establish() {
  const auto initiator_static = norr::generate_keypair();
  const auto responder_static = norr::generate_keypair();
  NORR_CHECK(initiator_static.has_value() && responder_static.has_value());

  norr::PresharedKey psk{};
  psk.fill(std::byte{0x7F});

  auto initiator = norr::NoiseHandshake::create(norr::HandshakeRole::initiator, *initiator_static,
                                                responder_static->public_key, psk);
  auto responder = norr::NoiseHandshake::create(norr::HandshakeRole::responder, *responder_static,
                                                norr::PublicKey{}, psk);
  NORR_CHECK(initiator.has_value() && responder.has_value());

  const std::array<std::byte, 2> payload{std::byte{1}, std::byte{0}};
  std::vector<std::byte> message_1(norr::kNoiseMessage1Overhead + payload.size());
  const auto written_1 = initiator->write_message_1(payload, message_1);
  NORR_CHECK(written_1.has_value());

  std::vector<std::byte> out_1(payload.size());
  NORR_CHECK(responder->read_message_1(std::span{message_1}.first(*written_1), out_1).has_value());

  std::vector<std::byte> message_2(norr::kNoiseMessage2Overhead + payload.size());
  const auto written_2 = responder->write_message_2(payload, message_2);
  NORR_CHECK(written_2.has_value());

  std::vector<std::byte> out_2(payload.size());
  NORR_CHECK(initiator->read_message_2(std::span{message_2}.first(*written_2), out_2).has_value());

  const auto initiator_result = initiator->result();
  const auto responder_result = responder->result();
  NORR_CHECK(initiator_result.has_value() && responder_result.has_value());

  NORR_CHECK(norr::constant_time_equal(initiator_result->send, responder_result->receive));

  return Established{.initiator_send = initiator_result->send,
                     .initiator_receive = initiator_result->receive};
}

void test_end_to_end() {
  Node alice;
  Node bob;

  NORR_CHECK(alice.routes.add(2, prefix_of("10.2.0.0/16")).has_value());
  NORR_CHECK(alice.routes.add(1, prefix_of("10.1.0.0/16")).has_value());
  NORR_CHECK(bob.routes.add(1, prefix_of("10.1.0.0/16")).has_value());
  NORR_CHECK(bob.routes.add(2, prefix_of("10.2.0.0/16")).has_value());

  const auto loopback = address_of("127.0.0.1");
  NORR_CHECK(alice.transport.start(norr::Endpoint{loopback, 0}).has_value());
  NORR_CHECK(bob.transport.start(norr::Endpoint{loopback, 0}).has_value());
  const auto alice_port = alice.transport.local_port();
  const auto bob_port = bob.transport.local_port();
  NORR_CHECK(alice_port.has_value() && bob_port.has_value());

  const auto keys = establish();

  auto alice_session = [&] {
    const auto installed = alice.sessions.install(2, 0x00A1, 0x00B1,
                                                  norr::TrafficKeys{keys.initiator_send, 0},
                                                  norr::TrafficKeys{keys.initiator_receive, 0});
    NORR_CHECK(installed.has_value());
    return *installed;
  }();
  auto bob_session = [&] {
    const auto installed = bob.sessions.install(1, 0x00B1, 0x00A1,
                                                norr::TrafficKeys{keys.initiator_receive, 0},
                                                norr::TrafficKeys{keys.initiator_send, 0});
    NORR_CHECK(installed.has_value());
    return *installed;
  }();

  alice_session->note_authenticated_endpoint(norr::Endpoint{loopback, *bob_port});
  bob_session->note_authenticated_endpoint(norr::Endpoint{loopback, *alice_port});

  alice.build();
  bob.build();

  const auto packet = make_ipv4("10.1.0.5", "10.2.0.7", 64, 16);
  NORR_CHECK(alice.worker->forward_from_tun(packet) == norr::DropReason::none);
  NORR_CHECK(alice.worker->stats().tun_to_udp == 1);

  norr::ReceiveBuffers pool{norr::UdpTransport::kDefaultBatchSize,
                            norr::UdpTransport::kDefaultDatagramSize};
  std::array<norr::InboundDatagram, norr::UdpTransport::kDefaultBatchSize> inbound{};

  std::size_t received = 0;
  for (int attempt = 0; attempt < 1000 && received == 0; ++attempt) {
    const auto result = bob.transport.receive_batch(pool, inbound);
    NORR_CHECK(result.has_value());
    received = *result;
  }
  NORR_CHECK(received == 1);

  const auto reason = bob.worker->forward_from_transport(inbound[0].source, inbound[0].payload);

  NORR_CHECK(reason == norr::DropReason::none || reason == norr::DropReason::tun_write_failed);

  NORR_CHECK(bob_session->endpoint().has_value());
  NORR_CHECK(bob_session->endpoint()->port() == *alice_port);

  std::puts("worker: end-to-end encrypted forward OK");
}

void test_drop_reasons() {
  Node node;
  NORR_CHECK(node.routes.add(2, prefix_of("10.2.0.0/16")).has_value());
  NORR_CHECK(node.routes.add(1, prefix_of("10.1.0.0/16")).has_value());

  const auto loopback = address_of("127.0.0.1");
  NORR_CHECK(node.transport.start(norr::Endpoint{loopback, 0}).has_value());
  node.build();

  {
    const std::array<std::byte, 4> garbage{std::byte{0xFF}, std::byte{0xFF}};
    NORR_CHECK(node.worker->forward_from_tun(garbage) == norr::DropReason::malformed_inner_packet);
  }

  {
    const auto packet = make_ipv4("10.1.0.5", "203.0.113.1");
    NORR_CHECK(node.worker->forward_from_tun(packet) == norr::DropReason::no_route);
  }

  {
    const auto packet = make_ipv4("10.1.0.5", "224.0.0.1");
    NORR_CHECK(node.worker->forward_from_tun(packet) == norr::DropReason::policy_denied);
  }

  {
    const auto packet = make_ipv4("10.1.0.5", "10.2.0.7", 1);
    NORR_CHECK(node.worker->forward_from_tun(packet) == norr::DropReason::hop_limit);
  }

  {
    const auto packet = make_ipv4("10.1.0.5", "10.2.0.7");
    NORR_CHECK(node.worker->forward_from_tun(packet) == norr::DropReason::no_session);
  }

  {
    const std::array<std::byte, 8> garbage{};
    const auto source = norr::Endpoint{loopback, 9999};
    NORR_CHECK(node.worker->forward_from_transport(source, garbage) ==
           norr::DropReason::malformed_outer_packet);
  }

  {
    const norr::PacketHeader header{.version = norr::kProtocolVersion,
                                    .type = norr::FrameType::data,
                                    .key_id = 0x4242,
                                    .counter = 1};
    const std::array<std::byte, 32> payload{};
    const auto encoded = norr::serialize_packet(header, payload);
    NORR_CHECK(encoded.has_value());
    const auto source = norr::Endpoint{loopback, 9999};
    NORR_CHECK(node.worker->forward_from_transport(source, *encoded) == norr::DropReason::no_session);
  }

  const auto& stats = node.worker->stats();
  NORR_CHECK(stats.drops == 7);
  NORR_CHECK(stats.drops_for(norr::DropReason::malformed_inner_packet) == 1);
  NORR_CHECK(stats.drops_for(norr::DropReason::no_route) == 1);
  NORR_CHECK(stats.drops_for(norr::DropReason::policy_denied) == 1);
  NORR_CHECK(stats.drops_for(norr::DropReason::hop_limit) == 1);
  NORR_CHECK(stats.drops_for(norr::DropReason::no_session) == 2);
  NORR_CHECK(stats.drops_for(norr::DropReason::malformed_outer_packet) == 1);
  NORR_CHECK(stats.tun_to_udp == 0);

  std::puts("worker: every drop reason counted separately OK");
}

void test_source_authorization() {
  Node node;
  NORR_CHECK(node.routes.add(1, prefix_of("10.1.0.0/16")).has_value());
  NORR_CHECK(node.routes.add(2, prefix_of("10.2.0.0/16")).has_value());

  const auto loopback = address_of("127.0.0.1");
  NORR_CHECK(node.transport.start(norr::Endpoint{loopback, 0}).has_value());

  const auto keys = establish();

  auto session = [&] {
    const auto installed = node.sessions.install(1, 0x0001, 0x0002,
                                                 norr::TrafficKeys{keys.initiator_send, 0},
                                                 norr::TrafficKeys{keys.initiator_receive, 0});
    NORR_CHECK(installed.has_value());
    return *installed;
  }();
  session->note_authenticated_endpoint(norr::Endpoint{loopback, 1});
  node.build();

  norr::Session sender{1, 0x0002, 0x0001, norr::TrafficKeys{keys.initiator_receive, 0},
                       norr::TrafficKeys{keys.initiator_send, 0}};
  const auto spoofed = make_ipv4("10.2.0.9", "10.1.0.5");
  std::vector<std::byte> wire(norr::kPacketHeaderSize + spoofed.size() + norr::kAeadTagSize);
  const auto sealed = sender.seal(norr::FrameType::data, spoofed, wire);
  NORR_CHECK(sealed.has_value());

  const auto source = norr::Endpoint{loopback, 1};
  const auto reason =
      node.worker->forward_from_transport(source, std::span{wire}.first(*sealed));
  NORR_CHECK(reason == norr::DropReason::source_not_authorized);
  NORR_CHECK(node.worker->stats().drops_for(norr::DropReason::source_not_authorized) == 1);

  std::puts("worker: spoofed source rejected after authentication OK");
}

void test_forged_packet_rejected() {
  Node node;
  NORR_CHECK(node.routes.add(1, prefix_of("10.1.0.0/16")).has_value());
  NORR_CHECK(node.routes.add(2, prefix_of("10.2.0.0/16")).has_value());

  const auto loopback = address_of("127.0.0.1");
  NORR_CHECK(node.transport.start(norr::Endpoint{loopback, 0}).has_value());

  const auto keys = establish();
  auto session = [&] {
    const auto installed = node.sessions.install(1, 0x0001, 0x0002,
                                                 norr::TrafficKeys{keys.initiator_send, 0},
                                                 norr::TrafficKeys{keys.initiator_receive, 0});
    NORR_CHECK(installed.has_value());
    return *installed;
  }();
  const auto original = norr::Endpoint{loopback, 1111};
  session->note_authenticated_endpoint(original);
  node.build();

  norr::Session sender{1, 0x0002, 0x0001, norr::TrafficKeys{keys.initiator_receive, 0},
                       norr::TrafficKeys{keys.initiator_send, 0}};
  const auto packet = make_ipv4("10.1.0.5", "10.2.0.7");
  std::vector<std::byte> wire(norr::kPacketHeaderSize + packet.size() + norr::kAeadTagSize);
  const auto sealed = sender.seal(norr::FrameType::data, packet, wire);
  NORR_CHECK(sealed.has_value());

  wire[*sealed - 1] ^= std::byte{0xFF};
  const auto attacker = norr::Endpoint{loopback, 2222};
  const auto reason = node.worker->forward_from_transport(attacker, std::span{wire}.first(*sealed));
  NORR_CHECK(reason == norr::DropReason::authentication_failed);

  NORR_CHECK(session->endpoint().has_value());
  NORR_CHECK(*session->endpoint() == original);

  std::puts("worker: forged packet cannot move the peer endpoint OK");
}
}

void test_padding_hides_inner_length() {
  Node alice;
  alice.build();

  norr::TrafficKey key{};
  key.fill(std::byte{0x33});

  const auto installed = alice.sessions.install(
      2, 0x0050, 0x0060, norr::TrafficKeys{key, 0}, norr::TrafficKeys{key, 0});
  NORR_CHECK(installed.has_value());

  const auto small = make_ipv4("10.1.0.5", "10.2.0.7", 64, 1);
  const auto larger = make_ipv4("10.1.0.5", "10.2.0.7", 64, 12);
  NORR_CHECK(small.size() != larger.size());
  NORR_CHECK(norr::padded_length(small.size()) == norr::padded_length(larger.size()));

  std::vector<std::byte> first(norr::kPacketHeaderSize + 128 + norr::kAeadTagSize);
  std::vector<std::byte> second(norr::kPacketHeaderSize + 128 + norr::kAeadTagSize);

  std::vector<std::byte> padded_small(norr::padded_length(small.size()), std::byte{0});
  std::copy(small.begin(), small.end(), padded_small.begin());
  std::vector<std::byte> padded_larger(norr::padded_length(larger.size()), std::byte{0});
  std::copy(larger.begin(), larger.end(), padded_larger.begin());

  const auto sealed_small =
      (*installed)->seal(norr::FrameType::data, padded_small, first);
  const auto sealed_larger =
      (*installed)->seal(norr::FrameType::data, padded_larger, second);
  NORR_CHECK(sealed_small.has_value() && sealed_larger.has_value());

  NORR_CHECK(*sealed_small == *sealed_larger);

  std::puts("worker: padding makes different inner sizes indistinguishable OK");
}

int main() {
  test_padding_hides_inner_length();
  if (!norr::UdpTransport::supported() || !norr::crypto_available()) {
    std::puts("worker: platform or crypto backend unavailable, skipped");
    return 0;
  }
  NORR_CHECK(norr::crypto_init().has_value());

  test_end_to_end();
  test_drop_reasons();
  test_source_authorization();
  test_forged_packet_rejected();
  return 0;
}
