
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

namespace {
std::vector<std::byte> as_bytes(std::string_view text) {
  std::vector<std::byte> bytes;
  bytes.reserve(text.size());
  for (const char character : text) {
    bytes.push_back(static_cast<std::byte>(static_cast<unsigned char>(character)));
  }
  return bytes;
}

norr::PresharedKey make_psk(std::uint8_t fill) {
  norr::PresharedKey psk{};
  psk.fill(static_cast<std::byte>(fill));
  return psk;
}

struct Peers {
  norr::KeyPair initiator;
  norr::KeyPair responder;
};

Peers make_peers() {
  const auto initiator = norr::generate_keypair();
  const auto responder = norr::generate_keypair();
  NORR_CHECK(initiator.has_value() && responder.has_value());
  return Peers{.initiator = *initiator, .responder = *responder};
}

struct Completed {
  norr::NoiseResult initiator;
  norr::NoiseResult responder;
};

std::optional<Completed> run_handshake(const Peers& peers, const norr::PresharedKey& initiator_psk,
                                       const norr::PresharedKey& responder_psk,
                                       const norr::PublicKey& initiator_believes,
                                       std::span<const std::byte> prologue = {}) {
  auto initiator = norr::NoiseHandshake::create(norr::HandshakeRole::initiator, peers.initiator,
                                                initiator_believes, initiator_psk, prologue);
  auto responder = norr::NoiseHandshake::create(norr::HandshakeRole::responder, peers.responder,
                                                norr::PublicKey{}, responder_psk, prologue);
  if (!initiator.has_value() || !responder.has_value()) return std::nullopt;

  const auto payload_1 = as_bytes("version=1;caps=3");
  std::vector<std::byte> message_1(norr::kNoiseMessage1Overhead + payload_1.size());
  const auto written_1 = initiator->write_message_1(payload_1, message_1);
  if (!written_1) return std::nullopt;

  std::vector<std::byte> received_1(payload_1.size());
  const auto read_1 = responder->read_message_1(std::span{message_1}.first(*written_1), received_1);
  if (!read_1) return std::nullopt;
  NORR_CHECK(*read_1 == payload_1.size());
  NORR_CHECK(std::equal(payload_1.begin(), payload_1.end(), received_1.begin()));

  const auto payload_2 = as_bytes("version=1;caps=1");
  std::vector<std::byte> message_2(norr::kNoiseMessage2Overhead + payload_2.size());
  const auto written_2 = responder->write_message_2(payload_2, message_2);
  if (!written_2) return std::nullopt;

  std::vector<std::byte> received_2(payload_2.size());
  const auto read_2 = initiator->read_message_2(std::span{message_2}.first(*written_2), received_2);
  if (!read_2) return std::nullopt;
  NORR_CHECK(std::equal(payload_2.begin(), payload_2.end(), received_2.begin()));

  const auto initiator_result = initiator->result();
  const auto responder_result = responder->result();
  if (!initiator_result.has_value() || !responder_result.has_value()) return std::nullopt;
  return Completed{.initiator = *initiator_result, .responder = *responder_result};
}

void test_successful_handshake() {
  const auto peers = make_peers();
  const auto psk = make_psk(0x42);

  const auto completed = run_handshake(peers, psk, psk, peers.responder.public_key);
  NORR_CHECK(completed.has_value());

  NORR_CHECK(norr::constant_time_equal(completed->initiator.send, completed->responder.receive));
  NORR_CHECK(norr::constant_time_equal(completed->initiator.receive, completed->responder.send));

  NORR_CHECK(!norr::constant_time_equal(completed->initiator.send, completed->initiator.receive));

  NORR_CHECK(norr::constant_time_equal(completed->initiator.handshake_hash,
                                   completed->responder.handshake_hash));

  NORR_CHECK(norr::constant_time_equal(completed->responder.remote_static,
                                   peers.initiator.public_key));
  NORR_CHECK(norr::constant_time_equal(completed->initiator.remote_static,
                                   peers.responder.public_key));

  std::puts("noise: handshake completes and keys agree");
}

void test_each_handshake_is_fresh() {
  const auto peers = make_peers();
  const auto psk = make_psk(0x42);

  const auto first = run_handshake(peers, psk, psk, peers.responder.public_key);
  const auto second = run_handshake(peers, psk, psk, peers.responder.public_key);
  NORR_CHECK(first.has_value() && second.has_value());

  NORR_CHECK(!norr::constant_time_equal(first->initiator.send, second->initiator.send));
  NORR_CHECK(!norr::constant_time_equal(first->initiator.handshake_hash,
                                    second->initiator.handshake_hash));

  std::puts("noise: every handshake derives fresh keys");
}

void test_psk_must_match() {
  const auto peers = make_peers();

  const auto completed =
      run_handshake(peers, make_psk(0x42), make_psk(0x43), peers.responder.public_key);
  NORR_CHECK(!completed.has_value());

  std::puts("noise: mismatched preshared key fails closed");
}

void test_initiator_must_know_the_right_responder() {
  const auto peers = make_peers();
  const auto psk = make_psk(0x42);

  const auto stranger = norr::generate_keypair();
  NORR_CHECK(stranger.has_value());
  const auto completed = run_handshake(peers, psk, psk, stranger->public_key);
  NORR_CHECK(!completed.has_value());

  std::puts("noise: wrong responder identity fails closed");
}

void test_prologue_must_match() {
  const auto peers = make_peers();
  const auto psk = make_psk(0x42);

  auto initiator = norr::NoiseHandshake::create(norr::HandshakeRole::initiator, peers.initiator,
                                                peers.responder.public_key, psk,
                                                as_bytes("norr v1 prologue"));
  auto responder = norr::NoiseHandshake::create(norr::HandshakeRole::responder, peers.responder,
                                                norr::PublicKey{}, psk,
                                                as_bytes("different prologue"));
  NORR_CHECK(initiator.has_value() && responder.has_value());

  const auto payload = as_bytes("x");
  std::vector<std::byte> message(norr::kNoiseMessage1Overhead + payload.size());
  const auto written = initiator->write_message_1(payload, message);
  NORR_CHECK(written.has_value());

  std::vector<std::byte> out(payload.size());
  const auto read = responder->read_message_1(std::span{message}.first(*written), out);
  NORR_CHECK(!read.has_value());

  std::puts("noise: prologue is bound into the transcript");
}

void test_tampering_is_detected() {
  const auto peers = make_peers();
  const auto psk = make_psk(0x42);
  const auto payload = as_bytes("version=1");

  for (const std::size_t position : {std::size_t{0}, std::size_t{31}, std::size_t{40},
                                     std::size_t{70}}) {
    auto initiator = norr::NoiseHandshake::create(norr::HandshakeRole::initiator, peers.initiator,
                                                  peers.responder.public_key, psk);
    auto responder = norr::NoiseHandshake::create(norr::HandshakeRole::responder, peers.responder,
                                                  norr::PublicKey{}, psk);
    NORR_CHECK(initiator.has_value() && responder.has_value());

    std::vector<std::byte> message(norr::kNoiseMessage1Overhead + payload.size());
    const auto written = initiator->write_message_1(payload, message);
    NORR_CHECK(written.has_value());
    NORR_CHECK(position < *written);

    message[position] ^= std::byte{0x01};

    std::vector<std::byte> out(payload.size());
    const auto read = responder->read_message_1(std::span{message}.first(*written), out);
    NORR_CHECK(!read.has_value());
  }

  std::puts("noise: tampering with message 1 is detected");
}

void test_truncation_is_rejected() {
  const auto peers = make_peers();
  const auto psk = make_psk(0x42);

  auto responder = norr::NoiseHandshake::create(norr::HandshakeRole::responder, peers.responder,
                                                norr::PublicKey{}, psk);
  NORR_CHECK(responder.has_value());

  std::vector<std::byte> tiny(8);
  std::vector<std::byte> out(64);
  const auto read = responder->read_message_1(tiny, out);
  NORR_CHECK(!read.has_value() && read.error() == norr::NoiseError::message_too_short);

  std::puts("noise: truncated message rejected");
}

void test_state_machine_order() {
  const auto peers = make_peers();
  const auto psk = make_psk(0x42);

  auto initiator = norr::NoiseHandshake::create(norr::HandshakeRole::initiator, peers.initiator,
                                                peers.responder.public_key, psk);
  auto responder = norr::NoiseHandshake::create(norr::HandshakeRole::responder, peers.responder,
                                                norr::PublicKey{}, psk);
  NORR_CHECK(initiator.has_value() && responder.has_value());

  const auto payload = as_bytes("x");
  std::vector<std::byte> buffer(256);
  std::vector<std::byte> out(64);

  NORR_CHECK(!initiator->read_message_1(buffer, out).has_value());
  NORR_CHECK(!responder->write_message_1(payload, buffer).has_value());

  NORR_CHECK(!responder->write_message_2(payload, buffer).has_value());

  NORR_CHECK(!initiator->read_message_2(buffer, out).has_value());

  NORR_CHECK(!initiator->result().has_value());
  NORR_CHECK(!initiator->finished());

  const auto first = initiator->write_message_1(payload, buffer);
  NORR_CHECK(first.has_value());
  const auto again = initiator->write_message_1(payload, buffer);
  NORR_CHECK(!again.has_value() && again.error() == norr::NoiseError::invalid_state);

  std::puts("noise: out-of-order steps rejected");
}

void test_initiator_requires_remote_static() {
  const auto peers = make_peers();
  const auto psk = make_psk(0x42);

  const auto created = norr::NoiseHandshake::create(norr::HandshakeRole::initiator, peers.initiator,
                                                    norr::PublicKey{}, psk);
  NORR_CHECK(!created.has_value());
  NORR_CHECK(created.error() == norr::NoiseError::missing_remote_static);

  std::puts("noise: initiator without responder identity refused");
}

void test_transport_keys_work() {
  const auto peers = make_peers();
  const auto psk = make_psk(0x42);
  const auto completed = run_handshake(peers, psk, psk, peers.responder.public_key);
  NORR_CHECK(completed.has_value());

  const norr::TrafficKeys initiator_send{completed->initiator.send, 0};
  const norr::TrafficKeys responder_receive{completed->responder.receive, 0};

  const auto plaintext = as_bytes("first transport packet");
  std::vector<std::byte> sealed(plaintext.size() + norr::kAeadTagSize);
  NORR_CHECK(initiator_send.seal(0, {}, plaintext, sealed).has_value());

  std::vector<std::byte> opened(plaintext.size());
  const auto result = responder_receive.open(0, {}, sealed, opened);
  NORR_CHECK(result.has_value() && *result == plaintext.size());
  NORR_CHECK(std::equal(plaintext.begin(), plaintext.end(), opened.begin()));

  const norr::TrafficKeys responder_send{completed->responder.send, 0};
  std::vector<std::byte> rejected(plaintext.size());
  NORR_CHECK(!responder_send.open(0, {}, sealed, rejected).has_value());

  std::puts("noise: derived transport keys carry traffic");
}
}

std::vector<std::byte> from_hex(std::string_view text) {
  std::vector<std::byte> bytes;
  for (std::size_t index = 0; index + 1 < text.size(); index += 2) {
    const auto digit = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
    bytes.push_back(static_cast<std::byte>(digit(text[index]) * 16 + digit(text[index + 1])));
  }
  return bytes;
}

norr::KeyPair fixed_pair(std::uint8_t fill) {
  norr::KeyPair pair{};
  pair.private_key.fill(static_cast<std::byte>(fill));
  const auto derived = norr::derive_public_key(pair.private_key);
  NORR_CHECK(derived.has_value());
  pair.public_key = *derived;
  return pair;
}

void test_interoperates_with_reference_implementation() {
  const auto initiator_static = fixed_pair(1);
  const auto responder_static = fixed_pair(2);
  norr::PresharedKey psk{};
  psk.fill(std::byte{5});

  auto initiator = norr::NoiseHandshake::create(norr::HandshakeRole::initiator, initiator_static,
                                                responder_static.public_key, psk);
  auto responder = norr::NoiseHandshake::create(norr::HandshakeRole::responder, responder_static,
                                                norr::PublicKey{}, psk);
  NORR_CHECK(initiator.has_value() && responder.has_value());
  initiator->use_ephemeral(fixed_pair(3));
  responder->use_ephemeral(fixed_pair(4));

  const auto hello = as_bytes("hello");
  std::vector<std::byte> message_1(norr::kNoiseMessage1Overhead + hello.size());
  const auto written_1 = initiator->write_message_1(hello, message_1);
  NORR_CHECK(written_1.has_value());
  NORR_CHECK(message_1 == from_hex(
      "5dfedd3b6bd47f6fa28ee15d969d5bb0ea53774d488bdaf9df1c6e0124b3ef220a26599fb2188bb7"
      "23276fc173af67616c817fc32fd04d686d87ec152fac10eefeeebde821c1de619c973faef04bf17b"
      "3f9e2adfa37e138a97508b9b104f122b19e4034277"));

  std::vector<std::byte> received_1(hello.size());
  NORR_CHECK(responder->read_message_1(message_1, received_1).has_value());
  NORR_CHECK(received_1 == hello);

  const auto world = as_bytes("world");
  std::vector<std::byte> message_2(norr::kNoiseMessage2Overhead + world.size());
  NORR_CHECK(responder->write_message_2(world, message_2).has_value());
  NORR_CHECK(message_2 == from_hex(
      "ac01b2209e86354fb853237b5de0f4fab13c7fcbf433a61c019369617fecf10b71d6d473452b9735"
      "05c8fa9c0a24662a7779813071"));

  std::vector<std::byte> received_2(world.size());
  NORR_CHECK(initiator->read_message_2(message_2, received_2).has_value());

  const auto result = initiator->result();
  NORR_CHECK(result.has_value());
  const auto expected_hash =
      from_hex("2fff77253f2a7db772f125ba27cd0c661b8d2232548c8a9e73dcf668eed4471e");
  NORR_CHECK(std::ranges::equal(result->handshake_hash, expected_hash));

  const norr::TrafficKeys send{result->send, 0};
  const auto plaintext = as_bytes("transport");
  std::vector<std::byte> sealed(plaintext.size() + norr::kAeadTagSize);
  NORR_CHECK(send.seal(0, {}, plaintext, sealed).has_value());
  NORR_CHECK(sealed == from_hex("fbd8f7ca03258ca140629b2aca76c83252a61132ef3ad5c402"));

  std::puts("noise: byte-identical to an independent Noise_IKpsk2 implementation OK");
}

int main() {
  if (!norr::crypto_available()) {
    const norr::KeyPair empty{};
    const auto created = norr::NoiseHandshake::create(norr::HandshakeRole::responder, empty,
                                                      norr::PublicKey{}, norr::PresharedKey{});
    NORR_CHECK(!created.has_value());
    NORR_CHECK(created.error() == norr::NoiseError::unsupported_platform);
    std::puts("noise: crypto backend absent, guards verified");
    return 0;
  }

  NORR_CHECK(norr::crypto_init().has_value());

  test_interoperates_with_reference_implementation();
  test_successful_handshake();
  test_each_handshake_is_fresh();
  test_psk_must_match();
  test_initiator_must_know_the_right_responder();
  test_prologue_must_match();
  test_tampering_is_detected();
  test_truncation_is_rejected();
  test_state_machine_order();
  test_initiator_requires_remote_static();
  test_transport_keys_work();
  return 0;
}
