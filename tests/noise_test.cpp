// Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s.
//
// The properties checked here are the ones the tunnel's security rests on:
// both sides reach the same keys, the keys are oriented correctly, and every
// way of getting the inputs wrong fails closed rather than producing a session.

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

// Runs a complete handshake and returns both results, or nothing if any step
// failed.
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

  // Both sides must agree on the keys, crossed over: what one sends with is
  // what the other receives with.
  NORR_CHECK(norr::constant_time_equal(completed->initiator.send, completed->responder.receive));
  NORR_CHECK(norr::constant_time_equal(completed->initiator.receive, completed->responder.send));

  // The two directions must be different keys, otherwise a reflected packet
  // would authenticate.
  NORR_CHECK(!norr::constant_time_equal(completed->initiator.send, completed->initiator.receive));

  // Both sides must reach the same transcript hash, which is what makes it
  // usable as a channel binding.
  NORR_CHECK(norr::constant_time_equal(completed->initiator.handshake_hash,
                                   completed->responder.handshake_hash));

  // Each side learns the other's authenticated static identity. This is the
  // whole point of the handshake: the responder did not know who was calling.
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

  // Same static keys and same PSK, but fresh ephemerals must give different
  // session keys. Identical keys would mean the ephemeral is not being used.
  NORR_CHECK(!norr::constant_time_equal(first->initiator.send, second->initiator.send));
  NORR_CHECK(!norr::constant_time_equal(first->initiator.handshake_hash,
                                    second->initiator.handshake_hash));

  std::puts("noise: every handshake derives fresh keys");
}

void test_psk_must_match() {
  const auto peers = make_peers();

  // A mismatched PSK must not produce a session. The psk is mixed in message 2,
  // so the failure surfaces when the initiator reads it.
  const auto completed =
      run_handshake(peers, make_psk(0x42), make_psk(0x43), peers.responder.public_key);
  NORR_CHECK(!completed.has_value());

  std::puts("noise: mismatched preshared key fails closed");
}

void test_initiator_must_know_the_right_responder() {
  const auto peers = make_peers();
  const auto psk = make_psk(0x42);

  // IK means the initiator knows the responder's static key in advance.
  // Believing the wrong key must fail: the `es` and `ss` DH results differ, so
  // the responder cannot decrypt the initiator's static key.
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

  // A differing prologue changes the transcript, so the first decryption fails.
  std::vector<std::byte> out(payload.size());
  const auto read = responder->read_message_1(std::span{message}.first(*written), out);
  NORR_CHECK(!read.has_value());

  std::puts("noise: prologue is bound into the transcript");
}

void test_tampering_is_detected() {
  const auto peers = make_peers();
  const auto psk = make_psk(0x42);
  const auto payload = as_bytes("version=1");

  // Every byte of message 1 is either hashed into the transcript or covered by
  // a tag, so flipping any of them must be caught.
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

  // A message shorter than the pattern's fixed overhead cannot be valid and
  // must be refused before any parsing walks off the end.
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

  // Roles cannot be swapped.
  NORR_CHECK(!initiator->read_message_1(buffer, out).has_value());
  NORR_CHECK(!responder->write_message_1(payload, buffer).has_value());

  // The responder cannot answer before it has read message 1.
  NORR_CHECK(!responder->write_message_2(payload, buffer).has_value());

  // The initiator cannot read message 2 before sending message 1.
  NORR_CHECK(!initiator->read_message_2(buffer, out).has_value());

  // Results are not available until the handshake finishes.
  NORR_CHECK(!initiator->result().has_value());
  NORR_CHECK(!initiator->finished());

  // Message 1 cannot be sent twice; that would reuse the ephemeral key.
  const auto first = initiator->write_message_1(payload, buffer);
  NORR_CHECK(first.has_value());
  const auto again = initiator->write_message_1(payload, buffer);
  NORR_CHECK(!again.has_value() && again.error() == norr::NoiseError::invalid_state);

  std::puts("noise: out-of-order steps rejected");
}

void test_initiator_requires_remote_static() {
  const auto peers = make_peers();
  const auto psk = make_psk(0x42);

  // IK has no way to run without the responder's static key, so an all-zero
  // key is refused at construction rather than producing a broken session.
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

  // The derived keys must actually drive the transport layer.
  const norr::TrafficKeys initiator_send{completed->initiator.send, 0};
  const norr::TrafficKeys responder_receive{completed->responder.receive, 0};

  const auto plaintext = as_bytes("first transport packet");
  std::vector<std::byte> sealed(plaintext.size() + norr::kAeadTagSize);
  NORR_CHECK(initiator_send.seal(0, {}, plaintext, sealed).has_value());

  std::vector<std::byte> opened(plaintext.size());
  const auto result = responder_receive.open(0, {}, sealed, opened);
  NORR_CHECK(result.has_value() && *result == plaintext.size());
  NORR_CHECK(std::equal(plaintext.begin(), plaintext.end(), opened.begin()));

  // The wrong direction must not open it.
  const norr::TrafficKeys responder_send{completed->responder.send, 0};
  std::vector<std::byte> rejected(plaintext.size());
  NORR_CHECK(!responder_send.open(0, {}, sealed, rejected).has_value());

  std::puts("noise: derived transport keys carry traffic");
}

}  // namespace

int main() {
  if (!norr::crypto_available()) {
    // Without a backend the handshake cannot run at all, and must say so
    // rather than appearing to succeed.
    const norr::KeyPair empty{};
    const auto created = norr::NoiseHandshake::create(norr::HandshakeRole::responder, empty,
                                                      norr::PublicKey{}, norr::PresharedKey{});
    NORR_CHECK(!created.has_value());
    NORR_CHECK(created.error() == norr::NoiseError::unsupported_platform);
    std::puts("noise: crypto backend absent, guards verified");
    return 0;
  }

  NORR_CHECK(norr::crypto_init().has_value());

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
