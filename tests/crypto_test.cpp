
#include <array>
#include "check.hpp"
#include <cstddef>
#include <cstdio>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "norr/crypto.hpp"

namespace {
std::vector<std::byte> as_bytes(std::string_view text) {
  std::vector<std::byte> bytes;
  bytes.reserve(text.size());
  for (const char character : text) {
    bytes.push_back(static_cast<std::byte>(static_cast<unsigned char>(character)));
  }
  return bytes;
}

void test_unavailable() {
  NORR_CHECK(!norr::crypto_init().has_value());
  NORR_CHECK(norr::crypto_init().error() == norr::CryptoError::unsupported_platform);
  NORR_CHECK(!norr::generate_keypair().has_value());

  std::array<std::byte, 8> buffer{};
  NORR_CHECK(!norr::random_bytes(buffer).has_value());

  const auto left = as_bytes("same");
  const auto right = as_bytes("same");
  NORR_CHECK(norr::constant_time_equal(left, right));
  NORR_CHECK(!norr::constant_time_equal(left, as_bytes("diff")));

  std::array<std::byte, 4> wipe{std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
  norr::secure_zero(wipe);
  for (const auto byte : wipe) NORR_CHECK(byte == std::byte{0});

  const auto secret = as_bytes("handshake secret");
  const auto key = norr::derive_traffic_key(secret, norr::kDataLabel,
                                            norr::KeyDirection::initiator_to_responder, 0);
  NORR_CHECK(key.has_value());

  std::puts("crypto: backend unavailable, guards verified");
}

void test_key_agreement() {
  const auto initiator = norr::generate_keypair();
  const auto responder = norr::generate_keypair();
  NORR_CHECK(initiator.has_value() && responder.has_value());

  const auto from_initiator = norr::x25519(initiator->private_key, responder->public_key);
  const auto from_responder = norr::x25519(responder->private_key, initiator->public_key);
  NORR_CHECK(from_initiator.has_value() && from_responder.has_value());
  NORR_CHECK(norr::constant_time_equal(*from_initiator, *from_responder));

  const auto stranger = norr::generate_keypair();
  NORR_CHECK(stranger.has_value());
  const auto wrong = norr::x25519(stranger->private_key, responder->public_key);
  NORR_CHECK(wrong.has_value());
  NORR_CHECK(!norr::constant_time_equal(*wrong, *from_initiator));

  const auto rederived = norr::derive_public_key(initiator->private_key);
  NORR_CHECK(rederived.has_value());
  NORR_CHECK(norr::constant_time_equal(*rederived, initiator->public_key));

  NORR_CHECK(!norr::constant_time_equal(initiator->public_key, responder->public_key));

  {
    norr::PublicKey all_zero{};
    const auto refused = norr::x25519(initiator->private_key, all_zero);
    NORR_CHECK(!refused.has_value() && refused.error() == norr::CryptoError::weak_public_key);
  }

  std::puts("crypto: X25519 key agreement OK");
}

void test_aead() {
  const auto secret = as_bytes("handshake secret material");
  const auto key = norr::derive_traffic_key(secret, norr::kDataLabel,
                                            norr::KeyDirection::initiator_to_responder, 0);
  NORR_CHECK(key.has_value());
  const norr::TrafficKeys keys{*key, 0};

  const auto plaintext = as_bytes("inner IP packet contents");
  const auto associated = as_bytes("norr header as AAD");

  std::vector<std::byte> ciphertext(plaintext.size() + norr::kAeadTagSize);
  const auto sealed = keys.seal(1, associated, plaintext, ciphertext);
  NORR_CHECK(sealed.has_value() && *sealed == ciphertext.size());

  NORR_CHECK(!norr::constant_time_equal(std::span{ciphertext}.first(plaintext.size()), plaintext));

  std::vector<std::byte> recovered(plaintext.size());
  const auto opened = keys.open(1, associated, ciphertext, recovered);
  NORR_CHECK(opened.has_value() && *opened == plaintext.size());
  NORR_CHECK(norr::constant_time_equal(recovered, plaintext));

  {
    std::vector<std::byte> out(plaintext.size());
    const auto wrong_counter = keys.open(2, associated, ciphertext, out);
    NORR_CHECK(!wrong_counter.has_value());
    NORR_CHECK(wrong_counter.error() == norr::CryptoError::authentication_failed);
  }

  {
    std::vector<std::byte> out(plaintext.size());
    const auto tampered = keys.open(1, as_bytes("norr header as AAE"), ciphertext, out);
    NORR_CHECK(!tampered.has_value());
    NORR_CHECK(tampered.error() == norr::CryptoError::authentication_failed);
  }

  {
    auto corrupted = ciphertext;
    corrupted[0] ^= std::byte{0x01};
    std::vector<std::byte> out(plaintext.size());
    const auto result = keys.open(1, associated, corrupted, out);
    NORR_CHECK(!result.has_value() && result.error() == norr::CryptoError::authentication_failed);
  }

  {
    auto corrupted = ciphertext;
    corrupted.back() ^= std::byte{0x80};
    std::vector<std::byte> out(plaintext.size());
    const auto result = keys.open(1, associated, corrupted, out);
    NORR_CHECK(!result.has_value() && result.error() == norr::CryptoError::authentication_failed);
  }

  {
    std::vector<std::byte> out(plaintext.size());
    const std::array<std::byte, 4> stub{};
    const auto result = keys.open(1, associated, stub, out);
    NORR_CHECK(!result.has_value() && result.error() == norr::CryptoError::authentication_failed);
  }

  {
    std::array<std::byte, 4> tiny{};
    const auto result = keys.seal(1, associated, plaintext, tiny);
    NORR_CHECK(!result.has_value() && result.error() == norr::CryptoError::buffer_too_small);
  }

  std::puts("crypto: ChaCha20-Poly1305 seal/open OK");
}

void test_key_separation() {
  const auto secret = as_bytes("one handshake secret");

  const auto send = norr::derive_traffic_key(secret, norr::kDataLabel,
                                             norr::KeyDirection::initiator_to_responder, 0);
  const auto receive = norr::derive_traffic_key(secret, norr::kDataLabel,
                                                norr::KeyDirection::responder_to_initiator, 0);
  const auto control = norr::derive_traffic_key(secret, norr::kControlLabel,
                                                norr::KeyDirection::initiator_to_responder, 0);
  const auto next_generation = norr::derive_traffic_key(
      secret, norr::kDataLabel, norr::KeyDirection::initiator_to_responder, 1);
  NORR_CHECK(send.has_value() && receive.has_value() && control.has_value() &&
         next_generation.has_value());

  NORR_CHECK(!norr::constant_time_equal(*send, *receive));
  NORR_CHECK(!norr::constant_time_equal(*send, *control));
  NORR_CHECK(!norr::constant_time_equal(*send, *next_generation));
  NORR_CHECK(!norr::constant_time_equal(*receive, *control));

  const auto again = norr::derive_traffic_key(secret, norr::kDataLabel,
                                              norr::KeyDirection::initiator_to_responder, 0);
  NORR_CHECK(again.has_value() && norr::constant_time_equal(*send, *again));

  {
    const norr::TrafficKeys sender{*send, 0};
    const norr::TrafficKeys receiver{*receive, 0};
    const auto plaintext = as_bytes("directional");
    std::vector<std::byte> ciphertext(plaintext.size() + norr::kAeadTagSize);
    NORR_CHECK(sender.seal(7, {}, plaintext, ciphertext).has_value());

    std::vector<std::byte> out(plaintext.size());
    const auto crossed = receiver.open(7, {}, ciphertext, out);
    NORR_CHECK(!crossed.has_value());
  }

  std::puts("crypto: key separation OK");
}

void test_counter_domain() {
  const auto secret = as_bytes("counter domain secret");
  const auto key = norr::derive_traffic_key(secret, norr::kDataLabel,
                                            norr::KeyDirection::initiator_to_responder, 0);
  NORR_CHECK(key.has_value());
  const norr::TrafficKeys keys{*key, 0};

  const auto plaintext = as_bytes("same plaintext");

  std::vector<std::byte> first(plaintext.size() + norr::kAeadTagSize);
  std::vector<std::byte> second(plaintext.size() + norr::kAeadTagSize);
  NORR_CHECK(keys.seal(0, {}, plaintext, first).has_value());
  NORR_CHECK(keys.seal(1, {}, plaintext, second).has_value());
  NORR_CHECK(!norr::constant_time_equal(first, second));

  std::vector<std::byte> extreme(plaintext.size() + norr::kAeadTagSize);
  NORR_CHECK(keys.seal(UINT64_MAX, {}, plaintext, extreme).has_value());
  std::vector<std::byte> out(plaintext.size());
  NORR_CHECK(keys.open(UINT64_MAX, {}, extreme, out).has_value());

  std::puts("crypto: counter nonce domain OK");
}

void test_published_vectors() {
  std::vector<std::byte> secret(32);
  for (std::size_t index = 0; index < secret.size(); ++index) {
    secret[index] = static_cast<std::byte>(index);
  }

  const auto to_hex = [](std::span<const std::byte> bytes) {
    constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (const auto byte : bytes) {
      const auto value = static_cast<std::uint8_t>(byte);
      out.push_back(kDigits[value >> 4U]);
      out.push_back(kDigits[value & 0x0FU]);
    }
    return out;
  };

  const auto i2r = norr::derive_traffic_key(secret, norr::kDataLabel,
                                            norr::KeyDirection::initiator_to_responder, 0);
  const auto r2i = norr::derive_traffic_key(secret, norr::kDataLabel,
                                            norr::KeyDirection::responder_to_initiator, 0);
  const auto control = norr::derive_traffic_key(secret, norr::kControlLabel,
                                                norr::KeyDirection::initiator_to_responder, 0);
  const auto generation_one = norr::derive_traffic_key(
      secret, norr::kDataLabel, norr::KeyDirection::initiator_to_responder, 1);
  NORR_CHECK(i2r && r2i && control && generation_one);

  NORR_CHECK(to_hex(*i2r) == "88501a443117eeb3125bbe4a8b2aac054ba0e829940c93c296a9455ea3f558fd");
  NORR_CHECK(to_hex(*r2i) == "747ddf7f38e51f40010e0026bf894c2de76ee33a3798299eb8f7c07deb049a57");
  NORR_CHECK(to_hex(*control) == "4c6adeb2f7332858e3cf89e7073788472f753a76ea3fc20784e1bda156f743d7");
  NORR_CHECK(to_hex(*generation_one) ==
         "a8e22da099129402d0ed8db62383fca77fd63c013f51ba82490e70540c212f13");

  const std::array<std::byte, 16> aad{
      std::byte{0x11}, std::byte{0x00}, std::byte{0xbe}, std::byte{0xef},
      std::byte{0x00}, std::byte{0x10}, std::byte{0x01}, std::byte{0x02},
      std::byte{0x03}, std::byte{0x04}, std::byte{0x05}, std::byte{0x06},
      std::byte{0x07}, std::byte{0x08}, std::byte{0x00}, std::byte{0x03}};
  const std::array<std::byte, 3> plaintext{std::byte{0x10}, std::byte{0x20}, std::byte{0x30}};

  const norr::TrafficKeys keys{*i2r, 0};
  std::array<std::byte, 3 + norr::kAeadTagSize> sealed{};
  NORR_CHECK(keys.seal(0x0102030405060708ULL, aad, plaintext, sealed).has_value());
  NORR_CHECK(to_hex(sealed) == "24b3ea4bcfc187c79917fb6832b24c966c53cb");

  std::array<std::byte, 3 + norr::kAeadTagSize> at_zero{};
  NORR_CHECK(keys.seal(0, aad, plaintext, at_zero).has_value());
  NORR_CHECK(to_hex(at_zero) == "8d31046a718c49f358b3ab7baab133db62d6a1");

  std::puts("crypto: published vectors OK");
}

void test_randomness() {
  std::array<std::byte, 32> first{};
  std::array<std::byte, 32> second{};
  NORR_CHECK(norr::random_bytes(first).has_value());
  NORR_CHECK(norr::random_bytes(second).has_value());

  NORR_CHECK(!norr::constant_time_equal(first, second));

  std::puts("crypto: random source OK");
}
}

int main() {
  if (!norr::crypto_available()) {
    test_unavailable();
    return 0;
  }

  NORR_CHECK(norr::crypto_init().has_value());

  NORR_CHECK(norr::crypto_init().has_value());

  test_published_vectors();
  test_randomness();
  test_key_agreement();
  test_aead();
  test_key_separation();
  test_counter_domain();
  return 0;
}
