// Feeds untrusted bytes to the responder's first handshake step, which is the
// one an unauthenticated peer can reach.
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "norr/noise.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (!norr::crypto_available()) return 0;
  static const bool initialised = norr::crypto_init().has_value();
  if (!initialised) return 0;

  // A fixed responder identity, so the fuzzer explores message parsing rather
  // than key generation.
  static const norr::KeyPair responder = [] {
    const auto pair = norr::generate_keypair();
    return pair.has_value() ? *pair : norr::KeyPair{};
  }();

  norr::PresharedKey psk{};
  auto handshake = norr::NoiseHandshake::create(norr::HandshakeRole::responder, responder,
                                                norr::PublicKey{}, psk);
  if (!handshake.has_value()) return 0;

  const auto message = std::span{reinterpret_cast<const std::byte*>(data), size};
  std::vector<std::byte> payload(size + 64);
  static_cast<void>(handshake->read_message_1(message, payload));
  return 0;
}
