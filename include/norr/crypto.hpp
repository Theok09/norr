#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string_view>

#include "norr/handshake.hpp"
#include "norr/key_schedule.hpp"

namespace norr {
enum class CryptoError {
  unsupported_platform,
  initialisation_failed,
  authentication_failed,
  buffer_too_small,
  invalid_key_length,
  invalid_nonce,
  counter_exhausted,
  weak_public_key,
};

[[nodiscard]] constexpr std::string_view crypto_error_message(CryptoError error) noexcept {
  switch (error) {
    case CryptoError::unsupported_platform: return "crypto backend not available in this build";
    case CryptoError::initialisation_failed: return "crypto backend initialisation failed";
    case CryptoError::authentication_failed: return "authentication failed";
    case CryptoError::buffer_too_small: return "output buffer too small";
    case CryptoError::invalid_key_length: return "invalid key length";
    case CryptoError::invalid_nonce: return "invalid nonce";
    case CryptoError::counter_exhausted: return "packet counter exhausted";
    case CryptoError::weak_public_key: return "peer public key rejected";
  }
  return "unknown crypto error";
}

inline constexpr std::size_t kPublicKeySize = 32;
inline constexpr std::size_t kPrivateKeySize = 32;
inline constexpr std::size_t kSharedSecretSize = 32;
inline constexpr std::size_t kAeadTagSize = 16;
inline constexpr std::size_t kAeadNonceSize = 12;

using PublicKey = std::array<std::byte, kPublicKeySize>;
using PrivateKey = std::array<std::byte, kPrivateKeySize>;
using SharedSecret = std::array<std::byte, kSharedSecretSize>;

struct KeyPair {
  PublicKey public_key{};
  PrivateKey private_key{};
};

[[nodiscard]] bool crypto_available() noexcept;

[[nodiscard]] std::expected<void, CryptoError> crypto_init() noexcept;

[[nodiscard]] std::expected<void, CryptoError> random_bytes(std::span<std::byte> out) noexcept;

[[nodiscard]] std::expected<KeyPair, CryptoError> generate_keypair() noexcept;

[[nodiscard]] std::expected<PublicKey, CryptoError> derive_public_key(
    const PrivateKey& private_key) noexcept;

[[nodiscard]] std::expected<SharedSecret, CryptoError> x25519(const PrivateKey& private_key,
                                                              const PublicKey& peer_public) noexcept;

[[nodiscard]] bool constant_time_equal(std::span<const std::byte> left,
                                       std::span<const std::byte> right) noexcept;

void secure_zero(std::span<std::byte> buffer) noexcept;

class TrafficKeys {
 public:
  TrafficKeys() = default;
  TrafficKeys(const TrafficKey& key, KeyGeneration generation) noexcept
      : key_(key), generation_(generation) {}

  ~TrafficKeys();

  TrafficKeys(const TrafficKeys&) = delete;
  TrafficKeys& operator=(const TrafficKeys&) = delete;
  TrafficKeys(TrafficKeys&&) noexcept;
  TrafficKeys& operator=(TrafficKeys&&) noexcept;

  [[nodiscard]] KeyGeneration generation() const noexcept { return generation_; }

  [[nodiscard]] std::expected<std::size_t, CryptoError> seal(
      std::uint64_t counter, std::span<const std::byte> associated_data,
      std::span<const std::byte> plaintext, std::span<std::byte> out) const noexcept;

  [[nodiscard]] std::expected<std::size_t, CryptoError> open(
      std::uint64_t counter, std::span<const std::byte> associated_data,
      std::span<const std::byte> ciphertext, std::span<std::byte> out) const noexcept;

 private:
  TrafficKey key_{};
  KeyGeneration generation_{};
};

[[nodiscard]] std::expected<TrafficKey, CryptoError> derive_traffic_key(
    std::span<const std::byte> handshake_secret, std::string_view domain, KeyDirection direction,
    KeyGeneration generation) noexcept;

}
