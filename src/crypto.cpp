// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#include "norr/crypto.hpp"

#include <algorithm>
#include <cstring>

#include "norr/blake2s.hpp"

#if defined(NORR_HAVE_LIBSODIUM)
#include <sodium.h>
#endif

namespace norr {
namespace {
#if defined(NORR_HAVE_LIBSODIUM)

[[nodiscard]] std::array<std::byte, kAeadNonceSize> aead_nonce(std::uint64_t counter) noexcept {
  std::array<std::byte, kAeadNonceSize> nonce{};
  for (std::size_t index = 0; index < 8; ++index) {
    nonce[4 + index] = static_cast<std::byte>(counter >> static_cast<unsigned>(index * 8U));
  }
  return nonce;
}
#endif

}

bool crypto_available() noexcept {
#if defined(NORR_HAVE_LIBSODIUM)
  return true;
#else
  return false;
#endif
}

void secure_zero(std::span<std::byte> buffer) noexcept {
#if defined(NORR_HAVE_LIBSODIUM)
  if (!buffer.empty()) sodium_memzero(buffer.data(), buffer.size());
#else

  volatile auto* pointer = reinterpret_cast<volatile unsigned char*>(buffer.data());
  for (std::size_t index = 0; index < buffer.size(); ++index) pointer[index] = 0;
#endif
}

TrafficKeys::~TrafficKeys() { secure_zero(key_); }

TrafficKeys::TrafficKeys(TrafficKeys&& other) noexcept
    : key_(other.key_), generation_(other.generation_) {
  secure_zero(other.key_);
  other.generation_ = 0;
}

TrafficKeys& TrafficKeys::operator=(TrafficKeys&& other) noexcept {
  if (this != &other) {
    secure_zero(key_);
    key_ = other.key_;
    generation_ = other.generation_;
    secure_zero(other.key_);
    other.generation_ = 0;
  }
  return *this;
}

std::expected<TrafficKey, CryptoError> derive_traffic_key(std::span<const std::byte> handshake_secret,
                                                          std::string_view domain,
                                                          KeyDirection direction,
                                                          KeyGeneration generation) noexcept {
  const auto label = make_key_label(domain, direction, generation);
  if (!label) return std::unexpected(CryptoError::invalid_key_length);

  TrafficKey key{};
  if (!hkdf_expand(handshake_secret, label->view(), key)) {
    return std::unexpected(CryptoError::invalid_key_length);
  }
  return key;
}

#if !defined(NORR_HAVE_LIBSODIUM)

std::expected<void, CryptoError> crypto_init() noexcept {
  return std::unexpected(CryptoError::unsupported_platform);
}

std::expected<void, CryptoError> random_bytes(std::span<std::byte>) noexcept {
  return std::unexpected(CryptoError::unsupported_platform);
}

std::expected<KeyPair, CryptoError> generate_keypair() noexcept {
  return std::unexpected(CryptoError::unsupported_platform);
}

std::expected<PublicKey, CryptoError> derive_public_key(const PrivateKey&) noexcept {
  return std::unexpected(CryptoError::unsupported_platform);
}

std::expected<SharedSecret, CryptoError> x25519(const PrivateKey&, const PublicKey&) noexcept {
  return std::unexpected(CryptoError::unsupported_platform);
}

bool constant_time_equal(std::span<const std::byte> left,
                         std::span<const std::byte> right) noexcept {
  if (left.size() != right.size()) return false;
  unsigned char difference = 0;
  for (std::size_t index = 0; index < left.size(); ++index) {
    difference = static_cast<unsigned char>(
        difference | (static_cast<unsigned char>(left[index]) ^
                      static_cast<unsigned char>(right[index])));
  }
  return difference == 0;
}

std::expected<std::size_t, CryptoError> TrafficKeys::seal(std::uint64_t, std::span<const std::byte>,
                                                          std::span<const std::byte>,
                                                          std::span<std::byte>) const noexcept {
  return std::unexpected(CryptoError::unsupported_platform);
}

std::expected<std::size_t, CryptoError> TrafficKeys::open(std::uint64_t, std::span<const std::byte>,
                                                          std::span<const std::byte>,
                                                          std::span<std::byte>) const noexcept {
  return std::unexpected(CryptoError::unsupported_platform);
}

#else

std::expected<void, CryptoError> crypto_init() noexcept {
  if (sodium_init() < 0) return std::unexpected(CryptoError::initialisation_failed);
  return {};
}

std::expected<void, CryptoError> random_bytes(std::span<std::byte> out) noexcept {
  if (out.empty()) return {};
  randombytes_buf(out.data(), out.size());
  return {};
}

std::expected<PublicKey, CryptoError> derive_public_key(const PrivateKey& private_key) noexcept {
  PublicKey public_key{};
  if (crypto_scalarmult_curve25519_base(
          reinterpret_cast<unsigned char*>(public_key.data()),
          reinterpret_cast<const unsigned char*>(private_key.data())) != 0) {
    return std::unexpected(CryptoError::invalid_key_length);
  }
  return public_key;
}

std::expected<KeyPair, CryptoError> generate_keypair() noexcept {
  KeyPair pair{};
  randombytes_buf(pair.private_key.data(), pair.private_key.size());
  const auto public_key = derive_public_key(pair.private_key);
  if (!public_key) {
    secure_zero(pair.private_key);
    return std::unexpected(public_key.error());
  }
  pair.public_key = *public_key;
  return pair;
}

std::expected<SharedSecret, CryptoError> x25519(const PrivateKey& private_key,
                                                const PublicKey& peer_public) noexcept {
  SharedSecret secret{};

  if (crypto_scalarmult_curve25519(
          reinterpret_cast<unsigned char*>(secret.data()),
          reinterpret_cast<const unsigned char*>(private_key.data()),
          reinterpret_cast<const unsigned char*>(peer_public.data())) != 0) {
    secure_zero(secret);
    return std::unexpected(CryptoError::weak_public_key);
  }
  return secret;
}

bool constant_time_equal(std::span<const std::byte> left,
                         std::span<const std::byte> right) noexcept {
  if (left.size() != right.size()) return false;
  if (left.empty()) return true;
  return sodium_memcmp(left.data(), right.data(), left.size()) == 0;
}

std::expected<std::size_t, CryptoError> TrafficKeys::seal(
    std::uint64_t counter, std::span<const std::byte> associated_data,
    std::span<const std::byte> plaintext, std::span<std::byte> out) const noexcept {
  if (out.size() < plaintext.size() + kAeadTagSize) {
    return std::unexpected(CryptoError::buffer_too_small);
  }

  const auto nonce = aead_nonce(counter);
  unsigned long long written = 0;
  if (crypto_aead_chacha20poly1305_ietf_encrypt(
          reinterpret_cast<unsigned char*>(out.data()), &written,
          reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size(),
          reinterpret_cast<const unsigned char*>(associated_data.data()), associated_data.size(),
          nullptr, reinterpret_cast<const unsigned char*>(nonce.data()),
          reinterpret_cast<const unsigned char*>(key_.data())) != 0) {
    return std::unexpected(CryptoError::authentication_failed);
  }
  return static_cast<std::size_t>(written);
}

std::expected<std::size_t, CryptoError> TrafficKeys::open(
    std::uint64_t counter, std::span<const std::byte> associated_data,
    std::span<const std::byte> ciphertext, std::span<std::byte> out) const noexcept {
  if (ciphertext.size() < kAeadTagSize) return std::unexpected(CryptoError::authentication_failed);
  if (out.size() < ciphertext.size() - kAeadTagSize) {
    return std::unexpected(CryptoError::buffer_too_small);
  }

  const auto nonce = aead_nonce(counter);
  unsigned long long written = 0;
  if (crypto_aead_chacha20poly1305_ietf_decrypt(
          reinterpret_cast<unsigned char*>(out.data()), &written, nullptr,
          reinterpret_cast<const unsigned char*>(ciphertext.data()), ciphertext.size(),
          reinterpret_cast<const unsigned char*>(associated_data.data()), associated_data.size(),
          reinterpret_cast<const unsigned char*>(nonce.data()),
          reinterpret_cast<const unsigned char*>(key_.data())) != 0) {
    secure_zero(out.first(std::min(out.size(), ciphertext.size())));
    return std::unexpected(CryptoError::authentication_failed);
  }
  return static_cast<std::size_t>(written);
}

#endif

}
