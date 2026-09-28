// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#include "norr/crypto.hpp"

#include <algorithm>
#include <array>
#include <cstring>

#include "norr/blake2s.hpp"

#if defined(NORR_HAVE_LIBSODIUM)
#include <sodium.h>
#endif

#if defined(NORR_HAVE_OPENSSL) && defined(NORR_HAVE_LIBSODIUM)
#include <openssl/evp.h>
#define NORR_AEAD_OPENSSL 1
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

#if defined(NORR_AEAD_OPENSSL)
class AeadContexts {
 public:
  AeadContexts() : cipher_(EVP_CIPHER_fetch(nullptr, "ChaCha20-Poly1305", nullptr)) {}

  AeadContexts(const AeadContexts&) = delete;
  AeadContexts& operator=(const AeadContexts&) = delete;

  ~AeadContexts() {
    for (auto& entry : entries_) {
      if (entry.context != nullptr) EVP_CIPHER_CTX_free(entry.context);
    }
    if (cipher_ != nullptr) EVP_CIPHER_free(cipher_);
  }

  EVP_CIPHER_CTX* get(const TrafficKey& key, bool encrypt) noexcept {
    if (cipher_ == nullptr) return nullptr;
    for (auto& entry : entries_) {
      if (entry.context != nullptr && entry.encrypt == encrypt && entry.key == key) return entry.context;
    }
    auto& victim = entries_[next_];
    next_ = (next_ + 1) % entries_.size();
    if (victim.context == nullptr) victim.context = EVP_CIPHER_CTX_new();
    if (victim.context == nullptr) return nullptr;
    if (EVP_CipherInit_ex(victim.context, cipher_, nullptr,
                          reinterpret_cast<const unsigned char*>(key.data()), nullptr,
                          encrypt ? 1 : 0) != 1) {
      victim.key = {};
      return nullptr;
    }
    victim.key = key;
    victim.encrypt = encrypt;
    return victim.context;
  }

 private:
  struct Entry {
    TrafficKey key{};
    bool encrypt{};
    EVP_CIPHER_CTX* context{};
  };

  EVP_CIPHER* cipher_{};
  std::array<Entry, 8> entries_{};
  std::size_t next_{};
};

AeadContexts& aead_contexts() {
  thread_local AeadContexts contexts;
  return contexts;
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
#if defined(NORR_AEAD_OPENSSL)
  if (auto* context = aead_contexts().get(key_, true); context != nullptr) {
    int length = 0;
    const auto* iv = reinterpret_cast<const unsigned char*>(nonce.data());
    auto* target = reinterpret_cast<unsigned char*>(out.data());
    const bool sealed =
        EVP_CipherInit_ex(context, nullptr, nullptr, nullptr, iv, 1) == 1 &&
        (associated_data.empty() ||
         EVP_CipherUpdate(context, nullptr, &length,
                          reinterpret_cast<const unsigned char*>(associated_data.data()),
                          static_cast<int>(associated_data.size())) == 1) &&
        EVP_CipherUpdate(context, target, &length,
                         reinterpret_cast<const unsigned char*>(plaintext.data()),
                         static_cast<int>(plaintext.size())) == 1 &&
        EVP_CipherFinal_ex(context, target + length, &length) == 1 &&
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_GET_TAG, static_cast<int>(kAeadTagSize),
                            target + plaintext.size()) == 1;
    if (!sealed) return std::unexpected(CryptoError::authentication_failed);
    return plaintext.size() + kAeadTagSize;
  }
#endif
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
#if defined(NORR_AEAD_OPENSSL)
  if (auto* context = aead_contexts().get(key_, false); context != nullptr) {
    const auto body = ciphertext.size() - kAeadTagSize;
    int length = 0;
    auto* target = reinterpret_cast<unsigned char*>(out.data());
    std::array<unsigned char, kAeadTagSize> tag{};
    std::memcpy(tag.data(), ciphertext.data() + body, kAeadTagSize);
    const bool opened =
        EVP_CipherInit_ex(context, nullptr, nullptr, nullptr,
                          reinterpret_cast<const unsigned char*>(nonce.data()), 0) == 1 &&
        (associated_data.empty() ||
         EVP_CipherUpdate(context, nullptr, &length,
                          reinterpret_cast<const unsigned char*>(associated_data.data()),
                          static_cast<int>(associated_data.size())) == 1) &&
        EVP_CipherUpdate(context, target, &length,
                         reinterpret_cast<const unsigned char*>(ciphertext.data()),
                         static_cast<int>(body)) == 1 &&
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_SET_TAG, static_cast<int>(kAeadTagSize),
                            tag.data()) == 1 &&
        EVP_CipherFinal_ex(context, target + length, &length) == 1;
    if (!opened) {
      secure_zero(out.first(std::min(out.size(), body)));
      return std::unexpected(CryptoError::authentication_failed);
    }
    return body;
  }
#endif
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
