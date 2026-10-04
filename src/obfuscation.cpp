// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#include "norr/obfuscation.hpp"

#include <algorithm>
#include <array>
#include <vector>

namespace norr {
namespace {
constexpr std::string_view kObfuscationDomain = "norr-obfuscation-v1";
}

ObfuscationKey derive_obfuscation_key(const PresharedKey& preshared) noexcept {
  const auto domain = std::as_bytes(std::span{kObfuscationDomain});
  const auto digest = Blake2s::hash(domain, preshared);
  ObfuscationKey key{};
  std::copy(digest.begin(), digest.end(), key.begin());
  return key;
}

void Obfuscator::configure(const ObfuscationConfig& config,
                           const PresharedKey& preshared) noexcept {
  config_ = config;
  key_ = derive_obfuscation_key(preshared);

  std::array<std::byte, sizeof(std::uint64_t)> seed{};
  if (!random_bytes(seed)) seed = {};
  nonce_counter_ = 0;
  for (const auto byte : seed) {
    nonce_counter_ = (nonce_counter_ << 8U) | static_cast<std::uint64_t>(byte);
  }

  junk_pos_ = sizeof(junk_pool_);
  junk_ready_ = config_.junk_padding && config_.junk_max > 0;
}

std::byte Obfuscator::next_junk_byte() noexcept {
  if (junk_pos_ >= junk_pool_.size()) {
    if (!random_bytes(junk_pool_)) {
      junk_ready_ = false;
      return std::byte{0};
    }
    junk_pos_ = 0;
  }
  return junk_pool_[junk_pos_++];
}

void Obfuscator::next_nonce(std::span<std::byte> out) noexcept {
  if (random_bytes(out.first(kObfuscationNonceSize))) return;
  const auto value = nonce_counter_++;
  for (std::size_t index = 0; index < kObfuscationNonceSize; ++index) {
    out[index] = static_cast<std::byte>((value >> (8U * (7U - index))) & 0xFFU);
  }
}

bool Obfuscator::mask(std::span<const std::byte> nonce,
                      std::span<std::byte> region) const noexcept {
  return keystream_xor(key_, nonce, region).has_value();
}

std::size_t Obfuscator::max_overhead() const noexcept {
  if (config_.mode == ObfuscationMode::off) return 0;
  std::size_t overhead = kObfuscationNonceSize;
  if (config_.mode == ObfuscationMode::full) {
    overhead += kJunkLengthFieldSize;
    if (config_.junk_padding) overhead += config_.junk_max;
  }
  return overhead;
}

std::expected<std::size_t, ObfuscationError> Obfuscator::wrap(
    std::span<const std::byte> plaintext, std::span<std::byte> out) noexcept {
  if (config_.mode == ObfuscationMode::off) return std::unexpected(ObfuscationError::disabled);

  std::array<std::byte, kObfuscationNonceSize> nonce{};
  next_nonce(nonce);

  if (out.size() < kObfuscationNonceSize) return std::unexpected(ObfuscationError::buffer_too_small);
  std::copy(nonce.begin(), nonce.end(), out.begin());
  const auto region = out.subspan(kObfuscationNonceSize);

  if (config_.mode == ObfuscationMode::header_mask) {
    if (region.size() < plaintext.size()) {
      return std::unexpected(ObfuscationError::buffer_too_small);
    }
    std::copy(plaintext.begin(), plaintext.end(), region.begin());
    const auto mask_length = std::min<std::size_t>(kPacketHeaderSize, plaintext.size());
    if (!mask(nonce, region.first(mask_length))) {
      return std::unexpected(ObfuscationError::decryption_failed);
    }
    return kObfuscationNonceSize + plaintext.size();
  }

  std::size_t junk_length = 0;
  if (config_.junk_padding && config_.junk_max > 0 && junk_ready_) {
    std::uint32_t entropy = 0;
    for (int b = 0; b < 4; ++b) {
      entropy = (entropy << 8U) | static_cast<std::uint32_t>(next_junk_byte());
    }
    if (junk_ready_) {
      const std::size_t cap = config_.junk_max;
      const std::size_t bucket = config_.length_bucket == 0 ? 1U : config_.length_bucket;
      const std::size_t base_len = kJunkLengthFieldSize + plaintext.size();
      const std::size_t to_bucket = (bucket - (base_len % bucket)) % bucket;
      const std::size_t floor = to_bucket <= cap ? to_bucket : 0U;
      const std::size_t span = cap - floor + 1U;
      junk_length = floor + static_cast<std::size_t>(entropy % span);
    }
  }

  const auto body = kJunkLengthFieldSize + junk_length + plaintext.size();
  if (region.size() < body) return std::unexpected(ObfuscationError::buffer_too_small);

  region[0] = static_cast<std::byte>(junk_length);
  for (std::size_t i = 0; i < junk_length; ++i) {
    region[kJunkLengthFieldSize + i] = next_junk_byte();
  }
  std::copy(plaintext.begin(), plaintext.end(),
            region.begin() + static_cast<std::ptrdiff_t>(kJunkLengthFieldSize + junk_length));

  if (!mask(nonce, region.first(body))) {
    return std::unexpected(ObfuscationError::decryption_failed);
  }
  return kObfuscationNonceSize + body;
}

std::expected<std::size_t, ObfuscationError> Obfuscator::unwrap(
    std::span<const std::byte> wire, std::span<std::byte> out) noexcept {
  if (config_.mode == ObfuscationMode::off) return std::unexpected(ObfuscationError::disabled);
  if (wire.size() < kObfuscationNonceSize) return std::unexpected(ObfuscationError::malformed);

  const auto nonce = wire.first(kObfuscationNonceSize);
  const auto region = wire.subspan(kObfuscationNonceSize);

  if (config_.mode == ObfuscationMode::header_mask) {
    if (out.size() < region.size()) return std::unexpected(ObfuscationError::buffer_too_small);
    std::copy(region.begin(), region.end(), out.begin());
    const auto mask_length = std::min<std::size_t>(kPacketHeaderSize, region.size());
    if (!mask(nonce, std::span{out}.first(mask_length))) {
      return std::unexpected(ObfuscationError::decryption_failed);
    }
    return region.size();
  }

  if (region.empty()) return std::unexpected(ObfuscationError::malformed);

  unwrap_scratch_.assign(region.begin(), region.end());
  auto& plain = unwrap_scratch_;
  if (!mask(nonce, plain)) return std::unexpected(ObfuscationError::decryption_failed);

  const auto junk_length = static_cast<std::size_t>(plain[0]);
  if (kJunkLengthFieldSize + junk_length > plain.size()) {
    return std::unexpected(ObfuscationError::junk_overflow);
  }
  const auto payload_length = plain.size() - kJunkLengthFieldSize - junk_length;
  if (out.size() < payload_length) return std::unexpected(ObfuscationError::buffer_too_small);
  std::copy(plain.begin() + static_cast<std::ptrdiff_t>(kJunkLengthFieldSize + junk_length),
            plain.end(), out.begin());
  return payload_length;
}

std::expected<std::size_t, ObfuscationError> Obfuscator::generate_priming(
    std::span<std::byte> out) noexcept {
  std::array<std::byte, 2> pick{};
  if (!random_bytes(pick)) return std::unexpected(ObfuscationError::invalid_nonce);
  const auto span = kPrimingMaxSize - kPrimingMinSize;
  const auto size = kPrimingMinSize +
                    (static_cast<std::size_t>(static_cast<std::uint8_t>(pick[0])) << 8U |
                     static_cast<std::size_t>(static_cast<std::uint8_t>(pick[1]))) %
                        (span + 1U);
  if (out.size() < size) return std::unexpected(ObfuscationError::buffer_too_small);
  if (!random_bytes(out.first(size))) return std::unexpected(ObfuscationError::invalid_nonce);
  return size;
}
}
