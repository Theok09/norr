// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string_view>

#include "norr/blake2s.hpp"
#include "norr/crypto.hpp"
#include "norr/noise.hpp"
#include "norr/packet.hpp"

namespace norr {
inline constexpr std::size_t kObfuscationKeySize = 32;
inline constexpr std::size_t kObfuscationNonceSize = 8;
inline constexpr std::size_t kObfuscationOverhead = kObfuscationNonceSize;
inline constexpr std::size_t kMaximumJunkLength = 255;
inline constexpr std::size_t kJunkLengthFieldSize = 1;
inline constexpr std::size_t kPrimingMinPackets = 3;
inline constexpr std::size_t kPrimingMaxPackets = 7;
inline constexpr std::size_t kPrimingMinSize = 40;
inline constexpr std::size_t kPrimingMaxSize = 576;

using ObfuscationKey = std::array<std::byte, kObfuscationKeySize>;

enum class ObfuscationError {
  disabled,
  buffer_too_small,
  invalid_nonce,
  decryption_failed,
  malformed,
  junk_overflow,
};

[[nodiscard]] constexpr std::string_view obfuscation_error_message(
    ObfuscationError error) noexcept {
  switch (error) {
    case ObfuscationError::disabled: return "obfuscation not enabled";
    case ObfuscationError::buffer_too_small: return "output buffer too small";
    case ObfuscationError::invalid_nonce: return "invalid obfuscation nonce";
    case ObfuscationError::decryption_failed: return "obfuscation unwrap failed";
    case ObfuscationError::malformed: return "malformed obfuscated packet";
    case ObfuscationError::junk_overflow: return "junk length exceeds packet";
  }
  return "unknown obfuscation error";
}

enum class ObfuscationMode : std::uint8_t {
  off,
  header_mask,
  full,
};

[[nodiscard]] constexpr std::string_view obfuscation_mode_name(
    ObfuscationMode mode) noexcept {
  switch (mode) {
    case ObfuscationMode::off: return "off";
    case ObfuscationMode::header_mask: return "header-mask";
    case ObfuscationMode::full: return "full";
  }
  return "unknown";
}

struct ObfuscationConfig {
  ObfuscationMode mode{ObfuscationMode::off};
  bool junk_padding{false};
  bool priming{false};
  std::uint8_t junk_max{64};
};

[[nodiscard]] ObfuscationKey derive_obfuscation_key(
    const PresharedKey& preshared) noexcept;

class Obfuscator {
 public:
  Obfuscator() = default;

  void configure(const ObfuscationConfig& config,
                 const PresharedKey& preshared) noexcept;

  [[nodiscard]] bool enabled() const noexcept {
    return config_.mode != ObfuscationMode::off;
  }
  [[nodiscard]] const ObfuscationConfig& config() const noexcept {
    return config_;
  }

  [[nodiscard]] std::expected<std::size_t, ObfuscationError> wrap(
      std::span<const std::byte> plaintext,
      std::span<std::byte> out) noexcept;

  [[nodiscard]] std::expected<std::size_t, ObfuscationError> unwrap(
      std::span<const std::byte> wire,
      std::span<std::byte> out) noexcept;

  [[nodiscard]] std::size_t max_overhead() const noexcept;

  [[nodiscard]] std::expected<std::size_t, ObfuscationError> generate_priming(
      std::span<std::byte> out) noexcept;

 private:
  [[nodiscard]] bool mask(std::span<const std::byte> nonce,
                          std::span<std::byte> region) const noexcept;

  void next_nonce(std::span<std::byte> out) noexcept;

  ObfuscationConfig config_{};
  ObfuscationKey key_{};
  std::uint64_t nonce_counter_{};
};
}
