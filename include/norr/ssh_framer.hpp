// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string_view>

namespace norr {
inline constexpr std::string_view kSshClientBanner =
    "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n";
inline constexpr std::string_view kSshServerBanner =
    "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n";

inline constexpr std::size_t kSshHeaderSize = 5;
inline constexpr std::size_t kSshBlockSize = 8;
inline constexpr std::size_t kSshMinPadding = 4;
inline constexpr std::size_t kSshMaxBannerSize = 255;

enum class SshFramerError {
  payload_too_large,
  buffer_too_small,
  malformed,
  incomplete,
};

class SshFramer {
 public:
  [[nodiscard]] static std::size_t padding_for(std::size_t payload) noexcept;

  [[nodiscard]] static std::size_t record_size(std::size_t payload) noexcept {
    return sizeof(std::uint32_t) + 1 + payload + padding_for(payload);
  }

  [[nodiscard]] std::expected<std::size_t, SshFramerError> wrap(
      std::span<const std::byte> payload, std::span<std::byte> out) noexcept;

  [[nodiscard]] std::expected<std::size_t, SshFramerError> unwrap(
      std::span<const std::byte> wire, std::span<std::byte> out,
      std::size_t& consumed) const noexcept;
};
}
