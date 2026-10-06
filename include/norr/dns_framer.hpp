// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <vector>

namespace norr {
inline constexpr std::size_t kDnsHeaderSize = 12;
inline constexpr std::size_t kDnsQuestionTrailerSize = 4;
inline constexpr std::size_t kDnsPayloadLengthSize = 2;
inline constexpr std::size_t kDnsLabelMaxSize = 63;
inline constexpr std::uint16_t kDnsTypeTxt = 0x0010;
inline constexpr std::uint16_t kDnsClassIn = 0x0001;
inline constexpr std::uint16_t kDnsFlagsQuery = 0x0100;
inline constexpr std::uint16_t kDnsFlagsResponse = 0x8180;

enum class DnsFramerError {
  payload_too_large,
  buffer_too_small,
  malformed,
};

enum class DnsRole : std::uint8_t { client, server };

class DnsFramer {
 public:
  void configure(DnsRole role, std::string domain);

  [[nodiscard]] DnsRole role() const noexcept { return role_; }

  [[nodiscard]] std::size_t envelope_size() const noexcept {
    return kDnsHeaderSize + qname_.size() + kDnsQuestionTrailerSize + kDnsPayloadLengthSize;
  }

  [[nodiscard]] std::size_t max_payload(std::size_t datagram_size) const noexcept {
    const auto env = envelope_size();
    return env < datagram_size ? datagram_size - env : 0;
  }

  [[nodiscard]] std::expected<std::size_t, DnsFramerError> wrap(
      std::span<const std::byte> payload, std::span<std::byte> out) noexcept;

  [[nodiscard]] std::expected<std::size_t, DnsFramerError> unwrap(
      std::span<const std::byte> wire, std::span<std::byte> out) const noexcept;

 private:
  DnsRole role_{DnsRole::client};
  std::vector<std::byte> qname_{};
  std::uint16_t id_{};
};
}
