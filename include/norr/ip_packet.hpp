// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>

#include "norr/address.hpp"
#include "norr/error.hpp"

namespace norr {
inline constexpr std::size_t kIpv4HeaderSize = 20;
inline constexpr std::size_t kIpv6HeaderSize = 40;

inline constexpr std::uint16_t kMinimumIpv6Mtu = 1280;

struct IpPacketView {
  AddressFamily family{};
  Address source;
  Address destination;
  std::uint8_t protocol{};
  std::uint8_t hop_limit{};
  std::size_t header_length{};
  std::size_t total_length{};
};

[[nodiscard]] std::expected<IpPacketView, Error> parse_ip_packet(
    std::span<const std::byte> bytes) noexcept;

// The length an IP header declares, without validating the rest of the packet.
//
// A padded buffer is longer than the packet it carries, and `parse_ip_packet`
// requires the declared length to match the span exactly. This reads just
// enough to trim the padding off first.
[[nodiscard]] std::optional<std::size_t> declared_ip_length(
    std::span<const std::byte> bytes) noexcept;

[[nodiscard]] bool is_multicast(const Address& address) noexcept;
[[nodiscard]] bool is_unspecified(const Address& address) noexcept;
[[nodiscard]] bool is_loopback(const Address& address) noexcept;

}
