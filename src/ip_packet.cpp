// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#include "norr/ip_packet.hpp"

#include <algorithm>

namespace norr {
namespace {
[[nodiscard]] constexpr std::uint16_t read_u16(std::span<const std::byte> bytes,
                                               std::size_t offset) noexcept {
  return static_cast<std::uint16_t>((static_cast<unsigned>(bytes[offset]) << 8U) |
                                    static_cast<unsigned>(bytes[offset + 1]));
}

[[nodiscard]] std::expected<IpPacketView, Error> parse_ipv4(
    std::span<const std::byte> bytes) noexcept {
  if (bytes.size() < kIpv4HeaderSize) return std::unexpected(Error::malformed_packet);

  const auto first = static_cast<std::uint8_t>(bytes[0]);
  const auto header_words = static_cast<std::size_t>(first & 0x0FU);
  const auto header_length = header_words * 4U;

  if (header_length < kIpv4HeaderSize || header_length > bytes.size()) {
    return std::unexpected(Error::malformed_packet);
  }

  const auto total_length = static_cast<std::size_t>(read_u16(bytes, 2));
  if (total_length < header_length) return std::unexpected(Error::malformed_packet);

  if (total_length != bytes.size()) return std::unexpected(Error::payload_length_mismatch);

  return IpPacketView{
      .family = AddressFamily::ipv4,
      .source = Address::from_bytes(AddressFamily::ipv4, bytes.subspan(12, 4)),
      .destination = Address::from_bytes(AddressFamily::ipv4, bytes.subspan(16, 4)),
      .protocol = static_cast<std::uint8_t>(bytes[9]),
      .hop_limit = static_cast<std::uint8_t>(bytes[8]),
      .header_length = header_length,
      .total_length = total_length,
  };
}

[[nodiscard]] std::expected<IpPacketView, Error> parse_ipv6(
    std::span<const std::byte> bytes) noexcept {
  if (bytes.size() < kIpv6HeaderSize) return std::unexpected(Error::malformed_packet);

  const auto payload_length = static_cast<std::size_t>(read_u16(bytes, 4));
  const auto total_length = kIpv6HeaderSize + payload_length;
  if (total_length != bytes.size()) return std::unexpected(Error::payload_length_mismatch);

  return IpPacketView{
      .family = AddressFamily::ipv6,
      .source = Address::from_bytes(AddressFamily::ipv6, bytes.subspan(8, 16)),
      .destination = Address::from_bytes(AddressFamily::ipv6, bytes.subspan(24, 16)),
      .protocol = static_cast<std::uint8_t>(bytes[6]),
      .hop_limit = static_cast<std::uint8_t>(bytes[7]),
      .header_length = kIpv6HeaderSize,
      .total_length = total_length,
  };
}

}

std::optional<std::size_t> declared_ip_length(std::span<const std::byte> bytes) noexcept {
  if (bytes.empty()) return std::nullopt;
  const auto version = static_cast<std::uint8_t>(bytes[0]) >> 4U;

  if (version == 4) {
    if (bytes.size() < kIpv4HeaderSize) return std::nullopt;
    const auto total = static_cast<std::size_t>(read_u16(bytes, 2));
    if (total < kIpv4HeaderSize) return std::nullopt;
    return total;
  }

  if (version == 6) {
    if (bytes.size() < kIpv6HeaderSize) return std::nullopt;
    return kIpv6HeaderSize + static_cast<std::size_t>(read_u16(bytes, 4));
  }

  return std::nullopt;
}

std::expected<IpPacketView, Error> parse_ip_packet(std::span<const std::byte> bytes) noexcept {
  if (bytes.empty()) return std::unexpected(Error::malformed_packet);

  const auto version = static_cast<std::uint8_t>(static_cast<std::uint8_t>(bytes[0]) >> 4U);
  switch (version) {
    case 4: return parse_ipv4(bytes);
    case 6: return parse_ipv6(bytes);
    default: return std::unexpected(Error::unsupported_version);
  }
}

bool is_multicast(const Address& address) noexcept {
  const auto octets = address.bytes();
  if (address.family() == AddressFamily::ipv4) {
    return (static_cast<std::uint8_t>(octets[0]) & 0xF0U) == 0xE0U;
  }

  return static_cast<std::uint8_t>(octets[0]) == 0xFFU;
}

bool is_unspecified(const Address& address) noexcept {
  const auto octets = address.bytes();
  return std::ranges::all_of(octets, [](std::byte octet) { return octet == std::byte{0}; });
}

bool is_loopback(const Address& address) noexcept {
  const auto octets = address.bytes();
  if (address.family() == AddressFamily::ipv4) {
    return static_cast<std::uint8_t>(octets[0]) == 127U;
  }

  for (std::size_t index = 0; index < 15; ++index) {
    if (octets[index] != std::byte{0}) return false;
  }
  return octets[15] == std::byte{1};
}

}
