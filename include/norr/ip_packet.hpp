#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
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

[[nodiscard]] bool is_multicast(const Address& address) noexcept;
[[nodiscard]] bool is_unspecified(const Address& address) noexcept;
[[nodiscard]] bool is_loopback(const Address& address) noexcept;

}
