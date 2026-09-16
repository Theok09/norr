// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#pragma once

#include <cstdint>

#include "norr/ip_packet.hpp"

namespace norr {
struct FlowKey {
  Address source;
  Address destination;
  std::uint16_t source_port{};
  std::uint16_t destination_port{};
  std::uint8_t protocol{};

  friend bool operator==(const FlowKey&, const FlowKey&) noexcept = default;
};

inline constexpr std::uint8_t kProtocolTcp = 6;
inline constexpr std::uint8_t kProtocolUdp = 17;

[[nodiscard]] FlowKey flow_key_of(const IpPacketView& packet,
                                  std::span<const std::byte> frame) noexcept;

[[nodiscard]] std::uint64_t hash_flow(const FlowKey& key) noexcept;

[[nodiscard]] inline std::size_t worker_for(const FlowKey& key, std::size_t worker_count) noexcept {
  if (worker_count <= 1) return 0;
  return static_cast<std::size_t>(hash_flow(key) % worker_count);
}

}
