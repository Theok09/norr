// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#include "norr/flow_hash.hpp"

#include <algorithm>

namespace norr {
namespace {
constexpr std::uint64_t kOffsetBasis = 1469598103934665603ULL;
constexpr std::uint64_t kPrime = 1099511628211ULL;

constexpr void mix(std::uint64_t& hash, std::uint64_t value) noexcept {
  hash ^= value;
  hash *= kPrime;
}

void mix_address(std::uint64_t& hash, const Address& address) noexcept {
  for (const auto octet : address.bytes()) {
    mix(hash, static_cast<std::uint64_t>(octet));
  }
}

[[nodiscard]] std::uint64_t hash_address(const Address& address) noexcept {
  std::uint64_t hash = kOffsetBasis;
  mix_address(hash, address);
  return hash;
}

}

FlowKey flow_key_of(const IpPacketView& packet, std::span<const std::byte> frame) noexcept {
  FlowKey key{
      .source = packet.source,
      .destination = packet.destination,
      .protocol = packet.protocol,
  };

  if (packet.protocol != kProtocolTcp && packet.protocol != kProtocolUdp) return key;
  if (frame.size() < packet.header_length + 4) return key;

  const auto transport = frame.subspan(packet.header_length);
  key.source_port = static_cast<std::uint16_t>((static_cast<unsigned>(transport[0]) << 8U) |
                                               static_cast<unsigned>(transport[1]));
  key.destination_port = static_cast<std::uint16_t>((static_cast<unsigned>(transport[2]) << 8U) |
                                                    static_cast<unsigned>(transport[3]));
  return key;
}

std::uint64_t hash_flow(const FlowKey& key) noexcept {
  const auto source = hash_address(key.source) + static_cast<std::uint64_t>(key.source_port);
  const auto destination =
      hash_address(key.destination) + static_cast<std::uint64_t>(key.destination_port);

  std::uint64_t hash = kOffsetBasis;
  mix(hash, source + destination);
  mix(hash, static_cast<std::uint64_t>(key.protocol));

  hash ^= hash >> 33U;
  hash *= 0xFF51AFD7ED558CCDULL;
  hash ^= hash >> 33U;
  return hash;
}

}
