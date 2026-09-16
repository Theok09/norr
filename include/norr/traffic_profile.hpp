// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include "norr/packet.hpp"
#include "norr/timers.hpp"

namespace norr {

enum class TrafficProfile : std::uint8_t { standard, quic, dns };

[[nodiscard]] constexpr std::string_view traffic_profile_name(TrafficProfile profile) noexcept {
  switch (profile) {
    case TrafficProfile::standard: return "standard";
    case TrafficProfile::quic: return "quic";
    case TrafficProfile::dns: return "dns";
  }
  return "unknown";
}

[[nodiscard]] constexpr std::span<const std::size_t> profile_buckets(
    TrafficProfile profile) noexcept {
  static constexpr std::array<std::size_t, 5> kQuic{64, 128, 256, 512, 1100};
  static constexpr std::array<std::size_t, 4> kDns{64, 128, 256, 512};

  switch (profile) {
    case TrafficProfile::standard: return {};
    case TrafficProfile::quic: return std::span<const std::size_t>{kQuic};
    case TrafficProfile::dns: return std::span<const std::size_t>{kDns};
  }
  return {};
}

[[nodiscard]] constexpr std::size_t profile_padded_length(TrafficProfile profile,
                                                          std::size_t length) noexcept {
  const auto aligned = padded_length(length);
  for (const auto bucket : profile_buckets(profile)) {
    if (aligned <= bucket) return bucket;
  }
  return aligned;
}

inline constexpr auto kChaffInterval = std::chrono::milliseconds{250};

}
