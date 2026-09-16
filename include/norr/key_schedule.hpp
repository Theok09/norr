// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string_view>

#include "norr/error.hpp"
#include "norr/handshake.hpp"

namespace norr {
inline constexpr std::size_t kKeyLength = 32;
using TrafficKey = std::array<std::byte, kKeyLength>;

enum class KeyDirection { initiator_to_responder, responder_to_initiator };

inline constexpr std::string_view kProtocolLabel = "norr v1";
inline constexpr std::string_view kDataLabel = "data";
inline constexpr std::string_view kControlLabel = "control";

[[nodiscard]] constexpr std::string_view direction_label(KeyDirection direction) noexcept {
  return direction == KeyDirection::initiator_to_responder ? "i2r" : "r2i";
}

struct KeyLabel {
  std::array<std::byte, 64> bytes{};
  std::size_t size{};

  [[nodiscard]] std::span<const std::byte> view() const noexcept {
    return std::span<const std::byte>{bytes.data(), size};
  }
};

[[nodiscard]] std::expected<KeyLabel, Error> make_key_label(std::string_view domain,
                                                            KeyDirection direction,
                                                            KeyGeneration generation) noexcept;

}
