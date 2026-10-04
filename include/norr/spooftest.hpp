// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include "norr/crypto.hpp"

namespace norr {
inline constexpr std::size_t kSpoofProbeSize = 32;
using SpoofProbe = std::array<std::byte, kSpoofProbeSize>;

[[nodiscard]] SpoofProbe spoof_probe(std::span<const std::byte> secret, std::uint32_t source_be,
                                     std::uint32_t destination_be, std::uint16_t sequence) noexcept;

[[nodiscard]] bool spoof_probe_valid(std::span<const std::byte> secret,
                                     std::span<const std::byte> probe, std::uint32_t source_be,
                                     std::uint32_t destination_be) noexcept;

[[nodiscard]] std::uint16_t spoof_probe_sequence(std::span<const std::byte> probe) noexcept;

[[nodiscard]] std::uint16_t ip_checksum(std::span<const std::byte> header) noexcept;

[[nodiscard]] std::size_t build_spoofed_udp(std::uint32_t source_be, std::uint32_t destination_be,
                                            std::uint16_t source_port, std::uint16_t destination_port,
                                            std::span<const std::byte> payload,
                                            std::span<std::byte> out) noexcept;
}
