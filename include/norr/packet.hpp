// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <vector>

#include "norr/error.hpp"

namespace norr {
inline constexpr std::uint8_t kProtocolVersion = 1;

inline constexpr std::size_t kPaddingAlignment = 16;

[[nodiscard]] constexpr std::size_t padded_length(std::size_t length) noexcept {
  const auto remainder = length % kPaddingAlignment;
  return remainder == 0 ? length : length + (kPaddingAlignment - remainder);
}
inline constexpr std::size_t kPacketHeaderSize = 16;
inline constexpr std::size_t kMaximumPacketSize = 65'535;

enum class FrameType : std::uint8_t { data = 1, control, path, key, error, fec };

inline constexpr std::uint16_t kPreSessionKeyId = 0;

// A control frame with a payload is an echo. The first byte says which half of
// the exchange it is; the rest is an opaque token the requester chose and the
// responder returns unchanged. This is what gives the datapath a real RTT.
inline constexpr std::byte kEchoRequest{1};
inline constexpr std::byte kEchoReply{2};
inline constexpr std::size_t kEchoTokenSize = 8;

struct PacketHeader {
  std::uint8_t version{};
  FrameType type{};
  std::uint8_t flags{};
  std::uint16_t key_id{};
  std::uint16_t header_length{kPacketHeaderSize};
  std::uint64_t counter{};
  std::uint16_t payload_length{};
};

struct PacketView { PacketHeader header; std::span<const std::byte> payload; };

[[nodiscard]] std::expected<PacketView, Error> parse_packet(std::span<const std::byte> bytes) noexcept;
[[nodiscard]] std::expected<std::vector<std::byte>, Error> serialize_packet(
    const PacketHeader& header, std::span<const std::byte> payload);

[[nodiscard]] std::expected<void, Error> serialize_header(const PacketHeader& header,
                                                          std::size_t payload_length,
                                                          std::span<std::byte> out) noexcept;

}
