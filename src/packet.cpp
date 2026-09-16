// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#include "norr/packet.hpp"

#include <algorithm>

namespace norr {
namespace {
constexpr std::uint16_t read_u16(std::span<const std::byte> b, std::size_t o) noexcept {
  const auto value = (static_cast<unsigned>(static_cast<std::uint16_t>(b[o])) << 8U) |
                     static_cast<unsigned>(static_cast<std::uint16_t>(b[o + 1]));
  return static_cast<std::uint16_t>(value);
}
constexpr std::uint64_t read_u64(std::span<const std::byte> b, std::size_t o) noexcept {
  std::uint64_t value = 0;
  for (std::size_t i = 0; i < 8; ++i) value = (value << 8U) | static_cast<std::uint64_t>(b[o + i]);
  return value;
}
constexpr void write_u16(std::span<std::byte> b, std::size_t o, std::uint16_t v) noexcept {
  b[o] = static_cast<std::byte>(v >> 8U); b[o + 1] = static_cast<std::byte>(v);
}
constexpr void write_u64(std::span<std::byte> b, std::size_t o, std::uint64_t v) noexcept {
  for (std::size_t i = 0; i < 8; ++i) b[o + i] = static_cast<std::byte>(v >> static_cast<unsigned>((7U - i) * 8U));
}
constexpr bool valid_frame_type(FrameType type) noexcept { return type >= FrameType::data && type <= FrameType::fec; }
}

std::expected<PacketView, Error> parse_packet(std::span<const std::byte> bytes) noexcept {
  if (bytes.size() < kPacketHeaderSize) return std::unexpected(Error::malformed_packet);
  if (bytes.size() > kMaximumPacketSize) return std::unexpected(Error::packet_too_large);
  const auto version = static_cast<std::uint8_t>(static_cast<std::uint8_t>(bytes[0]) >> 4U);
  const auto type = static_cast<FrameType>(static_cast<std::uint8_t>(bytes[0]) & 0x0FU);
  const auto flags = static_cast<std::uint8_t>(bytes[1]);
  const auto header_length = read_u16(bytes, 4);
  const auto payload_length = read_u16(bytes, 14);
  if (version != kProtocolVersion) return std::unexpected(Error::unsupported_version);
  if (!valid_frame_type(type)) return std::unexpected(Error::malformed_packet);
  if (flags != 0U) return std::unexpected(Error::unsupported_flags);
  if (header_length != kPacketHeaderSize) return std::unexpected(Error::malformed_packet);
  if (payload_length != bytes.size() - kPacketHeaderSize) return std::unexpected(Error::payload_length_mismatch);

  if (read_u16(bytes, 2) == kPreSessionKeyId && type == FrameType::data) return std::unexpected(Error::reserved_key_id);
  return PacketView{.header = {.version = version, .type = type, .flags = flags, .key_id = read_u16(bytes, 2), .header_length = header_length, .counter = read_u64(bytes, 6), .payload_length = payload_length}, .payload = bytes.subspan(kPacketHeaderSize)};
}

std::expected<void, Error> serialize_header(const PacketHeader& header, std::size_t payload_length,
                                            std::span<std::byte> out) noexcept {
  if (header.version != kProtocolVersion) return std::unexpected(Error::unsupported_version);
  if (!valid_frame_type(header.type)) return std::unexpected(Error::malformed_packet);
  if (header.flags != 0U) return std::unexpected(Error::unsupported_flags);
  if (header.header_length != kPacketHeaderSize) return std::unexpected(Error::malformed_packet);
  if (header.key_id == kPreSessionKeyId && header.type == FrameType::data) return std::unexpected(Error::reserved_key_id);
  if (payload_length > kMaximumPacketSize - kPacketHeaderSize) return std::unexpected(Error::packet_too_large);
  if (out.size() < kPacketHeaderSize) return std::unexpected(Error::malformed_packet);

  out[0] = static_cast<std::byte>((header.version << 4U) | static_cast<std::uint8_t>(header.type));
  out[1] = static_cast<std::byte>(header.flags);
  write_u16(out, 2, header.key_id);
  write_u16(out, 4, header.header_length);
  write_u64(out, 6, header.counter);
  write_u16(out, 14, static_cast<std::uint16_t>(payload_length));
  return {};
}

std::expected<std::vector<std::byte>, Error> serialize_packet(const PacketHeader& header, std::span<const std::byte> payload) {
  std::array<std::byte, kPacketHeaderSize> prefix{};
  const auto written = serialize_header(header, payload.size(), prefix);
  if (!written) return std::unexpected(written.error());

  std::vector<std::byte> bytes(kPacketHeaderSize + payload.size());
  std::ranges::copy(prefix, bytes.begin());
  std::ranges::copy(payload, bytes.begin() + static_cast<std::ptrdiff_t>(kPacketHeaderSize));
  return bytes;
}
}
