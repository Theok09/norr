// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#include "norr/handshake_frame.hpp"

#include <algorithm>

namespace norr {
namespace {
constexpr std::uint16_t read_u16(std::span<const std::byte> b, std::size_t o) noexcept {
  const auto value = (static_cast<unsigned>(static_cast<std::uint16_t>(b[o])) << 8U) | static_cast<unsigned>(static_cast<std::uint16_t>(b[o + 1]));
  return static_cast<std::uint16_t>(value);
}

constexpr bool is_wire_message(HandshakeMessage message) noexcept { return message >= HandshakeMessage::init && message <= HandshakeMessage::cookie_reply; }
}

std::expected<HandshakeFrameView, Error> parse_handshake_frame(std::span<const std::byte> bytes) noexcept {
  if (bytes.size() < kHandshakeEnvelopeSize) return std::unexpected(Error::malformed_packet);
  const auto message = static_cast<HandshakeMessage>(bytes[0]);
  const auto version = static_cast<std::uint8_t>(bytes[1]);
  const auto length = read_u16(bytes, 2);
  if (version != 1U) return std::unexpected(Error::unsupported_version);
  if (!is_wire_message(message)) return std::unexpected(Error::malformed_packet);
  if (length > kMaximumHandshakePayload) return std::unexpected(Error::packet_too_large);

  const auto without_header = bytes.size() - kHandshakeEnvelopeSize;

  if (length == without_header) {
    return HandshakeFrameView{.message = message,
                              .noise_message = bytes.subspan(kHandshakeEnvelopeSize),
                              .has_macs = false,
                              .mac1 = {},
                              .mac2 = {},
                              .mac1_covered = {},
                              .mac2_covered = {}};
  }
  if (length + kHandshakeMacTrailerSize != without_header) {
    return std::unexpected(Error::payload_length_mismatch);
  }

  const auto first = mac1_offset(length);
  const auto second = mac2_offset(length);
  return HandshakeFrameView{
      .message = message,
      .noise_message = bytes.subspan(kHandshakeEnvelopeSize, length),
      .has_macs = true,
      .mac1 = bytes.subspan(first, kHandshakeMacSize),
      .mac2 = bytes.subspan(second, kHandshakeMacSize),

      .mac1_covered = bytes.first(first),
      .mac2_covered = bytes.first(second),
  };
}

std::expected<std::vector<std::byte>, Error> serialize_handshake_frame(HandshakeMessage message, std::span<const std::byte> noise_message) {
  if (!is_wire_message(message)) return std::unexpected(Error::malformed_packet);
  if (noise_message.size() > kMaximumHandshakePayload) return std::unexpected(Error::packet_too_large);
  std::vector<std::byte> bytes(kHandshakeEnvelopeSize + noise_message.size());
  bytes[0] = static_cast<std::byte>(message); bytes[1] = std::byte{1};
  const auto length = static_cast<std::uint16_t>(noise_message.size());
  bytes[2] = static_cast<std::byte>(length >> 8U); bytes[3] = static_cast<std::byte>(length);
  std::ranges::copy(noise_message, bytes.begin() + static_cast<std::ptrdiff_t>(kHandshakeEnvelopeSize));
  return bytes;
}

std::expected<std::vector<std::byte>, Error> serialize_handshake_frame_with_macs(
    HandshakeMessage message, std::span<const std::byte> noise_message) {
  auto bytes = serialize_handshake_frame(message, noise_message);
  if (!bytes) return bytes;

  bytes->resize(bytes->size() + kHandshakeMacTrailerSize, std::byte{0});
  return bytes;
}
}
