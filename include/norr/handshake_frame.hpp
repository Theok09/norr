#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <vector>

#include "norr/error.hpp"
#include "norr/handshake.hpp"

namespace norr {
inline constexpr std::size_t kHandshakeEnvelopeSize = 4;
inline constexpr std::size_t kMaximumHandshakePayload = 4096;

inline constexpr std::size_t kHandshakeMacSize = 16;
inline constexpr std::size_t kHandshakeMacTrailerSize = 2 * kHandshakeMacSize;

struct HandshakeFrameView {
  HandshakeMessage message{HandshakeMessage::none};
  std::span<const std::byte> noise_message;

  bool has_macs{};
  std::span<const std::byte> mac1;
  std::span<const std::byte> mac2;

  std::span<const std::byte> mac1_covered;
  std::span<const std::byte> mac2_covered;
};

[[nodiscard]] std::expected<HandshakeFrameView, Error> parse_handshake_frame(std::span<const std::byte> bytes) noexcept;
[[nodiscard]] std::expected<std::vector<std::byte>, Error> serialize_handshake_frame(HandshakeMessage message, std::span<const std::byte> noise_message);

[[nodiscard]] std::expected<std::vector<std::byte>, Error> serialize_handshake_frame_with_macs(
    HandshakeMessage message, std::span<const std::byte> noise_message);

[[nodiscard]] constexpr std::size_t mac1_offset(std::size_t noise_length) noexcept {
  return kHandshakeEnvelopeSize + noise_length;
}
[[nodiscard]] constexpr std::size_t mac2_offset(std::size_t noise_length) noexcept {
  return mac1_offset(noise_length) + kHandshakeMacSize;
}

}
