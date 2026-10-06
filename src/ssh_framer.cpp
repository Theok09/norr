// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#include "norr/ssh_framer.hpp"

#include <algorithm>

#include "norr/tcp_transport.hpp"

namespace norr {
namespace {
thread_local std::uint64_t g_pad_state = 0x9E3779B97F4A7C15ULL;

std::byte cheap_random_byte() noexcept {
  g_pad_state += 0x9E3779B97F4A7C15ULL;
  auto value = g_pad_state;
  value = (value ^ (value >> 30U)) * 0xBF58476D1CE4E5B9ULL;
  value = (value ^ (value >> 27U)) * 0x94D049BB133111EBULL;
  value ^= value >> 31U;
  return static_cast<std::byte>(value & 0xFFU);
}

void put_u32(std::span<std::byte> out, std::uint32_t value) noexcept {
  out[0] = static_cast<std::byte>((value >> 24U) & 0xFFU);
  out[1] = static_cast<std::byte>((value >> 16U) & 0xFFU);
  out[2] = static_cast<std::byte>((value >> 8U) & 0xFFU);
  out[3] = static_cast<std::byte>(value & 0xFFU);
}

[[nodiscard]] std::uint32_t get_u32(std::span<const std::byte> in) noexcept {
  return (static_cast<std::uint32_t>(static_cast<std::uint8_t>(in[0])) << 24U) |
         (static_cast<std::uint32_t>(static_cast<std::uint8_t>(in[1])) << 16U) |
         (static_cast<std::uint32_t>(static_cast<std::uint8_t>(in[2])) << 8U) |
         static_cast<std::uint32_t>(static_cast<std::uint8_t>(in[3]));
}
}

std::size_t SshFramer::padding_for(std::size_t payload) noexcept {
  auto padding = kSshBlockSize - ((kSshHeaderSize + payload) % kSshBlockSize);
  if (padding < kSshMinPadding) padding += kSshBlockSize;
  return padding;
}

std::expected<std::size_t, SshFramerError> SshFramer::wrap(
    std::span<const std::byte> payload, std::span<std::byte> out) noexcept {
  if (payload.size() > kMaximumTcpFrame) return std::unexpected(SshFramerError::payload_too_large);
  const auto padding = padding_for(payload.size());
  const auto packet_length = 1 + payload.size() + padding;
  const auto total = sizeof(std::uint32_t) + packet_length;
  if (out.size() < total) return std::unexpected(SshFramerError::buffer_too_small);

  put_u32(out, static_cast<std::uint32_t>(packet_length));
  out[4] = static_cast<std::byte>(padding);
  std::copy(payload.begin(), payload.end(),
            out.begin() + static_cast<std::ptrdiff_t>(kSshHeaderSize));
  for (std::size_t i = 0; i < padding; ++i) {
    out[kSshHeaderSize + payload.size() + i] = cheap_random_byte();
  }
  return total;
}

std::expected<std::size_t, SshFramerError> SshFramer::unwrap(
    std::span<const std::byte> wire, std::span<std::byte> out,
    std::size_t& consumed) const noexcept {
  consumed = 0;
  if (wire.size() < kSshHeaderSize) return std::unexpected(SshFramerError::incomplete);
  const auto packet_length = static_cast<std::size_t>(get_u32(wire));
  const auto padding = static_cast<std::size_t>(static_cast<std::uint8_t>(wire[4]));
  if (packet_length < 2 || packet_length > kMaximumTcpFrame + kSshBlockSize + 1) {
    return std::unexpected(SshFramerError::malformed);
  }
  if (padding < kSshMinPadding || padding + 1 > packet_length) {
    return std::unexpected(SshFramerError::malformed);
  }
  const auto total = sizeof(std::uint32_t) + packet_length;
  if (wire.size() < total) return std::unexpected(SshFramerError::incomplete);
  const auto payload_length = packet_length - padding - 1;
  if (out.size() < payload_length) return std::unexpected(SshFramerError::buffer_too_small);
  std::copy(wire.begin() + static_cast<std::ptrdiff_t>(kSshHeaderSize),
            wire.begin() + static_cast<std::ptrdiff_t>(kSshHeaderSize + payload_length),
            out.begin());
  consumed = total;
  return payload_length;
}
}
