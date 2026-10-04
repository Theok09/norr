// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#include "norr/spooftest.hpp"

#include <atomic>

#include <algorithm>
#include <cstring>

#include "norr/blake2s.hpp"

namespace norr {
namespace {
constexpr std::string_view kSpoofDomain = "norr-spooftest-v1";

void put_u16(std::span<std::byte> out, std::size_t off, std::uint16_t value) noexcept {
  out[off] = static_cast<std::byte>(value >> 8U);
  out[off + 1] = static_cast<std::byte>(value & 0xFFU);
}

void put_u32(std::span<std::byte> out, std::size_t off, std::uint32_t value) noexcept {
  out[off] = static_cast<std::byte>((value >> 24U) & 0xFFU);
  out[off + 1] = static_cast<std::byte>((value >> 16U) & 0xFFU);
  out[off + 2] = static_cast<std::byte>((value >> 8U) & 0xFFU);
  out[off + 3] = static_cast<std::byte>(value & 0xFFU);
}

Blake2s::Digest probe_mac(std::span<const std::byte> secret, std::uint32_t source_be,
                          std::uint32_t destination_be, std::uint16_t sequence) noexcept {
  std::array<std::byte, 10 + kSpoofDomain.size()> input{};
  std::copy(kSpoofDomain.begin(), kSpoofDomain.end(),
            reinterpret_cast<char*>(input.data()));
  auto tail = std::span{input}.subspan(kSpoofDomain.size());
  put_u32(tail, 0, source_be);
  put_u32(tail, 4, destination_be);
  put_u16(tail, 8, sequence);
  return hmac_blake2s(secret, input);
}
}

std::uint16_t ip_checksum(std::span<const std::byte> header) noexcept {
  std::uint32_t sum = 0;
  std::size_t i = 0;
  for (; i + 1 < header.size(); i += 2) {
    sum += (static_cast<std::uint32_t>(static_cast<std::uint8_t>(header[i])) << 8U) |
           static_cast<std::uint32_t>(static_cast<std::uint8_t>(header[i + 1]));
  }
  if (i < header.size()) sum += static_cast<std::uint32_t>(static_cast<std::uint8_t>(header[i])) << 8U;
  while (sum >> 16U) sum = (sum & 0xFFFFU) + (sum >> 16U);
  return static_cast<std::uint16_t>(~sum & 0xFFFFU);
}

SpoofProbe spoof_probe(std::span<const std::byte> secret, std::uint32_t source_be,
                       std::uint32_t destination_be, std::uint16_t sequence) noexcept {
  SpoofProbe probe{};
  put_u16(probe, 0, sequence);
  const auto mac = probe_mac(secret, source_be, destination_be, sequence);
  std::copy(mac.begin(), mac.begin() + (kSpoofProbeSize - 2), probe.begin() + 2);
  return probe;
}

std::uint16_t spoof_probe_sequence(std::span<const std::byte> probe) noexcept {
  if (probe.size() < 2) return 0;
  return static_cast<std::uint16_t>((static_cast<unsigned>(static_cast<std::uint8_t>(probe[0])) << 8U) |
                                    static_cast<unsigned>(static_cast<std::uint8_t>(probe[1])));
}

bool spoof_probe_valid(std::span<const std::byte> secret, std::span<const std::byte> probe,
                       std::uint32_t source_be, std::uint32_t destination_be) noexcept {
  if (probe.size() != kSpoofProbeSize) return false;
  const auto sequence = spoof_probe_sequence(probe);
  const auto expected = spoof_probe(secret, source_be, destination_be, sequence);
  return constant_time_equal(probe, expected);
}

std::size_t build_spoofed_udp(std::uint32_t source_be, std::uint32_t destination_be,
                              std::uint16_t source_port, std::uint16_t destination_port,
                              std::span<const std::byte> payload, std::span<std::byte> out) noexcept {
  constexpr std::size_t kIpHeader = 20;
  constexpr std::size_t kUdpHeader = 8;
  const auto total = kIpHeader + kUdpHeader + payload.size();
  if (out.size() < total || total > 0xFFFFU) return 0;

  std::fill(out.begin(), out.begin() + static_cast<std::ptrdiff_t>(kIpHeader + kUdpHeader),
            std::byte{0});

  out[0] = std::byte{0x45};
  out[1] = std::byte{0};
  put_u16(out, 2, static_cast<std::uint16_t>(total));
  static std::atomic<std::uint32_t> ip_id_counter{0x1234U};
  const auto raw_id = ip_id_counter.fetch_add(1U, std::memory_order_relaxed);
  std::uint32_t id_mix = raw_id * 2654435761U;
  id_mix ^= id_mix >> 15U;
  put_u16(out, 4, static_cast<std::uint16_t>(id_mix & 0xFFFFU));
  out[6] = std::byte{0x40};
  out[8] = std::byte{64};
  out[9] = std::byte{17};
  put_u32(out, 12, source_be);
  put_u32(out, 16, destination_be);
  put_u16(out, 10, ip_checksum(out.first(kIpHeader)));

  put_u16(out, kIpHeader, source_port);
  put_u16(out, kIpHeader + 2, destination_port);
  put_u16(out, kIpHeader + 4, static_cast<std::uint16_t>(kUdpHeader + payload.size()));
  put_u16(out, kIpHeader + 6, 0);
  std::copy(payload.begin(), payload.end(),
            out.begin() + static_cast<std::ptrdiff_t>(kIpHeader + kUdpHeader));
  return total;
}
}
