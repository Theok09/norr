// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <vector>

namespace norr {
inline constexpr std::size_t kVirtioHeaderSize = 10;
inline constexpr std::size_t kMaximumOffloadFrame = 65535;

inline constexpr std::uint8_t kVirtioNeedsChecksum = 1;
inline constexpr std::uint8_t kGsoNone = 0;
inline constexpr std::uint8_t kGsoTcpV4 = 1;
inline constexpr std::uint8_t kGsoUdpL4 = 5;
inline constexpr std::uint8_t kGsoTcpV6 = 4;

struct VirtioHeader {
  std::uint8_t flags{};
  std::uint8_t gso_type{};
  std::uint16_t header_length{};
  std::uint16_t gso_size{};
  std::uint16_t checksum_start{};
  std::uint16_t checksum_offset{};
};

[[nodiscard]] VirtioHeader parse_virtio_header(std::span<const std::byte> bytes) noexcept;
void write_virtio_header(const VirtioHeader& header, std::span<std::byte> out) noexcept;

[[nodiscard]] std::uint16_t fold_checksum(std::uint64_t sum) noexcept;
[[nodiscard]] std::uint64_t checksum_add(std::span<const std::byte> bytes,
                                         std::uint64_t initial = 0) noexcept;
[[nodiscard]] std::uint64_t pseudo_header_sum(std::span<const std::byte> packet,
                                              std::uint8_t protocol,
                                              std::size_t transport_length) noexcept;
[[nodiscard]] bool transport_checksum_valid(std::span<const std::byte> packet) noexcept;

using SegmentSink = std::function<void(std::span<const std::byte>)>;

[[nodiscard]] bool expand_offloaded(const VirtioHeader& header, std::span<std::byte> packet,
                                    std::vector<std::byte>& scratch, const SegmentSink& sink);

class TcpCoalescer {
 public:
  using Writer = std::function<void(std::span<const std::byte> virtio, std::span<const std::byte> head,
                                    std::span<const std::span<const std::byte>> payloads)>;

  void add(std::span<const std::byte> packet, bool stable = false);

  std::size_t flush(const Writer& writer);

  [[nodiscard]] bool empty() const noexcept { return used_ == 0; }
  [[nodiscard]] std::uint64_t coalesced() const noexcept { return coalesced_; }

 private:
  struct Item {
    std::vector<std::byte> head;
    std::vector<std::span<const std::byte>> payloads;
    bool tcp{};
    bool ipv4{};
    std::size_t ip_length{};
    std::size_t tcp_length{};
    std::size_t segment{};
    std::size_t total{};
    std::uint32_t next_sequence{};
    bool open{};
  };

  [[nodiscard]] Item& next_item();
  [[nodiscard]] std::span<const std::byte> retain(std::span<const std::byte> packet, bool stable);
  [[nodiscard]] bool try_append(const Item& item, std::span<const std::byte> packet, bool ipv4,
                                std::size_t ip_length, std::size_t tcp_length) const noexcept;

  std::vector<Item> items_;
  std::size_t used_{};
  std::vector<std::vector<std::byte>> owned_;
  std::size_t owned_used_{};
  std::uint64_t coalesced_{};
};
}
