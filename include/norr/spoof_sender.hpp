// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <vector>

#include "norr/file_descriptor.hpp"

namespace norr {
enum class SpoofSendError {
  unsupported_platform,
  socket_failed,
  not_open,
  build_failed,
  send_failed,
};

struct SpoofDatagram {
  std::uint32_t source_be{};
  std::uint32_t destination_be{};
  std::uint16_t source_port{};
  std::uint16_t destination_port{};
  std::span<const std::byte> payload;
};

class SpoofSender {
 public:
  static constexpr std::size_t kMaxBatch = 64;
  static constexpr std::size_t kMaxPacket = 1500;

  SpoofSender() = default;

  [[nodiscard]] static bool supported() noexcept;

  [[nodiscard]] std::expected<void, SpoofSendError> open() noexcept;

  [[nodiscard]] bool is_open() const noexcept { return socket_.valid(); }

  [[nodiscard]] std::expected<void, SpoofSendError> set_mark(std::uint32_t mark) noexcept;

  [[nodiscard]] std::expected<std::size_t, SpoofSendError> send_batch(
      std::span<const SpoofDatagram> datagrams) noexcept;

  [[nodiscard]] std::size_t build_into(const SpoofDatagram& datagram,
                                       std::span<std::byte> out) const noexcept;

  [[nodiscard]] std::uint64_t dropped_oversized() const noexcept { return dropped_oversized_; }

 private:
  FileDescriptor socket_;
  std::vector<std::byte> scratch_;
  std::uint64_t dropped_oversized_{};
};
}
