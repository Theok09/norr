// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>

#include "norr/file_descriptor.hpp"

namespace norr {
enum class TunError {
  unsupported_platform,
  open_failed,
  configure_failed,
  name_too_long,
  read_failed,
  write_failed,
  would_block,
  not_open,
  already_open,
  frame_too_large,
};

[[nodiscard]] constexpr std::string_view tun_error_message(TunError error) noexcept {
  switch (error) {
    case TunError::unsupported_platform: return "TUN not supported on this platform";
    case TunError::open_failed: return "cannot open /dev/net/tun";
    case TunError::configure_failed: return "cannot configure TUN device";
    case TunError::name_too_long: return "interface name too long";
    case TunError::read_failed: return "TUN read failed";
    case TunError::write_failed: return "TUN write failed";
    case TunError::would_block: return "operation would block";
    case TunError::not_open: return "TUN device not open";
    case TunError::already_open: return "TUN device already open";
    case TunError::frame_too_large: return "frame exceeds the configured maximum";
  }
  return "unknown TUN error";
}

struct TunStats {
  std::uint64_t rx_frames{};
  std::uint64_t tx_frames{};
  std::uint64_t rx_bytes{};
  std::uint64_t tx_bytes{};
  std::uint64_t rx_errors{};
  std::uint64_t tx_errors{};
  std::uint64_t oversized{};
};

class TunDevice {
 public:
  static constexpr std::size_t kMaximumNameLength = 15;

  static constexpr std::size_t kMaximumFrameSize = 9216;

  static constexpr std::uint16_t kMinimumTunMtu = 1280;

  [[nodiscard]] static bool supported() noexcept;

  TunDevice() = default;

  TunDevice(const TunDevice&) = delete;
  TunDevice& operator=(const TunDevice&) = delete;
  TunDevice(TunDevice&&) noexcept = default;
  TunDevice& operator=(TunDevice&&) noexcept = default;

  [[nodiscard]] std::expected<void, TunError> open(std::string_view requested_name = {},
                                                   bool non_blocking = true,
                                                   bool multiqueue = false);

  [[nodiscard]] static std::expected<TunDevice, TunError> open_queue(std::string_view name,
                                                                     bool non_blocking = true);

  [[nodiscard]] bool multiqueue() const noexcept { return multiqueue_; }

  void close() noexcept;

  [[nodiscard]] bool is_open() const noexcept { return device_.valid(); }
  [[nodiscard]] const std::string& name() const noexcept { return name_; }
  [[nodiscard]] int descriptor() const noexcept { return device_.get(); }

  [[nodiscard]] std::expected<std::span<const std::byte>, TunError> read_frame(
      std::span<std::byte> buffer);

  [[nodiscard]] std::expected<std::size_t, TunError> write_frame(std::span<const std::byte> frame);

  [[nodiscard]] std::expected<void, TunError> set_mtu(std::uint16_t mtu) noexcept;

  [[nodiscard]] std::expected<std::uint16_t, TunError> mtu() const noexcept;

  [[nodiscard]] const TunStats& stats() const noexcept { return stats_; }

 private:
  FileDescriptor device_;
  std::string name_;
  bool multiqueue_{};
  TunStats stats_{};
};

}
