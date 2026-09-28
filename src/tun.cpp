// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#include "norr/tun.hpp"

#include <array>
#include <cstring>

#include "norr/offload.hpp"

#if defined(__linux__)
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <unistd.h>

#include <cerrno>
#endif

namespace norr {
bool TunDevice::supported() noexcept {
#if defined(__linux__)
  return true;
#else
  return false;
#endif
}

#if !defined(__linux__)

std::expected<void, TunError> TunDevice::open(std::string_view, bool, bool, bool) {
  return std::unexpected(TunError::unsupported_platform);
}

std::expected<std::size_t, TunError> TunDevice::write_offloaded(std::span<const std::byte>,
                                                                std::span<const std::byte>) {
  return std::unexpected(TunError::unsupported_platform);
}

std::expected<std::size_t, TunError> TunDevice::write_vectored(
    std::span<const std::byte>, std::span<const std::byte>,
    std::span<const std::span<const std::byte>>) {
  return std::unexpected(TunError::unsupported_platform);
}

std::expected<TunDevice, TunError> TunDevice::open_queue(std::string_view, bool) {
  return std::unexpected(TunError::unsupported_platform);
}

void TunDevice::close() noexcept { device_.reset(); }

std::expected<void, TunError> TunDevice::set_mtu(std::uint16_t) noexcept {
  return std::unexpected(TunError::unsupported_platform);
}

std::expected<std::uint16_t, TunError> TunDevice::mtu() const noexcept {
  return std::unexpected(TunError::unsupported_platform);
}

std::expected<std::span<const std::byte>, TunError> TunDevice::read_frame(std::span<std::byte>) {
  return std::unexpected(TunError::unsupported_platform);
}

std::expected<std::size_t, TunError> TunDevice::write_frame(std::span<const std::byte>) {
  return std::unexpected(TunError::unsupported_platform);
}

#else

std::expected<void, TunError> TunDevice::open(std::string_view requested_name, bool non_blocking,
                                              bool multiqueue, bool offload) {
  if (device_.valid()) return std::unexpected(TunError::already_open);
  if (requested_name.size() > kMaximumNameLength) {
    return std::unexpected(TunError::name_too_long);
  }

  FileDescriptor device{::open("/dev/net/tun", O_RDWR | O_CLOEXEC)};
  if (!device) return std::unexpected(TunError::open_failed);

  ifreq request{};
  std::memset(&request, 0, sizeof(request));

  request.ifr_flags = IFF_TUN | IFF_NO_PI;
  if (offload) request.ifr_flags |= IFF_VNET_HDR;
#if defined(IFF_MULTI_QUEUE)

  if (multiqueue) request.ifr_flags |= IFF_MULTI_QUEUE;
#else
  if (multiqueue) return std::unexpected(TunError::configure_failed);
#endif
  if (!requested_name.empty()) {
    std::memcpy(request.ifr_name, requested_name.data(), requested_name.size());
    request.ifr_name[requested_name.size()] = '\0';
  }

  if (::ioctl(device.get(), TUNSETIFF, &request) != 0) {
    return std::unexpected(TunError::configure_failed);
  }

  if (offload) {
    int header_size = static_cast<int>(kVirtioHeaderSize);
    if (::ioctl(device.get(), TUNSETVNETHDRSZ, &header_size) != 0) {
      return std::unexpected(TunError::configure_failed);
    }
    const unsigned base = TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6;
#if defined(TUN_F_USO4) && defined(TUN_F_USO6)
    if (::ioctl(device.get(), TUNSETOFFLOAD, base | TUN_F_USO4 | TUN_F_USO6) != 0 &&
        ::ioctl(device.get(), TUNSETOFFLOAD, base) != 0) {
      static_cast<void>(::ioctl(device.get(), TUNSETOFFLOAD, 0U));
    }
#else
    if (::ioctl(device.get(), TUNSETOFFLOAD, base) != 0) {
      static_cast<void>(::ioctl(device.get(), TUNSETOFFLOAD, 0U));
    }
#endif
  }

  if (non_blocking) {
    const auto flags = ::fcntl(device.get(), F_GETFL, 0);
    if (flags < 0 || ::fcntl(device.get(), F_SETFL, flags | O_NONBLOCK) != 0) {
      return std::unexpected(TunError::configure_failed);
    }
  }

  request.ifr_name[IFNAMSIZ - 1] = '\0';
  name_.assign(request.ifr_name);
  device_ = std::move(device);
  multiqueue_ = multiqueue;
  offload_ = offload;
  stats_ = TunStats{};
  return {};
}

std::expected<TunDevice, TunError> TunDevice::open_queue(std::string_view name,
                                                         bool non_blocking) {
  if (name.empty() || name.size() > kMaximumNameLength) {
    return std::unexpected(TunError::name_too_long);
  }

  FileDescriptor device{::open("/dev/net/tun", O_RDWR | O_CLOEXEC)};
  if (!device) return std::unexpected(TunError::open_failed);

  ifreq request{};
  std::memset(&request, 0, sizeof(request));
#if defined(IFF_MULTI_QUEUE)
  request.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE;
#else

  return std::unexpected(TunError::configure_failed);
#endif
  std::memcpy(request.ifr_name, name.data(), name.size());
  request.ifr_name[name.size()] = '\0';

  if (::ioctl(device.get(), TUNSETIFF, &request) != 0) {
    return std::unexpected(TunError::configure_failed);
  }

  if (non_blocking) {
    const auto flags = ::fcntl(device.get(), F_GETFL, 0);
    if (flags < 0 || ::fcntl(device.get(), F_SETFL, flags | O_NONBLOCK) != 0) {
      return std::unexpected(TunError::configure_failed);
    }
  }

  TunDevice queue;
  request.ifr_name[IFNAMSIZ - 1] = '\0';
  queue.name_.assign(request.ifr_name);
  queue.device_ = std::move(device);
  queue.multiqueue_ = true;
  return queue;
}

void TunDevice::close() noexcept {
  device_.reset();
  name_.clear();
}

std::expected<std::span<const std::byte>, TunError> TunDevice::read_frame(
    std::span<std::byte> buffer) {
  if (!device_.valid()) return std::unexpected(TunError::not_open);
  if (buffer.empty()) return std::unexpected(TunError::frame_too_large);

  const auto limit = offload_ ? buffer.size() : std::min(buffer.size(), kMaximumFrameSize);

  while (true) {
    const auto result = ::read(device_.get(), buffer.data(), limit);
    if (result >= 0) {
      const auto length = static_cast<std::size_t>(result);

      if (!offload_ && length == limit && limit < kMaximumFrameSize) {
        ++stats_.oversized;
        return std::span<const std::byte>{};
      }
      stats_.rx_bytes += length;
      ++stats_.rx_frames;
      return std::span<const std::byte>{buffer.data(), length};
    }

    if (errno == EINTR) continue;
    if (errno == EAGAIN || errno == EWOULDBLOCK) return std::span<const std::byte>{};
    ++stats_.rx_errors;
    return std::unexpected(TunError::read_failed);
  }
}

std::expected<std::size_t, TunError> TunDevice::write_offloaded(
    std::span<const std::byte> header, std::span<const std::byte> packet) {
  if (!device_.valid()) return std::unexpected(TunError::not_open);
  std::array<iovec, 2> vectors{};
  vectors[0].iov_base = const_cast<std::byte*>(header.data());
  vectors[0].iov_len = header.size();
  vectors[1].iov_base = const_cast<std::byte*>(packet.data());
  vectors[1].iov_len = packet.size();
  while (true) {
    const auto result = ::writev(device_.get(), vectors.data(), 2);
    if (result >= 0) {
      stats_.tx_bytes += packet.size();
      ++stats_.tx_frames;
      return packet.size();
    }
    if (errno == EINTR) continue;
    if (errno == EAGAIN || errno == EWOULDBLOCK) return std::unexpected(TunError::would_block);
    ++stats_.tx_errors;
    return std::unexpected(TunError::write_failed);
  }
}

std::expected<std::size_t, TunError> TunDevice::write_vectored(
    std::span<const std::byte> header, std::span<const std::byte> head,
    std::span<const std::span<const std::byte>> payloads) {
  if (!device_.valid()) return std::unexpected(TunError::not_open);
  std::array<iovec, 68> vectors{};
  std::size_t used = 0;
  std::size_t total = 0;
  const auto push = [&](std::span<const std::byte> piece) {
    if (piece.empty() || used == vectors.size()) return;
    vectors[used].iov_base = const_cast<std::byte*>(piece.data());
    vectors[used].iov_len = piece.size();
    ++used;
  };
  if (offload_) push(header);
  push(head);
  total += head.size();
  for (const auto piece : payloads) {
    push(piece);
    total += piece.size();
  }
  while (true) {
    const auto result = ::writev(device_.get(), vectors.data(), static_cast<int>(used));
    if (result >= 0) {
      stats_.tx_bytes += total;
      ++stats_.tx_frames;
      return total;
    }
    if (errno == EINTR) continue;
    if (errno == EAGAIN || errno == EWOULDBLOCK) return std::unexpected(TunError::would_block);
    ++stats_.tx_errors;
    return std::unexpected(TunError::write_failed);
  }
}

std::expected<std::size_t, TunError> TunDevice::write_frame(std::span<const std::byte> frame) {
  if (!device_.valid()) return std::unexpected(TunError::not_open);
  if (offload_) {
    const std::array<std::byte, kVirtioHeaderSize> header{};
    if (frame.empty() || frame.size() > kMaximumOffloadFrame) {
      return std::unexpected(TunError::frame_too_large);
    }
    return write_offloaded(header, frame);
  }
  if (frame.empty()) return std::unexpected(TunError::write_failed);
  if (frame.size() > kMaximumFrameSize) {
    ++stats_.oversized;
    return std::unexpected(TunError::frame_too_large);
  }

  while (true) {
    const auto result = ::write(device_.get(), frame.data(), frame.size());
    if (result >= 0) {
      const auto written = static_cast<std::size_t>(result);
      stats_.tx_bytes += written;
      ++stats_.tx_frames;
      return written;
    }

    if (errno == EINTR) continue;
    if (errno == EAGAIN || errno == EWOULDBLOCK) return std::unexpected(TunError::would_block);
    ++stats_.tx_errors;
    return std::unexpected(TunError::write_failed);
  }
}

std::expected<void, TunError> TunDevice::set_mtu(std::uint16_t mtu) noexcept {
  if (!device_.valid()) return std::unexpected(TunError::not_open);
  if (mtu < kMinimumTunMtu || mtu > kMaximumFrameSize) {
    return std::unexpected(TunError::configure_failed);
  }

  FileDescriptor control{::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0)};
  if (!control.valid()) return std::unexpected(TunError::configure_failed);

  ifreq request{};
  std::strncpy(request.ifr_name, name_.c_str(), IFNAMSIZ - 1);
  request.ifr_mtu = mtu;
  if (::ioctl(control.get(), SIOCSIFMTU, &request) != 0) {
    return std::unexpected(TunError::configure_failed);
  }
  return {};
}

std::expected<std::uint16_t, TunError> TunDevice::mtu() const noexcept {
  if (!device_.valid()) return std::unexpected(TunError::not_open);

  FileDescriptor control{::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0)};
  if (!control.valid()) return std::unexpected(TunError::configure_failed);

  ifreq request{};
  std::strncpy(request.ifr_name, name_.c_str(), IFNAMSIZ - 1);
  if (::ioctl(control.get(), SIOCGIFMTU, &request) != 0) {
    return std::unexpected(TunError::configure_failed);
  }
  return static_cast<std::uint16_t>(request.ifr_mtu);
}

#endif
}
