// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#include "norr/spoof_sender.hpp"

#include <algorithm>
#include <array>

#include "norr/spooftest.hpp"

#if defined(__linux__)
#include <netinet/in.h>
#include <sys/socket.h>

#include <cerrno>
#include <cstring>
#endif

namespace norr {

bool SpoofSender::supported() noexcept {
#if defined(__linux__)
  return true;
#else
  return false;
#endif
}

std::size_t SpoofSender::build_into(const SpoofDatagram& datagram,
                                    std::span<std::byte> out) const noexcept {
  return build_spoofed_udp(datagram.source_be, datagram.destination_be, datagram.source_port,
                           datagram.destination_port, datagram.payload, out);
}

#if defined(__linux__)

std::expected<void, SpoofSendError> SpoofSender::open() noexcept {
  const int raw = ::socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_RAW);
  if (raw < 0) return std::unexpected(SpoofSendError::socket_failed);
  const int on = 1;
  static_cast<void>(::setsockopt(raw, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)));
  socket_ = FileDescriptor{raw};
  scratch_.assign(kMaxBatch * kMaxPacket, std::byte{0});
  return {};
}

std::expected<void, SpoofSendError> SpoofSender::set_mark(std::uint32_t mark) noexcept {
  if (!socket_.valid()) return std::unexpected(SpoofSendError::not_open);
  if (::setsockopt(socket_.get(), SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) != 0) {
    return std::unexpected(SpoofSendError::send_failed);
  }
  return {};
}

std::expected<std::size_t, SpoofSendError> SpoofSender::send_batch(
    std::span<const SpoofDatagram> datagrams) noexcept {
  if (!socket_.valid()) return std::unexpected(SpoofSendError::not_open);
  if (datagrams.empty()) return std::size_t{0};

  std::size_t sent_total = 0;
  for (std::size_t base = 0; base < datagrams.size(); base += kMaxBatch) {
    const auto count = std::min(kMaxBatch, datagrams.size() - base);
    std::array<mmsghdr, kMaxBatch> headers{};
    std::array<iovec, kMaxBatch> iovecs{};
    std::array<sockaddr_in, kMaxBatch> addrs{};
    std::size_t prepared = 0;

    for (std::size_t i = 0; i < count; ++i) {
      const auto& datagram = datagrams[base + i];
      const auto offset = prepared * kMaxPacket;
      const auto region = std::span{scratch_}.subspan(offset, kMaxPacket);
      const auto length = build_into(datagram, region);
      if (length == 0) continue;

      addrs[prepared].sin_family = AF_INET;
      addrs[prepared].sin_port = htons(datagram.destination_port);
      addrs[prepared].sin_addr.s_addr = htonl(datagram.destination_be);

      iovecs[prepared].iov_base = scratch_.data() + offset;
      iovecs[prepared].iov_len = length;

      headers[prepared].msg_hdr.msg_name = &addrs[prepared];
      headers[prepared].msg_hdr.msg_namelen = sizeof(sockaddr_in);
      headers[prepared].msg_hdr.msg_iov = &iovecs[prepared];
      headers[prepared].msg_hdr.msg_iovlen = 1;
      ++prepared;
    }

    if (prepared == 0) continue;
    const auto result =
        ::sendmmsg(socket_.get(), headers.data(), static_cast<unsigned>(prepared), 0);
    if (result < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) break;
      return std::unexpected(SpoofSendError::send_failed);
    }
    sent_total += static_cast<std::size_t>(result);
  }
  return sent_total;
}

#else

std::expected<void, SpoofSendError> SpoofSender::open() noexcept {
  return std::unexpected(SpoofSendError::unsupported_platform);
}

std::expected<void, SpoofSendError> SpoofSender::set_mark(std::uint32_t) noexcept {
  return std::unexpected(SpoofSendError::unsupported_platform);
}

std::expected<std::size_t, SpoofSendError> SpoofSender::send_batch(
    std::span<const SpoofDatagram>) noexcept {
  return std::unexpected(SpoofSendError::unsupported_platform);
}

#endif
}
