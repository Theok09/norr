// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#include "norr/icmp_transport.hpp"

#include <algorithm>
#include <array>
#include <cstring>

#if defined(__linux__)
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#endif

namespace norr {
namespace {
void write_u16(std::span<std::byte> b, std::size_t o, std::uint16_t v) noexcept {
  b[o] = static_cast<std::byte>(v >> 8U);
  b[o + 1] = static_cast<std::byte>(v & 0xFFU);
}
std::uint16_t read_u16(std::span<const std::byte> b, std::size_t o) noexcept {
  return static_cast<std::uint16_t>((static_cast<unsigned>(static_cast<std::uint8_t>(b[o])) << 8U) |
                                    static_cast<unsigned>(static_cast<std::uint8_t>(b[o + 1])));
}
}

std::uint16_t icmp_checksum(std::span<const std::byte> data) noexcept {
  std::uint32_t sum = 0;
  std::size_t i = 0;
  for (; i + 1 < data.size(); i += 2) {
    sum += (static_cast<std::uint32_t>(static_cast<std::uint8_t>(data[i])) << 8U) |
           static_cast<std::uint32_t>(static_cast<std::uint8_t>(data[i + 1]));
  }
  if (i < data.size()) {
    sum += static_cast<std::uint32_t>(static_cast<std::uint8_t>(data[i])) << 8U;
  }
  while (sum >> 16U) sum = (sum & 0xFFFFU) + (sum >> 16U);
  return static_cast<std::uint16_t>(~sum & 0xFFFFU);
}

std::size_t build_icmp_echo(std::uint8_t type, std::uint16_t identifier, std::uint16_t sequence,
                            std::span<const std::byte> payload, std::span<std::byte> out) noexcept {
  const auto total = kIcmpHeaderSize + payload.size();
  if (out.size() < total) return 0;
  out[0] = static_cast<std::byte>(type);
  out[1] = std::byte{0};
  out[2] = std::byte{0};
  out[3] = std::byte{0};
  write_u16(out, 4, identifier);
  write_u16(out, 6, sequence);
  std::copy(payload.begin(), payload.end(),
            out.begin() + static_cast<std::ptrdiff_t>(kIcmpHeaderSize));
  const auto checksum = icmp_checksum(out.first(total));
  write_u16(out, 2, checksum);
  return total;
}

std::expected<IcmpEchoView, TransportError> parse_icmp_echo(std::span<const std::byte> datagram,
                                                            bool includes_ip_header) noexcept {
  std::size_t offset = 0;
  if (includes_ip_header) {
    if (datagram.empty()) return std::unexpected(TransportError::receive_failed);
    const auto version = static_cast<std::uint8_t>(datagram[0]) >> 4U;
    if (version != 4) return std::unexpected(TransportError::receive_failed);
    const auto ihl = (static_cast<std::uint8_t>(datagram[0]) & 0x0FU) * 4U;
    if (datagram.size() < ihl) return std::unexpected(TransportError::receive_failed);
    offset = ihl;
  }
  const auto icmp = datagram.subspan(offset);
  if (icmp.size() < kIcmpHeaderSize) return std::unexpected(TransportError::receive_failed);
  return IcmpEchoView{.type = static_cast<std::uint8_t>(icmp[0]),
                      .identifier = read_u16(icmp, 4),
                      .sequence = read_u16(icmp, 6),
                      .payload = icmp.subspan(kIcmpHeaderSize)};
}

#if !defined(__linux__)

bool IcmpTransport::supported() noexcept { return false; }

std::expected<void, TransportError> IcmpTransport::start(const Endpoint&, Role) {
  return std::unexpected(TransportError::unsupported_platform);
}

void IcmpTransport::stop() noexcept { socket_.reset(); }

std::expected<void, TransportError> IcmpTransport::set_mark(std::uint32_t) {
  return std::unexpected(TransportError::unsupported_platform);
}

std::expected<std::size_t, TransportError> IcmpTransport::send_batch(
    std::span<const OutboundDatagram>) {
  return std::unexpected(TransportError::unsupported_platform);
}

std::expected<std::size_t, TransportError> IcmpTransport::receive_batch(ReceiveBuffers&,
                                                                        std::span<InboundDatagram>) {
  return std::unexpected(TransportError::unsupported_platform);
}

#else

bool IcmpTransport::supported() noexcept { return true; }

std::expected<void, TransportError> IcmpTransport::start(const Endpoint& bind_address, Role role) {
  if (socket_.valid()) return std::unexpected(TransportError::already_started);
  FileDescriptor descriptor{::socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMP)};
  if (!descriptor) return std::unexpected(TransportError::socket_creation_failed);

  const auto flags = ::fcntl(descriptor.get(), F_GETFL, 0);
  if (flags < 0 || ::fcntl(descriptor.get(), F_SETFL, flags | O_NONBLOCK) != 0) {
    return std::unexpected(TransportError::socket_option_failed);
  }

  static_cast<void>(bind_address);
  socket_ = std::move(descriptor);
  role_ = role;
  return {};
}

void IcmpTransport::stop() noexcept { socket_.reset(); }

std::expected<void, TransportError> IcmpTransport::set_mark(std::uint32_t mark) {
  if (!socket_.valid()) return std::unexpected(TransportError::not_started);
  if (::setsockopt(socket_.get(), SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) != 0) {
    return std::unexpected(TransportError::socket_option_failed);
  }
  return {};
}

std::expected<std::size_t, TransportError> IcmpTransport::send_batch(
    std::span<const OutboundDatagram> datagrams) {
  if (!socket_.valid()) return std::unexpected(TransportError::not_started);
  const std::uint8_t type = role_ == Role::client ? kIcmpEchoRequest : kIcmpEchoReply;

  std::size_t sent = 0;
  for (const auto& datagram : datagrams) {
    scratch_.assign(kIcmpHeaderSize + datagram.payload.size(), std::byte{0});
    const auto framed = build_icmp_echo(type, kNorrIcmpId, sequence_++, datagram.payload, scratch_);
    if (framed == 0) {
      ++stats_.tx_errors;
      continue;
    }
    if (datagram.destination.family() != AddressFamily::ipv4) {
      ++stats_.tx_errors;
      continue;
    }
    sockaddr_in dest{};
    dest.sin_family = AF_INET;
    const auto octets = datagram.destination.address().bytes();
    std::memcpy(&dest.sin_addr.s_addr, octets.data(), 4);

    const auto result = ::sendto(socket_.get(), scratch_.data(), framed, MSG_NOSIGNAL,
                                 reinterpret_cast<const sockaddr*>(&dest), sizeof(dest));
    if (result < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) break;
      ++stats_.tx_errors;
      return sent > 0 ? std::expected<std::size_t, TransportError>{sent}
                      : std::unexpected(TransportError::send_failed);
    }
    ++sent;
    ++stats_.tx_packets;
    stats_.tx_bytes += datagram.payload.size();
  }
  return sent;
}

std::expected<std::size_t, TransportError> IcmpTransport::receive_batch(
    ReceiveBuffers& buffers, std::span<InboundDatagram> out) {
  if (!socket_.valid()) return std::unexpected(TransportError::not_started);
  if (out.empty()) return std::size_t{0};

  const std::uint8_t want = role_ == Role::client ? kIcmpEchoReply : kIcmpEchoRequest;
  std::size_t received = 0;
  const auto limit = std::min(out.size(), buffers.count());

  while (received < limit) {
    auto slot = buffers.slot(received);
    sockaddr_in from{};
    socklen_t from_len = sizeof(from);
    const auto got = ::recvfrom(socket_.get(), slot.data(), slot.size(), 0,
                                reinterpret_cast<sockaddr*>(&from), &from_len);
    if (got < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) break;
      if (errno == EINTR) continue;
      ++stats_.rx_errors;
      break;
    }
    const auto view = parse_icmp_echo(slot.first(static_cast<std::size_t>(got)), true);
    if (!view) {
      ++stats_.rx_errors;
      continue;
    }
    if (view->type != want || view->identifier != kNorrIcmpId) continue;

    std::array<std::byte, 4> ipv4{};
    std::memcpy(ipv4.data(), &from.sin_addr.s_addr, 4);
    const auto source = Address::from_bytes(AddressFamily::ipv4, ipv4);

    out[received] = InboundDatagram{.source = Endpoint{source, 0}, .payload = view->payload};
    ++received;
    ++stats_.rx_packets;
    stats_.rx_bytes += view->payload.size();
  }
  return received;
}

#endif
}
