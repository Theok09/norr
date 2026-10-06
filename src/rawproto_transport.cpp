// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#include "norr/rawproto_transport.hpp"

#include <algorithm>
#include <array>
#include <cstring>

#if defined(__linux__)
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
[[maybe_unused]] void write_u32(std::span<std::byte> b, std::size_t o, std::uint32_t v) noexcept {
  write_u16(b, o, static_cast<std::uint16_t>(v >> 16U));
  write_u16(b, o + 2U, static_cast<std::uint16_t>(v & 0xFFFFU));
}
[[maybe_unused]] std::uint32_t read_u32(std::span<const std::byte> b, std::size_t o) noexcept {
  return (static_cast<std::uint32_t>(read_u16(b, o)) << 16U) |
         static_cast<std::uint32_t>(read_u16(b, o + 2U));
}
[[maybe_unused]] std::uint16_t internet_checksum(std::span<const std::byte> b) noexcept {
  std::uint32_t sum = 0;
  std::size_t index = 0;
  for (; index + 1 < b.size(); index += 2) {
    sum += (static_cast<std::uint32_t>(static_cast<std::uint8_t>(b[index])) << 8U) |
           static_cast<std::uint32_t>(static_cast<std::uint8_t>(b[index + 1]));
  }
  if (index < b.size()) {
    sum += static_cast<std::uint32_t>(static_cast<std::uint8_t>(b[index])) << 8U;
  }
  while ((sum >> 16U) != 0) sum = (sum & 0xFFFFU) + (sum >> 16U);
  return static_cast<std::uint16_t>(~sum);
}
}

std::size_t rawproto_envelope_size(RawProto proto) noexcept {
  switch (proto) {
    case RawProto::gre: return kGreHeaderSize;
    case RawProto::esp: return kEspHeaderSize;
    case RawProto::ah: return kAhHeaderSize;
    case RawProto::ipip: return kIpipHeaderSize;
    case RawProto::ospf: return kOspfHeaderSize;
  }
  return 0U;
}

int rawproto_number(RawProto proto) noexcept {
  switch (proto) {
    case RawProto::gre: return kGreProtocol;
    case RawProto::esp: return kEspProtocol;
    case RawProto::ah: return kAhProtocol;
    case RawProto::ospf: return kOspfProtocol;
    case RawProto::ipip: break;
  }
  return kIpipProtocol;
}

#if !defined(__linux__)

bool RawProtoTransport::supported() noexcept { return false; }

std::expected<void, TransportError> RawProtoTransport::start(const Endpoint&, Role) {
  return std::unexpected(TransportError::unsupported_platform);
}

void RawProtoTransport::stop() noexcept { socket_.reset(); }

std::expected<void, TransportError> RawProtoTransport::set_mark(std::uint32_t) {
  return std::unexpected(TransportError::unsupported_platform);
}

std::size_t RawProtoTransport::build_frame(std::span<const std::byte>,
                                           std::span<std::byte>) const noexcept {
  return 0;
}

std::expected<std::size_t, TransportError> RawProtoTransport::send_batch(
    std::span<const OutboundDatagram>) {
  return std::unexpected(TransportError::unsupported_platform);
}

std::expected<std::size_t, TransportError> RawProtoTransport::receive_batch(
    ReceiveBuffers&, std::span<InboundDatagram>) {
  return std::unexpected(TransportError::unsupported_platform);
}

#else

bool RawProtoTransport::supported() noexcept { return true; }

bool RawProtoTransport::frame_matches(std::span<const std::byte> body) const noexcept {
  const auto envelope = rawproto_envelope_size(proto_);
  if (body.size() < envelope) return false;

  switch (proto_) {
    case RawProto::gre:
      if ((read_u16(body, 0) & kGreKeyFlags) == 0) return false;
      return read_u32(body, 4) == static_cast<std::uint32_t>(tag_);

    case RawProto::esp:
      if (read_u32(body, 0) != kEspSpi) return false;
      return read_u16(body, 4) == tag_;

    case RawProto::ah:
      if (static_cast<std::uint8_t>(body[0]) != 0x3B) return false;
      if (static_cast<std::uint8_t>(body[1]) != 0x04) return false;
      if (static_cast<std::uint8_t>(body[2]) != 0 || static_cast<std::uint8_t>(body[3]) != 0) {
        return false;
      }
      return read_u16(body, 4) == tag_;

    case RawProto::ospf:
      if (static_cast<std::uint8_t>(body[0]) != kOspfVersion) return false;
      return read_u16(body, 6) == tag_;

    case RawProto::ipip:
      if ((static_cast<std::uint8_t>(body[0]) & 0xF0U) != 0x40U) return false;
      if (static_cast<std::uint8_t>(body[9]) != kIpipInnerProtocol) return false;
      return read_u16(body, 4) == tag_;
  }
  return false;
}

std::size_t RawProtoTransport::build_frame(std::span<const std::byte> payload,
                                           std::span<std::byte> out) const noexcept {
  const auto envelope = rawproto_envelope_size(proto_);
  const auto total = envelope + payload.size();
  if (out.size() < total) return 0;

  switch (proto_) {
    case RawProto::gre:
      write_u16(out, 0, kGreKeyFlags);
      write_u16(out, 2, kGreProtocolType);
      write_u32(out, 4, static_cast<std::uint32_t>(tag_));
      break;

    case RawProto::esp:
      write_u32(out, 0, kEspSpi);
      write_u16(out, 4, tag_);
      break;

    case RawProto::ah:
      out[0] = static_cast<std::byte>(0x3B);
      out[1] = static_cast<std::byte>(0x04);
      out[2] = std::byte{0};
      out[3] = std::byte{0};
      write_u16(out, 4, tag_);
      break;

    case RawProto::ospf:
      out[0] = static_cast<std::byte>(kOspfVersion);
      out[1] = static_cast<std::byte>(kOspfHelloType);
      write_u16(out, 2, static_cast<std::uint16_t>(total));
      write_u16(out, 4, 0);
      write_u16(out, 6, tag_);
      std::fill(out.begin() + 8, out.begin() + static_cast<std::ptrdiff_t>(kOspfHeaderSize),
                std::byte{0});
      break;

    case RawProto::ipip: {
      out[0] = static_cast<std::byte>(0x45);
      out[1] = std::byte{0};
      write_u16(out, 2, static_cast<std::uint16_t>(total));
      write_u16(out, 4, tag_);
      write_u16(out, 6, 0x4000);
      out[8] = static_cast<std::byte>(kIpipInnerTtl);
      out[9] = static_cast<std::byte>(kIpipInnerProtocol);
      write_u16(out, 10, 0);
      std::fill(out.begin() + 12, out.begin() + static_cast<std::ptrdiff_t>(kIpipHeaderSize),
                std::byte{0});
      const auto header = out.first(kIpipHeaderSize);
      write_u16(out, 10, internet_checksum(header));
      break;
    }
  }

  std::copy(payload.begin(), payload.end(),
            out.begin() + static_cast<std::ptrdiff_t>(envelope));
  return total;
}

std::expected<void, TransportError> RawProtoTransport::start(const Endpoint& bind_address,
                                                             Role role) {
  if (socket_.valid()) return std::unexpected(TransportError::already_started);
  if (bind_address.family() == AddressFamily::ipv6) {
    return std::unexpected(TransportError::unsupported_platform);
  }
  const int proto = rawproto_number(proto_);
  FileDescriptor descriptor{::socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, proto)};
  if (!descriptor) return std::unexpected(TransportError::socket_creation_failed);

  const auto flags = ::fcntl(descriptor.get(), F_GETFL, 0);
  if (flags < 0 || ::fcntl(descriptor.get(), F_SETFL, flags | O_NONBLOCK) != 0) {
    return std::unexpected(TransportError::socket_option_failed);
  }

  family_ = AddressFamily::ipv4;
  socket_ = std::move(descriptor);
  role_ = role;
  scratch_.resize(rawproto_envelope_size(proto_) + kDefaultDatagramSize);
  return {};
}

void RawProtoTransport::stop() noexcept { socket_.reset(); }

std::expected<void, TransportError> RawProtoTransport::set_mark(std::uint32_t mark) {
  if (!socket_.valid()) return std::unexpected(TransportError::not_started);
  if (::setsockopt(socket_.get(), SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) != 0) {
    return std::unexpected(TransportError::socket_option_failed);
  }
  return {};
}

std::expected<std::size_t, TransportError> RawProtoTransport::send_batch(
    std::span<const OutboundDatagram> datagrams) {
  if (!socket_.valid()) return std::unexpected(TransportError::not_started);

  std::size_t sent = 0;
  for (const auto& datagram : datagrams) {
    if (datagram.destination.family() != AddressFamily::ipv4) {
      ++stats_.tx_errors;
      continue;
    }
    const auto needed = rawproto_envelope_size(proto_) + datagram.payload.size();
    if (scratch_.size() < needed) scratch_.resize(needed);
    const auto framed = build_frame(datagram.payload, scratch_);
    if (framed == 0) {
      ++stats_.tx_errors;
      continue;
    }
    const auto octets = datagram.destination.address().bytes();
    sockaddr_in dest{};
    dest.sin_family = AF_INET;
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

std::expected<std::size_t, TransportError> RawProtoTransport::receive_batch(
    ReceiveBuffers& buffers, std::span<InboundDatagram> out) {
  if (!socket_.valid()) return std::unexpected(TransportError::not_started);
  if (out.empty()) return std::size_t{0};

  const auto envelope = rawproto_envelope_size(proto_);
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
    const auto datagram = slot.first(static_cast<std::size_t>(got));
    if (datagram.empty()) {
      ++stats_.rx_errors;
      continue;
    }
    const auto version = static_cast<std::uint8_t>(datagram[0]) >> 4U;
    if (version != 4) {
      ++stats_.rx_errors;
      continue;
    }
    const auto ihl = (static_cast<std::uint8_t>(datagram[0]) & 0x0FU) * 4U;
    if (datagram.size() < ihl + envelope) continue;
    const auto body = datagram.subspan(ihl);
    if (!frame_matches(body)) continue;

    const auto payload = body.subspan(envelope);

    std::array<std::byte, 4> raw{};
    std::memcpy(raw.data(), &from.sin_addr.s_addr, 4);
    const auto source = Address::from_bytes(AddressFamily::ipv4, raw);

    out[received] = InboundDatagram{.source = Endpoint{source, 0}, .payload = payload};
    ++received;
    ++stats_.rx_packets;
    stats_.rx_bytes += payload.size();
  }
  return received;
}

#endif
}
