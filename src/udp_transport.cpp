#include "norr/udp_transport.hpp"

#include <algorithm>
#include <cstring>

#if defined(__linux__)
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#endif

namespace norr {
namespace {
#if defined(__linux__)

[[nodiscard]] Endpoint endpoint_from_sockaddr(const sockaddr_storage& storage) noexcept {
  if (storage.ss_family == AF_INET) {
    sockaddr_in address{};
    std::memcpy(&address, &storage, sizeof(address));
    std::array<std::byte, 4> octets{};
    std::memcpy(octets.data(), &address.sin_addr.s_addr, octets.size());
    return Endpoint{Address::from_bytes(AddressFamily::ipv4, octets), ntohs(address.sin_port)};
  }
  if (storage.ss_family == AF_INET6) {
    sockaddr_in6 address{};
    std::memcpy(&address, &storage, sizeof(address));
    std::array<std::byte, 16> octets{};
    std::memcpy(octets.data(), address.sin6_addr.s6_addr, octets.size());
    return Endpoint{Address::from_bytes(AddressFamily::ipv6, octets), ntohs(address.sin6_port)};
  }
  return Endpoint{};
}

[[nodiscard]] socklen_t sockaddr_from_endpoint(const Endpoint& endpoint, AddressFamily socket_family,
                                               sockaddr_storage& storage) noexcept {
  std::memset(&storage, 0, sizeof(storage));
  const auto octets = endpoint.address().bytes();

  if (socket_family == AddressFamily::ipv4) {
    if (endpoint.family() != AddressFamily::ipv4) return 0;
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(endpoint.port());
    std::memcpy(&address.sin_addr.s_addr, octets.data(), 4);
    std::memcpy(&storage, &address, sizeof(address));
    return sizeof(address);
  }

  sockaddr_in6 address{};
  address.sin6_family = AF_INET6;
  address.sin6_port = htons(endpoint.port());
  if (endpoint.family() == AddressFamily::ipv6) {
    std::memcpy(address.sin6_addr.s6_addr, octets.data(), 16);
  } else {
    address.sin6_addr.s6_addr[10] = 0xFF;
    address.sin6_addr.s6_addr[11] = 0xFF;
    std::memcpy(&address.sin6_addr.s6_addr[12], octets.data(), 4);
  }
  std::memcpy(&storage, &address, sizeof(address));
  return sizeof(address);
}

[[nodiscard]] bool set_non_blocking(int descriptor) noexcept {
  const auto flags = ::fcntl(descriptor, F_GETFL, 0);
  if (flags < 0) return false;
  return ::fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0;
}

#endif

}

ReceiveBuffers::ReceiveBuffers(std::size_t count, std::size_t datagram_size)
    : count_(count), datagram_size_(datagram_size), storage_(count * datagram_size) {}

std::span<std::byte> ReceiveBuffers::slot(std::size_t index) noexcept {
  if (index >= count_) return {};
  return std::span<std::byte>{storage_.data() + index * datagram_size_, datagram_size_};
}

bool UdpTransport::supported() noexcept {
#if defined(__linux__)
  return true;
#else
  return false;
#endif
}

#if !defined(__linux__)

std::expected<void, TransportError> UdpTransport::start(const Endpoint&, bool) {
  return std::unexpected(TransportError::unsupported_platform);
}

void UdpTransport::stop() noexcept { socket_.reset(); }

std::expected<std::uint16_t, TransportError> UdpTransport::local_port() const {
  return std::unexpected(TransportError::unsupported_platform);
}

std::expected<std::size_t, TransportError> UdpTransport::send_batch(
    std::span<const OutboundDatagram>) {
  return std::unexpected(TransportError::unsupported_platform);
}

std::expected<std::size_t, TransportError> UdpTransport::receive_batch(ReceiveBuffers&,
                                                                      std::span<InboundDatagram>) {
  return std::unexpected(TransportError::unsupported_platform);
}

std::expected<std::size_t, TransportError> UdpTransport::send_segmented(const Endpoint&,
                                                                        std::span<const std::byte>,
                                                                        std::size_t) {
  return std::unexpected(TransportError::unsupported_platform);
}

#else

std::expected<void, TransportError> UdpTransport::start(const Endpoint& bind_address,
                                                        bool dual_stack) {
  if (socket_.valid()) return std::unexpected(TransportError::already_started);

  const auto family = bind_address.family();
  const auto domain = family == AddressFamily::ipv4 ? AF_INET : AF_INET6;

  FileDescriptor descriptor{::socket(domain, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP)};
  if (!descriptor) return std::unexpected(TransportError::socket_creation_failed);

  const int enable = 1;
  if (::setsockopt(descriptor.get(), SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) != 0) {
    return std::unexpected(TransportError::socket_option_failed);
  }

  if (family == AddressFamily::ipv6) {
    const int only_v6 = dual_stack ? 0 : 1;
    if (::setsockopt(descriptor.get(), IPPROTO_IPV6, IPV6_V6ONLY, &only_v6, sizeof(only_v6)) != 0) {
      return std::unexpected(TransportError::socket_option_failed);
    }
  }

  if (!set_non_blocking(descriptor.get())) {
    return std::unexpected(TransportError::socket_option_failed);
  }

  sockaddr_storage storage{};
  std::memset(&storage, 0, sizeof(storage));
  socklen_t length = 0;
  if (family == AddressFamily::ipv4) {
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(bind_address.port());
    std::memcpy(&address.sin_addr.s_addr, bind_address.address().bytes().data(), 4);
    std::memcpy(&storage, &address, sizeof(address));
    length = sizeof(address);
  } else {
    sockaddr_in6 address{};
    address.sin6_family = AF_INET6;
    address.sin6_port = htons(bind_address.port());
    std::memcpy(address.sin6_addr.s6_addr, bind_address.address().bytes().data(), 16);
    std::memcpy(&storage, &address, sizeof(address));
    length = sizeof(address);
  }

  if (::bind(descriptor.get(), reinterpret_cast<const sockaddr*>(&storage), length) != 0) {
    return std::unexpected(TransportError::bind_failed);
  }

  socket_ = std::move(descriptor);
  family_ = family;
  stats_ = TransportStats{};

  offloads_ = OffloadCapabilities{};
#if defined(UDP_SEGMENT)
  {
    const int probe = 0;
    offloads_.udp_gso =
        ::setsockopt(socket_.get(), IPPROTO_UDP, UDP_SEGMENT, &probe, sizeof(probe)) == 0;
  }
#endif
#if defined(UDP_GRO)
  {
    const int enable_gro = 1;
    offloads_.udp_gro =
        ::setsockopt(socket_.get(), IPPROTO_UDP, UDP_GRO, &enable_gro, sizeof(enable_gro)) == 0;
  }
#endif
  return {};
}

void UdpTransport::stop() noexcept { socket_.reset(); }

std::expected<std::uint16_t, TransportError> UdpTransport::local_port() const {
  if (!socket_.valid()) return std::unexpected(TransportError::not_started);

  sockaddr_storage storage{};
  socklen_t length = sizeof(storage);
  if (::getsockname(socket_.get(), reinterpret_cast<sockaddr*>(&storage), &length) != 0) {
    return std::unexpected(TransportError::socket_option_failed);
  }
  return endpoint_from_sockaddr(storage).port();
}

std::expected<std::size_t, TransportError> UdpTransport::send_batch(
    std::span<const OutboundDatagram> datagrams) {
  if (!socket_.valid()) return std::unexpected(TransportError::not_started);
  if (datagrams.empty()) return std::size_t{0};

  const auto count = std::min(datagrams.size(), kDefaultBatchSize);
  std::array<mmsghdr, kDefaultBatchSize> messages{};
  std::array<iovec, kDefaultBatchSize> vectors{};
  std::array<sockaddr_storage, kDefaultBatchSize> addresses{};

  std::size_t prepared = 0;
  for (std::size_t index = 0; index < count; ++index) {
    const auto length = sockaddr_from_endpoint(datagrams[index].destination, family_,
                                               addresses[prepared]);

    if (length == 0) continue;

    vectors[prepared].iov_base = const_cast<std::byte*>(datagrams[index].payload.data());
    vectors[prepared].iov_len = datagrams[index].payload.size();

    auto& header = messages[prepared].msg_hdr;
    header.msg_name = &addresses[prepared];
    header.msg_namelen = length;
    header.msg_iov = &vectors[prepared];
    header.msg_iovlen = 1;
    ++prepared;
  }
  if (prepared == 0) return std::size_t{0};

  const auto sent = ::sendmmsg(socket_.get(), messages.data(), static_cast<unsigned>(prepared), 0);
  if (sent < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) return std::unexpected(TransportError::would_block);
    ++stats_.tx_errors;
    return std::unexpected(TransportError::send_failed);
  }

  const auto delivered = static_cast<std::size_t>(sent);
  for (std::size_t index = 0; index < delivered; ++index) {
    stats_.tx_bytes += messages[index].msg_len;
  }
  stats_.tx_packets += delivered;
  return delivered;
}

std::expected<std::size_t, TransportError> UdpTransport::receive_batch(
    ReceiveBuffers& buffers, std::span<InboundDatagram> out) {
  if (!socket_.valid()) return std::unexpected(TransportError::not_started);
  if (out.empty() || buffers.count() == 0) return std::size_t{0};

  const auto count = std::min({out.size(), buffers.count(), kDefaultBatchSize});
  std::array<mmsghdr, kDefaultBatchSize> messages{};
  std::array<iovec, kDefaultBatchSize> vectors{};
  std::array<sockaddr_storage, kDefaultBatchSize> addresses{};

  for (std::size_t index = 0; index < count; ++index) {
    const auto slot = buffers.slot(index);
    vectors[index].iov_base = slot.data();
    vectors[index].iov_len = slot.size();

    auto& header = messages[index].msg_hdr;
    header.msg_name = &addresses[index];
    header.msg_namelen = sizeof(sockaddr_storage);
    header.msg_iov = &vectors[index];
    header.msg_iovlen = 1;
  }

  const auto received = ::recvmmsg(socket_.get(), messages.data(), static_cast<unsigned>(count),
                                   MSG_DONTWAIT, nullptr);
  if (received < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) return std::size_t{0};
    ++stats_.rx_errors;
    return std::unexpected(TransportError::receive_failed);
  }

  std::size_t delivered = 0;
  for (std::size_t index = 0; index < static_cast<std::size_t>(received); ++index) {
    if ((messages[index].msg_hdr.msg_flags & MSG_TRUNC) != 0) {
      ++stats_.rx_truncated;
      continue;
    }

    const auto source = endpoint_from_sockaddr(addresses[index]);

    if (source.port() == 0) {
      ++stats_.rx_errors;
      continue;
    }

    const auto length = static_cast<std::size_t>(messages[index].msg_len);
    out[delivered] = InboundDatagram{
        .source = source,
        .payload = buffers.slot(index).first(length),
    };
    stats_.rx_bytes += length;
    ++delivered;
  }

  stats_.rx_packets += delivered;
  return delivered;
}

std::expected<std::size_t, TransportError> UdpTransport::send_segmented(
    const Endpoint& destination, std::span<const std::byte> payload, std::size_t segment_size) {
  if (!socket_.valid()) return std::unexpected(TransportError::not_started);
  if (payload.empty() || segment_size == 0) return std::size_t{0};

  const auto segments = (payload.size() + segment_size - 1) / segment_size;

  if (!offloads_.udp_gso || segments <= 1) {
    std::array<OutboundDatagram, kDefaultBatchSize> datagrams{};
    std::size_t prepared = 0;
    std::size_t sent_total = 0;

    for (std::size_t offset = 0; offset < payload.size();) {
      const auto length = std::min(segment_size, payload.size() - offset);
      datagrams[prepared++] = OutboundDatagram{.destination = destination,
                                               .payload = payload.subspan(offset, length)};
      offset += length;

      if (prepared == datagrams.size() || offset >= payload.size()) {
        const auto sent = send_batch(std::span{datagrams}.first(prepared));
        if (!sent) return std::unexpected(sent.error());
        sent_total += *sent;
        prepared = 0;
      }
    }
    return sent_total;
  }

#if defined(UDP_SEGMENT)
  sockaddr_storage storage{};
  const auto length = sockaddr_from_endpoint(destination, family_, storage);
  if (length == 0) return std::unexpected(TransportError::send_failed);

  iovec vector{};
  vector.iov_base = const_cast<std::byte*>(payload.data());
  vector.iov_len = payload.size();

  alignas(cmsghdr) std::array<std::byte, CMSG_SPACE(sizeof(std::uint16_t))> control{};

  msghdr header{};
  header.msg_name = &storage;
  header.msg_namelen = length;
  header.msg_iov = &vector;
  header.msg_iovlen = 1;
  header.msg_control = control.data();
  header.msg_controllen = control.size();

  auto* message = CMSG_FIRSTHDR(&header);
  message->cmsg_level = SOL_UDP;
  message->cmsg_type = UDP_SEGMENT;
  message->cmsg_len = CMSG_LEN(sizeof(std::uint16_t));
  const auto segment = static_cast<std::uint16_t>(segment_size);
  std::memcpy(CMSG_DATA(message), &segment, sizeof(segment));

  const auto written = ::sendmsg(socket_.get(), &header, 0);
  if (written < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) return std::unexpected(TransportError::would_block);
    ++stats_.tx_errors;
    return std::unexpected(TransportError::send_failed);
  }

  stats_.tx_bytes += static_cast<std::uint64_t>(written);
  stats_.tx_packets += segments;
  ++stats_.gso_writes;
  stats_.gso_segments += segments;
  return segments;
#else
  return std::unexpected(TransportError::unsupported_platform);
#endif
}

#endif

}
