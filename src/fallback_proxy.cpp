// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#include "norr/fallback_proxy.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <utility>

#if defined(__linux__)
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#endif

namespace norr {
#if !defined(__linux__)
std::expected<void, TransportError> FallbackProxy::start(FileDescriptor, const Endpoint&,
                                                         std::span<const std::byte>) {
  return std::unexpected(TransportError::unsupported_platform);
}
void FallbackProxy::pump() {}
void FallbackProxy::close() noexcept {}
#else
namespace {
void set_nonblocking(int fd) noexcept {
  const auto flags = ::fcntl(fd, F_GETFL, 0);
  if (flags >= 0) static_cast<void>(::fcntl(fd, F_SETFL, flags | O_NONBLOCK));
}

std::size_t fill_sockaddr(const Endpoint& endpoint, sockaddr_storage& storage) noexcept {
  std::memset(&storage, 0, sizeof(storage));
  const auto octets = endpoint.address().bytes();
  if (endpoint.family() == AddressFamily::ipv4) {
    auto* in = reinterpret_cast<sockaddr_in*>(&storage);
    in->sin_family = AF_INET;
    in->sin_port = htons(endpoint.port());
    std::memcpy(&in->sin_addr.s_addr, octets.data(), 4);
    return sizeof(sockaddr_in);
  }
  auto* in6 = reinterpret_cast<sockaddr_in6*>(&storage);
  in6->sin6_family = AF_INET6;
  in6->sin6_port = htons(endpoint.port());
  std::memcpy(&in6->sin6_addr, octets.data(), 16);
  return sizeof(sockaddr_in6);
}
}

std::expected<void, TransportError> FallbackProxy::start(FileDescriptor client,
                                                         const Endpoint& cover,
                                                         std::span<const std::byte> prelude) {
  const auto domain = cover.family() == AddressFamily::ipv4 ? AF_INET : AF_INET6;
  FileDescriptor cover_fd{::socket(domain, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP)};
  if (!cover_fd) return std::unexpected(TransportError::socket_creation_failed);
  set_nonblocking(cover_fd.get());
  set_nonblocking(client.get());

  sockaddr_storage storage{};
  const auto length = fill_sockaddr(cover, storage);
  const auto result =
      ::connect(cover_fd.get(), reinterpret_cast<const sockaddr*>(&storage),
                static_cast<socklen_t>(length));
  if (result != 0 && errno != EINPROGRESS) {
    return std::unexpected(TransportError::send_failed);
  }
  connecting_ = result != 0;

  client_ = std::move(client);
  cover_ = std::move(cover_fd);
  to_cover_.assign(prelude.begin(), prelude.end());
  active_ = true;
  return {};
}

void FallbackProxy::pump() {
  if (!active_) return;

  if (connecting_) {
    int error = 0;
    socklen_t len = sizeof(error);
    if (::getsockopt(cover_.get(), SOL_SOCKET, SO_ERROR, &error, &len) != 0 || error != 0) {
      close();
      return;
    }
    connecting_ = false;
  }

  const auto drain = [](int fd, std::vector<std::byte>& buf) -> bool {
    std::size_t off = 0;
    while (off < buf.size()) {
      const auto n = ::send(fd, buf.data() + off, buf.size() - off, MSG_NOSIGNAL);
      if (n > 0) {
        off += static_cast<std::size_t>(n);
        continue;
      }
      if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
      if (n < 0 && errno == EINTR) continue;
      return false;
    }
    buf.erase(buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(off));
    return true;
  };

  const auto pull = [](int fd, std::vector<std::byte>& dst, bool& eof) -> bool {
    std::array<std::byte, 16384> tmp{};
    while (dst.size() < kBufferLimit) {
      const auto n = ::recv(fd, tmp.data(), tmp.size(), 0);
      if (n > 0) {
        dst.insert(dst.end(), tmp.begin(), tmp.begin() + n);
        continue;
      }
      if (n == 0) { eof = true; break; }
      if (errno == EAGAIN || errno == EWOULDBLOCK) break;
      if (errno == EINTR) continue;
      return false;
    }
    return true;
  };

  if (!drain(cover_.get(), to_cover_)) { close(); return; }
  if (!drain(client_.get(), to_client_)) { close(); return; }

  if (!client_eof_ && !pull(client_.get(), to_cover_, client_eof_)) { close(); return; }
  if (!cover_eof_ && !pull(cover_.get(), to_client_, cover_eof_)) { close(); return; }

  if (!drain(cover_.get(), to_cover_)) { close(); return; }
  if (!drain(client_.get(), to_client_)) { close(); return; }

  if (client_eof_ && to_cover_.empty() && cover_eof_ && to_client_.empty()) {
    close();
  }
}

void FallbackProxy::close() noexcept {
  client_.reset();
  cover_.reset();
  to_cover_.clear();
  to_client_.clear();
  active_ = false;
}
#endif
}
