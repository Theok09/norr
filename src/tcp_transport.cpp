#include "norr/tcp_transport.hpp"

#include <algorithm>
#include <cstring>

#if defined(__linux__)
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include <cerrno>
#endif

namespace norr {
namespace {
#if defined(__linux__)

[[nodiscard]] socklen_t fill_sockaddr(const Endpoint& endpoint, sockaddr_storage& storage) noexcept {
  std::memset(&storage, 0, sizeof(storage));
  const auto octets = endpoint.address().bytes();

  if (endpoint.family() == AddressFamily::ipv4) {
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
  std::memcpy(address.sin6_addr.s6_addr, octets.data(), 16);
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

bool FrameReassembler::push(std::span<const std::byte> bytes) {
  if (violated_) return false;
  buffer_.insert(buffer_.end(), bytes.begin(), bytes.end());
  return true;
}

void FrameReassembler::compact() {
  if (consumed_ == 0) return;
  buffer_.erase(buffer_.begin(), buffer_.begin() + static_cast<std::ptrdiff_t>(consumed_));
  consumed_ = 0;
}

std::span<const std::byte> FrameReassembler::next() {
  if (violated_) return {};

  const auto available = buffer_.size() - consumed_;
  if (available < kTcpLengthPrefixSize) {
    compact();
    return {};
  }

  const auto* const base = buffer_.data() + consumed_;
  const auto length = static_cast<std::size_t>(
      (static_cast<unsigned>(base[0]) << 8U) | static_cast<unsigned>(base[1]));

  if (length > maximum_frame_) {
    violated_ = true;
    return {};
  }
  if (available < kTcpLengthPrefixSize + length) {
    compact();
    return {};
  }

  frame_.assign(base + kTcpLengthPrefixSize, base + kTcpLengthPrefixSize + length);
  consumed_ += kTcpLengthPrefixSize + length;

  if (consumed_ > 65536 || consumed_ * 2 > buffer_.size()) compact();
  return frame_;
}

void FrameReassembler::reset() noexcept {
  buffer_.clear();
  frame_.clear();
  consumed_ = 0;
  violated_ = false;
}

Duration TcpReconnector::current_delay() const noexcept {
  auto delay = kInitialDelay;

  for (std::uint32_t step = 0; step < attempts_ && delay < kMaximumDelay; ++step) {
    delay *= 2;
  }
  return std::min<Duration>(delay, kMaximumDelay);
}

void TcpReconnector::note_disconnected(Instant now) {
  ++attempts_;
  next_attempt_ = now + current_delay();
}

void TcpReconnector::poll(TcpTransport& transport, Instant now) {
  switch (transport.state()) {
    case TcpState::connected:
      return;

    case TcpState::connecting: {
      const auto ready = transport.poll_connect();
      if (!ready) {
        transport.close();
        note_disconnected(now);
      } else if (*ready) {
        ++reconnects_;
      }
      return;
    }

    case TcpState::failed:

      transport.close();
      note_disconnected(now);
      return;

    case TcpState::closed:
      break;
  }

  if (next_attempt_ != Instant{} && now < next_attempt_) return;

  if (!transport.connect(peer_)) {
    note_disconnected(now);
  }
}

bool TcpTransport::supported() noexcept {
#if defined(__linux__)
  return true;
#else
  return false;
#endif
}

#if !defined(__linux__)

std::expected<void, TransportError> TcpTransport::connect(const Endpoint&) {
  return std::unexpected(TransportError::unsupported_platform);
}

std::expected<bool, TransportError> TcpTransport::poll_connect() {
  return std::unexpected(TransportError::unsupported_platform);
}

void TcpTransport::close() noexcept {
  socket_.reset();
  state_ = TcpState::closed;
}

std::expected<std::size_t, TransportError> TcpTransport::send_frame(std::span<const std::byte>) {
  return std::unexpected(TransportError::unsupported_platform);
}

std::expected<void, TransportError> TcpTransport::enable_tls(TlsRole, std::string_view,
                                                             std::span<const std::byte>) {
  return std::unexpected(TransportError::unsupported_platform);
}

std::expected<bool, TransportError> TcpTransport::poll_tls() {
  return std::unexpected(TransportError::unsupported_platform);
}

std::expected<std::size_t, TransportError> TcpTransport::receive_frames(
    std::span<std::span<const std::byte>>) {
  return std::unexpected(TransportError::unsupported_platform);
}

std::expected<void, TransportError> TcpListener::listen(const Endpoint&, int) {
  return std::unexpected(TransportError::unsupported_platform);
}

std::expected<std::optional<TcpTransport>, TransportError> TcpListener::accept() {
  return std::unexpected(TransportError::unsupported_platform);
}

std::expected<std::uint16_t, TransportError> TcpListener::local_port() const {
  return std::unexpected(TransportError::unsupported_platform);
}

#else

std::expected<void, TransportError> TcpTransport::connect(const Endpoint& peer) {
  if (state_ == TcpState::connected || state_ == TcpState::connecting) {
    return std::unexpected(TransportError::already_started);
  }

  const auto domain = peer.family() == AddressFamily::ipv4 ? AF_INET : AF_INET6;
  FileDescriptor descriptor{::socket(domain, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP)};
  if (!descriptor) return std::unexpected(TransportError::socket_creation_failed);

  const int enable = 1;
  if (::setsockopt(descriptor.get(), IPPROTO_TCP, TCP_NODELAY, &enable, sizeof(enable)) != 0) {
    return std::unexpected(TransportError::socket_option_failed);
  }
  if (!set_non_blocking(descriptor.get())) {
    return std::unexpected(TransportError::socket_option_failed);
  }

  sockaddr_storage storage{};
  const auto length = fill_sockaddr(peer, storage);

  const auto result =
      ::connect(descriptor.get(), reinterpret_cast<const sockaddr*>(&storage), length);
  if (result == 0) {
    socket_ = std::move(descriptor);
    state_ = TcpState::connected;
    reassembler_.reset();
    ++stats_.connects;
    return {};
  }
  if (errno == EINPROGRESS) {
    socket_ = std::move(descriptor);
    state_ = TcpState::connecting;
    reassembler_.reset();
    return {};
  }

  state_ = TcpState::failed;
  return std::unexpected(TransportError::send_failed);
}

std::expected<bool, TransportError> TcpTransport::poll_connect() {
  if (state_ == TcpState::connected) return true;
  if (state_ != TcpState::connecting) return std::unexpected(TransportError::not_started);

  int error = 0;
  socklen_t length = sizeof(error);
  if (::getsockopt(socket_.get(), SOL_SOCKET, SO_ERROR, &error, &length) != 0) {
    state_ = TcpState::failed;
    return std::unexpected(TransportError::socket_option_failed);
  }
  if (error == EINPROGRESS || error == EALREADY) return false;
  if (error != 0) {
    state_ = TcpState::failed;
    socket_.reset();
    return std::unexpected(TransportError::send_failed);
  }

  state_ = TcpState::connected;
  ++stats_.connects;
  return true;
}

void TcpTransport::close() noexcept {
  if (state_ == TcpState::connected) ++stats_.disconnects;
  socket_.reset();
  state_ = TcpState::closed;
  reassembler_.reset();
}

std::expected<std::size_t, TransportError> TcpTransport::send_frame(
    std::span<const std::byte> frame) {
  if (state_ != TcpState::connected) return std::unexpected(TransportError::not_started);
  if (frame.size() > kMaximumTcpFrame) {
    return std::unexpected(TransportError::message_too_large);
  }

  std::array<std::byte, kTcpLengthPrefixSize> prefix{};
  prefix[0] = static_cast<std::byte>((frame.size() >> 8U) & 0xFFU);
  prefix[1] = static_cast<std::byte>(frame.size() & 0xFFU);

  std::array<iovec, 2> vectors{};
  vectors[0].iov_base = prefix.data();
  vectors[0].iov_len = prefix.size();
  vectors[1].iov_base = const_cast<std::byte*>(frame.data());
  vectors[1].iov_len = frame.size();

  const auto total = prefix.size() + frame.size();
  std::size_t written = 0;

  if (tls_.has_value()) {
    if (!tls_->established()) return std::unexpected(TransportError::not_started);

    std::vector<std::byte> record;
    record.reserve(total);
    record.insert(record.end(), prefix.begin(), prefix.end());
    record.insert(record.end(), frame.begin(), frame.end());

    while (written < total) {
      const auto sent = tls_->send(std::span{record}.subspan(written));
      if (!sent) {
        if (sent.error() == TlsError::handshake_pending) {
          return std::unexpected(TransportError::would_block);
        }
        state_ = TcpState::failed;
        return std::unexpected(TransportError::send_failed);
      }
      if (*sent == 0) return std::unexpected(TransportError::would_block);
      written += *sent;
    }

    stats_.bytes_sent += total;
    ++stats_.frames_sent;
    return frame.size();
  }

  while (written < total) {
    if (written < prefix.size()) {
      vectors[0].iov_base = prefix.data() + written;
      vectors[0].iov_len = prefix.size() - written;
      vectors[1].iov_base = const_cast<std::byte*>(frame.data());
      vectors[1].iov_len = frame.size();
      const auto sent = ::writev(socket_.get(), vectors.data(), 2);
      if (sent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return std::unexpected(TransportError::would_block);
        if (errno == EINTR) continue;
        state_ = TcpState::failed;
        return std::unexpected(TransportError::send_failed);
      }
      written += static_cast<std::size_t>(sent);
    } else {
      const auto offset = written - prefix.size();
      const auto sent = ::write(socket_.get(), frame.data() + offset, frame.size() - offset);
      if (sent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return std::unexpected(TransportError::would_block);
        if (errno == EINTR) continue;
        state_ = TcpState::failed;
        return std::unexpected(TransportError::send_failed);
      }
      written += static_cast<std::size_t>(sent);
    }
  }

  stats_.bytes_sent += total;
  ++stats_.frames_sent;
  return frame.size();
}

std::expected<void, TransportError> TcpTransport::enable_tls(
    TlsRole role, std::string_view identity, std::span<const std::byte> preshared_key) {
  if (!socket_.valid()) return std::unexpected(TransportError::not_started);
  if (tls_.has_value()) return std::unexpected(TransportError::already_started);
  if (!tls_available()) return std::unexpected(TransportError::unsupported_platform);

  tls_.emplace();
  if (!tls_->start(socket_.get(), role, identity, preshared_key)) {
    tls_.reset();
    return std::unexpected(TransportError::not_started);
  }
  return {};
}

std::expected<bool, TransportError> TcpTransport::poll_tls() {
  if (!tls_.has_value()) return true;
  if (tls_->established()) return true;

  const auto done = tls_->handshake();
  if (!done) {
    if (done.error() == TlsError::handshake_pending) return false;
    state_ = TcpState::failed;
    return std::unexpected(TransportError::not_started);
  }
  return *done;
}

std::expected<std::size_t, TransportError> TcpTransport::receive_frames(
    std::span<std::span<const std::byte>> out) {
  if (state_ != TcpState::connected) return std::unexpected(TransportError::not_started);
  if (out.empty()) return std::size_t{0};

  if (read_buffer_.size() < 16384) read_buffer_.resize(16384);

  while (true) {
    ssize_t received = 0;
    bool drained = false;
    bool closed = false;

    if (tls_.has_value()) {
      if (!tls_->established()) return std::unexpected(TransportError::not_started);
      const auto got = tls_->receive(read_buffer_);
      if (!got) {
        if (got.error() == TlsError::closed) {
          closed = true;
        } else if (got.error() == TlsError::handshake_pending) {
          drained = true;
        } else {
          state_ = TcpState::failed;
          return std::unexpected(TransportError::receive_failed);
        }
      } else if (*got == 0) {
        drained = true;
      } else {
        received = static_cast<ssize_t>(*got);
      }
    } else {
      received = ::read(socket_.get(), read_buffer_.data(), read_buffer_.size());
      if (received == 0) {
        closed = true;
      } else if (received < 0) {
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          drained = true;
        } else {
          state_ = TcpState::failed;
          return std::unexpected(TransportError::receive_failed);
        }
      }
    }

    if (closed) {
      state_ = TcpState::failed;
      ++stats_.disconnects;
      break;
    }
    if (drained) break;

    if (!reassembler_.push(std::span{read_buffer_}.first(static_cast<std::size_t>(received)))) {
      state_ = TcpState::failed;
      return std::unexpected(TransportError::receive_failed);
    }
    stats_.bytes_received += static_cast<std::uint64_t>(received);
  }

  ready_.clear();
  while (ready_.size() < out.size()) {
    const auto frame = reassembler_.next();
    if (reassembler_.violated()) {
      ++stats_.oversized_rejected;
      state_ = TcpState::failed;
      return std::unexpected(TransportError::message_too_large);
    }
    if (frame.empty()) break;
    ready_.emplace_back(frame.begin(), frame.end());
  }

  for (std::size_t index = 0; index < ready_.size(); ++index) {
    out[index] = ready_[index];
  }
  stats_.frames_received += ready_.size();
  return ready_.size();
}

std::expected<void, TransportError> TcpListener::listen(const Endpoint& bind_address, int backlog) {
  if (socket_.valid()) return std::unexpected(TransportError::already_started);

  const auto domain = bind_address.family() == AddressFamily::ipv4 ? AF_INET : AF_INET6;
  FileDescriptor descriptor{::socket(domain, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP)};
  if (!descriptor) return std::unexpected(TransportError::socket_creation_failed);

  const int enable = 1;
  if (::setsockopt(descriptor.get(), SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) != 0) {
    return std::unexpected(TransportError::socket_option_failed);
  }
  if (!set_non_blocking(descriptor.get())) {
    return std::unexpected(TransportError::socket_option_failed);
  }

  sockaddr_storage storage{};
  const auto length = fill_sockaddr(bind_address, storage);
  if (::bind(descriptor.get(), reinterpret_cast<const sockaddr*>(&storage), length) != 0) {
    return std::unexpected(TransportError::bind_failed);
  }
  if (::listen(descriptor.get(), backlog) != 0) {
    return std::unexpected(TransportError::bind_failed);
  }

  socket_ = std::move(descriptor);
  return {};
}

std::expected<std::optional<TcpTransport>, TransportError> TcpListener::accept() {
  if (!socket_.valid()) return std::unexpected(TransportError::not_started);

  const auto descriptor = ::accept4(socket_.get(), nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
  if (descriptor < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) return std::optional<TcpTransport>{};
    return std::unexpected(TransportError::receive_failed);
  }

  const int enable = 1;
  static_cast<void>(::setsockopt(descriptor, IPPROTO_TCP, TCP_NODELAY, &enable, sizeof(enable)));

  TcpTransport accepted;
  accepted.socket_ = FileDescriptor{descriptor};
  accepted.state_ = TcpState::connected;
  return std::optional<TcpTransport>{std::move(accepted)};
}

std::expected<std::uint16_t, TransportError> TcpListener::local_port() const {
  if (!socket_.valid()) return std::unexpected(TransportError::not_started);

  sockaddr_storage storage{};
  socklen_t length = sizeof(storage);
  if (::getsockname(socket_.get(), reinterpret_cast<sockaddr*>(&storage), &length) != 0) {
    return std::unexpected(TransportError::socket_option_failed);
  }
  if (storage.ss_family == AF_INET) {
    sockaddr_in address{};
    std::memcpy(&address, &storage, sizeof(address));
    return ntohs(address.sin_port);
  }
  sockaddr_in6 address{};
  std::memcpy(&address, &storage, sizeof(address));
  return ntohs(address.sin6_port);
}

#endif

}
