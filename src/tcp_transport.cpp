// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
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

constexpr int kTcpNotSentLowat = 16384;

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

void TcpTransport::set_mark(std::uint32_t mark) noexcept {
  mark_ = mark;
  apply_mark();
}

void TcpTransport::apply_mark() noexcept {
#if defined(__linux__)
  if (mark_ == 0 || !socket_.valid()) return;
  static_cast<void>(::setsockopt(socket_.get(), SOL_SOCKET, SO_MARK, &mark_, sizeof(mark_)));
#endif
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

std::expected<bool, TransportError> TcpTransport::flush_output() {
  return std::unexpected(TransportError::unsupported_platform);
}

std::expected<bool, TransportError> TcpTransport::poll_tls() {
  return std::unexpected(TransportError::unsupported_platform);
}

std::expected<void, TransportError> TcpTransport::enable_camouflage(CamouflageFramer::Role,
                                                                    std::string) {
  return std::unexpected(TransportError::unsupported_platform);
}

std::expected<bool, TransportError> TcpTransport::poll_camouflage() {
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

namespace {
void apply_liveness(int descriptor) noexcept {
  const int enable = 1;
  static_cast<void>(::setsockopt(descriptor, SOL_SOCKET, SO_KEEPALIVE, &enable, sizeof(enable)));
#if defined(TCP_KEEPIDLE) && defined(TCP_KEEPINTVL) && defined(TCP_KEEPCNT)
  const int idle = 20;
  const int interval = 5;
  const int count = 4;
  static_cast<void>(::setsockopt(descriptor, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle)));
  static_cast<void>(
      ::setsockopt(descriptor, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(interval)));
  static_cast<void>(::setsockopt(descriptor, IPPROTO_TCP, TCP_KEEPCNT, &count, sizeof(count)));
#endif
#if defined(TCP_USER_TIMEOUT)
  const unsigned int user_timeout = 45000;
  static_cast<void>(::setsockopt(descriptor, IPPROTO_TCP, TCP_USER_TIMEOUT, &user_timeout,
                                 sizeof(user_timeout)));
#endif
}
}

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
#if defined(TCP_NOTSENT_LOWAT)
  const int lowat = kTcpNotSentLowat;
  static_cast<void>(
      ::setsockopt(descriptor.get(), IPPROTO_TCP, TCP_NOTSENT_LOWAT, &lowat, sizeof(lowat)));
#endif
  apply_liveness(descriptor.get());
  if (!set_non_blocking(descriptor.get())) {
    return std::unexpected(TransportError::socket_option_failed);
  }
  if (mark_ != 0) {
    static_cast<void>(
        ::setsockopt(descriptor.get(), SOL_SOCKET, SO_MARK, &mark_, sizeof(mark_)));
  }

  sockaddr_storage storage{};
  const auto length = fill_sockaddr(peer, storage);

  const auto result =
      ::connect(descriptor.get(), reinterpret_cast<const sockaddr*>(&storage), length);
  outbox_.clear();
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
  outbox_.clear();
  tls_.reset();
  camo_.reset();
  camo_ready_ = false;
}

std::expected<std::size_t, TransportError> TcpTransport::write_some(
    std::span<const std::byte> bytes) {
  if (tls_.has_value()) {
    if (!tls_->established()) return std::size_t{0};
    const auto sent = tls_->send(bytes);
    if (!sent) {
      if (sent.error() == TlsError::handshake_pending) return std::size_t{0};
      state_ = TcpState::failed;
      return std::unexpected(TransportError::send_failed);
    }
    return *sent;
  }

  while (true) {
    const auto sent = ::send(socket_.get(), bytes.data(), bytes.size(), MSG_NOSIGNAL);
    if (sent >= 0) return static_cast<std::size_t>(sent);
    if (errno == EINTR) continue;
    if (errno == EAGAIN || errno == EWOULDBLOCK) return std::size_t{0};
    state_ = TcpState::failed;
    return std::unexpected(TransportError::send_failed);
  }
}

std::expected<bool, TransportError> TcpTransport::flush_output() {
  if (state_ != TcpState::connected) return std::unexpected(TransportError::not_started);
  std::size_t offset = 0;
  while (offset < outbox_.size()) {
    const auto sent = write_some(std::span{outbox_}.subspan(offset));
    if (!sent) return std::unexpected(sent.error());
    if (*sent == 0) break;
    offset += *sent;
  }
  outbox_.erase(outbox_.begin(), outbox_.begin() + static_cast<std::ptrdiff_t>(offset));
  return outbox_.empty();
}

std::expected<std::size_t, TransportError> TcpTransport::send_frame(
    std::span<const std::byte> frame) {
  if (state_ != TcpState::connected) return std::unexpected(TransportError::not_started);
  if (frame.size() > kMaximumTcpFrame) {
    return std::unexpected(TransportError::message_too_large);
  }
  if (tls_.has_value() && !tls_->established()) return std::unexpected(TransportError::not_started);

  const auto drained = flush_output();
  if (!drained) return std::unexpected(drained.error());

  if (camo_.has_value()) {
    if (!*drained && outbox_.size() >= kTcpOutboxLimit) {
      return std::unexpected(TransportError::would_block);
    }
    auto wrapped = camo_->wrap(frame);
    std::size_t written = 0;
    if (*drained) {
      while (written < wrapped.size()) {
        const auto sent = write_some(std::span{wrapped}.subspan(written));
        if (!sent) return std::unexpected(sent.error());
        if (*sent == 0) break;
        written += *sent;
      }
    }
    if (written < wrapped.size()) {
      outbox_.insert(outbox_.end(),
                     wrapped.begin() + static_cast<std::ptrdiff_t>(written), wrapped.end());
    }
    stats_.bytes_sent += wrapped.size();
    ++stats_.frames_sent;
    return frame.size();
  }

  if (!*drained) return std::unexpected(TransportError::would_block);

  record_.resize(kTcpLengthPrefixSize + frame.size());
  record_[0] = static_cast<std::byte>((frame.size() >> 8U) & 0xFFU);
  record_[1] = static_cast<std::byte>(frame.size() & 0xFFU);
  std::copy(frame.begin(), frame.end(), record_.begin() + kTcpLengthPrefixSize);

  std::size_t written = 0;
  while (written < record_.size()) {
    const auto sent = write_some(std::span{record_}.subspan(written));
    if (!sent) return std::unexpected(sent.error());
    if (*sent == 0) break;
    written += *sent;
  }
  if (written < record_.size()) {
    outbox_.assign(record_.begin() + static_cast<std::ptrdiff_t>(written), record_.end());
  }

  stats_.bytes_sent += record_.size();
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

std::expected<void, TransportError> TcpTransport::enable_camouflage(CamouflageFramer::Role role,
                                                                    std::string server_name) {
  if (!socket_.valid()) return std::unexpected(TransportError::not_started);
  if (camo_.has_value() || tls_.has_value()) {
    return std::unexpected(TransportError::already_started);
  }
  camo_.emplace(role, std::move(server_name));
  if (reality_mode_ == RealityMode::client) {
    camo_->configure_reality_client(reality_server_public_, reality_short_id_);
  } else if (reality_mode_ == RealityMode::server) {
    camo_->configure_reality_server(reality_server_private_, reality_window_);
  }
  camo_ready_ = false;
  auto hello = camo_->open();
  if (!hello.empty()) {
    outbox_.insert(outbox_.end(), hello.begin(), hello.end());
    camo_ready_ = true;
  }
  return {};
}

std::expected<bool, TransportError> TcpTransport::poll_camouflage() {
  if (!camo_.has_value()) return true;
  if (state_ != TcpState::connected) return std::unexpected(TransportError::not_started);
  if (!outbox_.empty()) {
    const auto drained = flush_output();
    if (!drained) return std::unexpected(drained.error());
  }
  return camo_ready_;
}

std::expected<std::size_t, TransportError> TcpTransport::receive_frames(
    std::span<std::span<const std::byte>> out) {
  if (state_ != TcpState::connected) return std::unexpected(TransportError::not_started);
  if (out.empty()) return std::size_t{0};

  if (read_buffer_.size() < 65536) read_buffer_.resize(65536);

  if (camo_.has_value()) {
    if (ready_head_ >= ready_.size()) {
      ready_.clear();
      ready_head_ = 0;
      while (true) {
        const auto received = ::read(socket_.get(), read_buffer_.data(), read_buffer_.size());
        if (received == 0) {
          state_ = TcpState::failed;
          ++stats_.disconnects;
          break;
        }
        if (received < 0) {
          if (errno == EINTR) continue;
          if (errno == EAGAIN || errno == EWOULDBLOCK) break;
          state_ = TcpState::failed;
          return std::unexpected(TransportError::receive_failed);
        }
        camo_->feed(std::span{read_buffer_}.first(static_cast<std::size_t>(received)));
        stats_.bytes_received += static_cast<std::uint64_t>(received);
        while (true) {
          const auto payload = camo_->next_payload();
          if (!payload) break;
          ready_.emplace_back(payload->begin(), payload->end());
        }
        if (ready_.size() >= out.size()) break;
      }
      if (camo_->violated()) {
        state_ = TcpState::failed;
        return std::unexpected(TransportError::receive_failed);
      }
      auto reply = camo_->take_handshake_reply();
      if (!reply.empty()) {
        outbox_.insert(outbox_.end(), reply.begin(), reply.end());
        static_cast<void>(flush_output());
      }
      if (camo_->handshake_done()) camo_ready_ = true;
    }

    std::size_t n = 0;
    while (n < out.size() && ready_head_ < ready_.size()) {
      out[n++] = ready_[ready_head_++];
    }
    stats_.frames_received += n;
    return n;
  }

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
  apply_liveness(descriptor);
#if defined(TCP_NOTSENT_LOWAT)
  const int lowat = kTcpNotSentLowat;
  static_cast<void>(::setsockopt(descriptor, IPPROTO_TCP, TCP_NOTSENT_LOWAT, &lowat, sizeof(lowat)));
#endif

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
