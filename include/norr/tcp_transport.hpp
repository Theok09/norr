#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include "norr/endpoint.hpp"
#include "norr/file_descriptor.hpp"
#include "norr/rate_limit.hpp"
#include "norr/tls.hpp"
#include "norr/udp_transport.hpp"

namespace norr {
inline constexpr std::size_t kTcpLengthPrefixSize = 2;
inline constexpr std::size_t kMaximumTcpFrame = 65535;

enum class TcpState { closed, connecting, connected, failed };

[[nodiscard]] constexpr std::string_view tcp_state_name(TcpState state) noexcept {
  switch (state) {
    case TcpState::closed: return "closed";
    case TcpState::connecting: return "connecting";
    case TcpState::connected: return "connected";
    case TcpState::failed: return "failed";
  }
  return "unknown";
}

struct TcpStats {
  std::uint64_t frames_sent{};
  std::uint64_t frames_received{};
  std::uint64_t bytes_sent{};
  std::uint64_t bytes_received{};
  std::uint64_t connects{};
  std::uint64_t disconnects{};
  std::uint64_t oversized_rejected{};
};

class FrameReassembler {
 public:
  explicit FrameReassembler(std::size_t maximum_frame = kMaximumTcpFrame)
      : maximum_frame_(maximum_frame) {}

  [[nodiscard]] bool push(std::span<const std::byte> bytes);

  [[nodiscard]] std::span<const std::byte> next();

  [[nodiscard]] std::size_t buffered() const noexcept { return buffer_.size() - consumed_; }
  [[nodiscard]] bool violated() const noexcept { return violated_; }

  void reset() noexcept;

 private:
  void compact();

  std::size_t maximum_frame_{kMaximumTcpFrame};
  std::vector<std::byte> buffer_;
  std::size_t consumed_{};
  std::vector<std::byte> frame_;
  bool violated_{};
};

class TcpTransport {
 public:
  [[nodiscard]] static bool supported() noexcept;

  TcpTransport() = default;

  TcpTransport(const TcpTransport&) = delete;
  TcpTransport& operator=(const TcpTransport&) = delete;
  TcpTransport(TcpTransport&&) noexcept = default;
  TcpTransport& operator=(TcpTransport&&) noexcept = default;

  [[nodiscard]] std::expected<void, TransportError> connect(const Endpoint& peer);

  [[nodiscard]] std::expected<void, TransportError> enable_tls(
      TlsRole role, std::string_view identity, std::span<const std::byte> preshared_key);

  [[nodiscard]] bool tls_enabled() const noexcept { return tls_.has_value(); }

  [[nodiscard]] bool tls_established() const noexcept {
    return tls_.has_value() && tls_->established();
  }

  [[nodiscard]] std::expected<bool, TransportError> poll_tls();

  [[nodiscard]] std::expected<bool, TransportError> poll_connect();

  void close() noexcept;

  [[nodiscard]] std::expected<std::size_t, TransportError> send_frame(
      std::span<const std::byte> frame);

  [[nodiscard]] std::expected<std::size_t, TransportError> receive_frames(
      std::span<std::span<const std::byte>> out);

  [[nodiscard]] TcpState state() const noexcept { return state_; }
  [[nodiscard]] bool connected() const noexcept { return state_ == TcpState::connected; }
  [[nodiscard]] int descriptor() const noexcept { return socket_.get(); }
  [[nodiscard]] const TcpStats& stats() const noexcept { return stats_; }

 private:
  friend class TcpListener;

  FileDescriptor socket_;
  TcpState state_{TcpState::closed};
  FrameReassembler reassembler_;
  std::vector<std::byte> read_buffer_;

  std::vector<std::vector<std::byte>> ready_;
  std::optional<TlsSession> tls_;
  TcpStats stats_{};
};

class TcpReconnector {
 public:
  static constexpr auto kInitialDelay = std::chrono::milliseconds{250};
  static constexpr auto kMaximumDelay = std::chrono::seconds{30};

  explicit TcpReconnector(Endpoint peer) noexcept : peer_(peer) {}

  void poll(TcpTransport& transport, Instant now);

  void note_disconnected(Instant now);

  [[nodiscard]] std::uint32_t attempts() const noexcept { return attempts_; }
  [[nodiscard]] Duration current_delay() const noexcept;
  [[nodiscard]] Instant next_attempt() const noexcept { return next_attempt_; }
  [[nodiscard]] std::uint64_t reconnects() const noexcept { return reconnects_; }

  void note_stable() noexcept { attempts_ = 0; }

 private:
  Endpoint peer_{};
  std::uint32_t attempts_{};
  Instant next_attempt_{};
  std::uint64_t reconnects_{};
};

class TcpListener {
 public:
  [[nodiscard]] std::expected<void, TransportError> listen(const Endpoint& bind_address,
                                                           int backlog = 16);

  [[nodiscard]] std::expected<std::optional<TcpTransport>, TransportError> accept();

  [[nodiscard]] std::expected<std::uint16_t, TransportError> local_port() const;

  void close() noexcept { socket_.reset(); }
  [[nodiscard]] bool listening() const noexcept { return socket_.valid(); }

 private:
  FileDescriptor socket_;
};

}
