// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include "norr/camouflage.hpp"
#include "norr/endpoint.hpp"
#include "norr/file_descriptor.hpp"
#include "norr/ssh_framer.hpp"
#include "norr/rate_limit.hpp"
#include "norr/reality.hpp"
#include "norr/tls.hpp"
#include "norr/udp_transport.hpp"

namespace norr {
inline constexpr std::size_t kTcpLengthPrefixSize = 2;
inline constexpr std::size_t kMaximumTcpFrame = 65535;
inline constexpr std::size_t kTcpOutboxLimit = 4U * 1024U * 1024U;

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

enum class GreetProfile : std::uint8_t { pop3, smtp, xmpp };

struct GreetScript {
  std::string_view greeting;
  std::string_view client_reply;
  std::string_view server_ack;
  std::string_view client_final;
  std::string_view server_final;
};

[[nodiscard]] constexpr GreetScript greet_script(GreetProfile profile) noexcept {
  switch (profile) {
    case GreetProfile::smtp:
      return GreetScript{.greeting = "220 mail.example.com ESMTP Postfix\r\n",
                         .client_reply = "EHLO localhost\r\n",
                         .server_ack = "250-mail.example.com\r\n",
                         .client_final = "MAIL FROM:<norr@localhost>\r\n",
                         .server_final = "250 2.1.0 Ok\r\n"};
    case GreetProfile::xmpp:
      return GreetScript{
          .greeting = "<stream:stream xmlns='jabber:client' "
                      "xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>\r\n",
          .client_reply = "<?xml version='1.0'?><stream:stream to='example.com' "
                          "xmlns='jabber:client' version='1.0'>\r\n",
          .server_ack = "<stream:features/>\r\n",
          .client_final = "<iq type='get' id='n1'><ping xmlns='urn:xmpp:ping'/></iq>\r\n",
          .server_final = "<iq type='result' id='n1'/>\r\n"};
    case GreetProfile::pop3: break;
  }
  return GreetScript{.greeting = "+OK POP3 ready\r\n",
                     .client_reply = "USER norr\r\n",
                     .server_ack = "+OK\r\n",
                     .client_final = "PASS norr\r\n",
                     .server_final = "+OK logged in\r\n"};
}

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
      TlsRole role, std::string_view identity, std::span<const std::byte> preshared_key,
      std::string_view server_name = {});

  [[nodiscard]] bool tls_enabled() const noexcept { return tls_.has_value(); }

  [[nodiscard]] bool tls_established() const noexcept {
    return tls_.has_value() && tls_->established();
  }

  [[nodiscard]] std::expected<bool, TransportError> poll_tls();

  [[nodiscard]] std::expected<void, TransportError> enable_camouflage(
      CamouflageFramer::Role role, std::string server_name);

  [[nodiscard]] bool camouflage_enabled() const noexcept { return camo_.has_value(); }

  void set_reality_client(const PublicKey& server_public, const RealityShortId& short_id) {
    reality_mode_ = RealityMode::client;
    reality_server_public_ = server_public;
    reality_short_id_ = short_id;
  }
  void set_reality_server(const PrivateKey& server_private, std::uint64_t window_seconds) {
    reality_mode_ = RealityMode::server;
    reality_server_private_ = server_private;
    reality_window_ = window_seconds;
  }
  [[nodiscard]] bool reality_rejected() const noexcept {
    return camo_.has_value() && camo_->reality_rejected();
  }
  [[nodiscard]] bool reality_authenticated() const noexcept {
    return camo_.has_value() && camo_->reality_authenticated();
  }
  [[nodiscard]] std::vector<std::byte> take_fallback_prelude() {
    return camo_.has_value() ? camo_->take_fallback_prelude() : std::vector<std::byte>{};
  }
  [[nodiscard]] FileDescriptor release_socket() noexcept {
    state_ = TcpState::closed;
    reassembler_.reset();
    outbox_.clear();
    tls_.reset();
    camo_.reset();
    camo_ready_ = false;
    return std::move(socket_);
  }

  [[nodiscard]] bool camouflage_established() const noexcept { return camo_ready_; }

  [[nodiscard]] std::expected<bool, TransportError> poll_camouflage();

  [[nodiscard]] std::expected<void, TransportError> enable_pop3(bool client,
                                                            GreetProfile profile);

  [[nodiscard]] bool pop3_enabled() const noexcept { return pop3_active_; }

  [[nodiscard]] bool pop3_established() const noexcept { return pop3_ready_; }

  [[nodiscard]] std::expected<bool, TransportError> poll_pop3();

  [[nodiscard]] std::expected<void, TransportError> enable_ssh(bool client);

  [[nodiscard]] bool ssh_enabled() const noexcept { return ssh_active_; }

  [[nodiscard]] bool ssh_established() const noexcept { return ssh_ready_; }

  [[nodiscard]] std::expected<bool, TransportError> poll_ssh();

  [[nodiscard]] std::expected<bool, TransportError> poll_connect();

  void close() noexcept;

  [[nodiscard]] std::expected<std::size_t, TransportError> send_frame(
      std::span<const std::byte> frame);

  [[nodiscard]] std::expected<std::size_t, TransportError> receive_frames(
      std::span<std::span<const std::byte>> out);

  [[nodiscard]] std::expected<bool, TransportError> flush_output();
  [[nodiscard]] bool has_pending_output() const noexcept { return !outbox_.empty(); }

  [[nodiscard]] TcpState state() const noexcept { return state_; }
  [[nodiscard]] bool connected() const noexcept { return state_ == TcpState::connected; }

  void set_mark(std::uint32_t mark) noexcept;
  [[nodiscard]] int descriptor() const noexcept { return socket_.get(); }
  [[nodiscard]] const TcpStats& stats() const noexcept { return stats_; }

 private:
  friend class TcpListener;

  void apply_mark() noexcept;
  [[nodiscard]] std::expected<std::size_t, TransportError> write_some(
      std::span<const std::byte> bytes);

  FileDescriptor socket_;
  std::uint32_t mark_{};
  TcpState state_{TcpState::closed};
  FrameReassembler reassembler_;
  std::vector<std::byte> read_buffer_;
  std::vector<std::byte> outbox_;
  std::vector<std::byte> record_;

  std::vector<std::vector<std::byte>> ready_;
  std::size_t ready_head_{};
  std::optional<TlsSession> tls_;
  std::optional<CamouflageFramer> camo_;
  bool camo_ready_{};
  bool pop3_active_{};
  bool pop3_ready_{};
  bool pop3_client_{};
  std::size_t pop3_step_{};
  std::vector<std::byte> pop3_inbox_;
  GreetProfile pop3_profile_{GreetProfile::pop3};
  bool ssh_active_{};
  bool ssh_ready_{};
  bool ssh_client_{};
  std::vector<std::byte> ssh_inbox_;
  SshFramer ssh_framer_{};
  std::vector<std::byte> ssh_reassembly_;
  enum class RealityMode { off, client, server };
  RealityMode reality_mode_{RealityMode::off};
  PublicKey reality_server_public_{};
  PrivateKey reality_server_private_{};
  RealityShortId reality_short_id_{};
  std::uint64_t reality_window_{120};
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
  [[nodiscard]] int descriptor() const noexcept { return socket_.get(); }

 private:
  FileDescriptor socket_;
};
}
