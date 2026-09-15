#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <string_view>
#include <vector>

#if defined(__linux__)
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#include "norr/endpoint.hpp"
#include "norr/udp_transport.hpp"

namespace norr {
enum class QuicError {
  unsupported,
  not_connected,
  already_connected,
  handshake_failed,
  datagram_too_large,
  send_failed,
  receive_failed,
  closed_by_peer,
};

[[nodiscard]] constexpr std::string_view quic_error_message(QuicError error) noexcept {
  switch (error) {
    case QuicError::unsupported: return "no QUIC implementation is linked";
    case QuicError::not_connected: return "QUIC connection not established";
    case QuicError::already_connected: return "QUIC connection already established";
    case QuicError::handshake_failed: return "QUIC handshake failed";
    case QuicError::datagram_too_large: return "datagram exceeds the negotiated limit";
    case QuicError::send_failed: return "QUIC send failed";
    case QuicError::receive_failed: return "QUIC receive failed";
    case QuicError::closed_by_peer: return "connection closed by peer";
  }
  return "unknown QUIC error";
}

inline constexpr std::size_t kMaxDatagramFrame = 1200;

struct QuicStats {
  std::uint64_t datagrams_sent{};
  std::uint64_t datagrams_received{};
  std::uint64_t bytes_sent{};
  std::uint64_t bytes_received{};
  std::uint64_t datagrams_dropped{};
  std::uint64_t handshakes{};
};

class QuicConnection {
 public:
  virtual ~QuicConnection() = default;

  [[nodiscard]] virtual std::expected<void, QuicError> connect(const Endpoint& peer) = 0;
  [[nodiscard]] virtual bool established() const noexcept = 0;
  virtual void close() noexcept = 0;

  [[nodiscard]] virtual std::expected<std::size_t, QuicError> send_datagram(
      std::span<const std::byte> payload) = 0;

  [[nodiscard]] virtual std::expected<std::size_t, QuicError> receive_datagrams(
      std::span<std::span<const std::byte>> out) = 0;

  [[nodiscard]] virtual std::size_t max_datagram_size() const noexcept = 0;

  [[nodiscard]] virtual const QuicStats& stats() const noexcept = 0;
};

[[nodiscard]] bool quic_available() noexcept;

[[nodiscard]] std::string_view quic_backend_version() noexcept;

[[nodiscard]] std::expected<std::unique_ptr<QuicConnection>, QuicError> make_quic_connection();

class Ngtcp2Connection final : public QuicConnection {
 public:
  Ngtcp2Connection();
  ~Ngtcp2Connection() override;

  Ngtcp2Connection(const Ngtcp2Connection&) = delete;
  Ngtcp2Connection& operator=(const Ngtcp2Connection&) = delete;

  [[nodiscard]] std::expected<void, QuicError> connect(const Endpoint& peer) override;
  [[nodiscard]] bool established() const noexcept override;
  void close() noexcept override;

  [[nodiscard]] std::expected<std::size_t, QuicError> send_datagram(
      std::span<const std::byte> payload) override;

  [[nodiscard]] std::expected<std::size_t, QuicError> receive_datagrams(
      std::span<std::span<const std::byte>> out) override;

  [[nodiscard]] std::size_t max_datagram_size() const noexcept override;
  [[nodiscard]] const QuicStats& stats() const noexcept override;

  [[nodiscard]] std::expected<void, QuicError> feed(std::span<const std::byte> datagram);

  [[nodiscard]] std::span<const std::byte> next_outgoing();

  [[nodiscard]] std::expected<void, QuicError> accept(const Endpoint& local,
                                                      const Endpoint& peer,
                                                      std::span<const std::byte> initial);

  struct Impl;

 private:
  std::unique_ptr<Impl> impl_;
};

class LoopbackQuicConnection final : public QuicConnection {
 public:
  static constexpr std::size_t kMaxDatagram = 1200;

  [[nodiscard]] std::expected<void, QuicError> connect(const Endpoint& peer) override;
  [[nodiscard]] bool established() const noexcept override { return established_; }
  void close() noexcept override;

  [[nodiscard]] std::expected<std::size_t, QuicError> send_datagram(
      std::span<const std::byte> payload) override;

  [[nodiscard]] std::expected<std::size_t, QuicError> receive_datagrams(
      std::span<std::span<const std::byte>> out) override;

  [[nodiscard]] std::size_t max_datagram_size() const noexcept override { return kMaxDatagram; }
  [[nodiscard]] const QuicStats& stats() const noexcept override { return stats_; }

  void deliver(std::span<const std::byte> payload);

 private:
  bool established_{};
  Endpoint peer_{};
  std::vector<std::vector<std::byte>> inbox_;
  std::vector<std::vector<std::byte>> ready_;
  QuicStats stats_{};
};

}
