#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "norr/endpoint.hpp"
#include "norr/file_descriptor.hpp"

namespace norr {
enum class TransportError {
  unsupported_platform,
  socket_creation_failed,
  socket_option_failed,
  bind_failed,
  send_failed,
  receive_failed,
  would_block,
  not_started,
  already_started,
  message_too_large,
};

[[nodiscard]] constexpr std::string_view transport_error_message(TransportError error) noexcept {
  switch (error) {
    case TransportError::unsupported_platform: return "transport not supported on this platform";
    case TransportError::socket_creation_failed: return "socket creation failed";
    case TransportError::socket_option_failed: return "socket option failed";
    case TransportError::bind_failed: return "bind failed";
    case TransportError::send_failed: return "send failed";
    case TransportError::receive_failed: return "receive failed";
    case TransportError::would_block: return "operation would block";
    case TransportError::not_started: return "transport not started";
    case TransportError::already_started: return "transport already started";
    case TransportError::message_too_large: return "message exceeds the receive buffer";
  }
  return "unknown transport error";
}

struct TransportStats {
  std::uint64_t rx_packets{};
  std::uint64_t tx_packets{};
  std::uint64_t rx_bytes{};
  std::uint64_t tx_bytes{};
  std::uint64_t rx_errors{};
  std::uint64_t tx_errors{};
  std::uint64_t rx_truncated{};

  std::uint64_t gso_writes{};
  std::uint64_t gso_segments{};
};

struct OffloadCapabilities {
  bool udp_gso{};
  bool udp_gro{};

  [[nodiscard]] std::string_view summary() const noexcept {
    if (udp_gso && udp_gro) return "GSO+GRO";
    if (udp_gso) return "GSO";
    if (udp_gro) return "GRO";
    return "none";
  }
};

struct OutboundDatagram {
  Endpoint destination;
  std::span<const std::byte> payload;
};

struct InboundDatagram {
  Endpoint source;
  std::span<const std::byte> payload;
};

class ReceiveBuffers {
 public:
  ReceiveBuffers(std::size_t count, std::size_t datagram_size);

  [[nodiscard]] std::size_t count() const noexcept { return count_; }
  [[nodiscard]] std::size_t datagram_size() const noexcept { return datagram_size_; }
  [[nodiscard]] std::span<std::byte> slot(std::size_t index) noexcept;

 private:
  std::size_t count_{};
  std::size_t datagram_size_{};
  std::vector<std::byte> storage_;
};

class UdpTransport {
 public:
  static constexpr std::size_t kDefaultBatchSize = 64;

  static constexpr std::size_t kDefaultDatagramSize = 2048;

  [[nodiscard]] static bool supported() noexcept;

  UdpTransport() = default;

  UdpTransport(const UdpTransport&) = delete;
  UdpTransport& operator=(const UdpTransport&) = delete;
  UdpTransport(UdpTransport&&) noexcept = default;
  UdpTransport& operator=(UdpTransport&&) noexcept = default;

  [[nodiscard]] std::expected<void, TransportError> start(const Endpoint& bind_address,
                                                          bool dual_stack = true);

  void stop() noexcept;

  [[nodiscard]] bool started() const noexcept { return socket_.valid(); }
  [[nodiscard]] int descriptor() const noexcept { return socket_.get(); }

  [[nodiscard]] std::expected<std::uint16_t, TransportError> local_port() const;

  [[nodiscard]] std::expected<std::size_t, TransportError> send_batch(
      std::span<const OutboundDatagram> datagrams);

  [[nodiscard]] std::expected<std::size_t, TransportError> receive_batch(
      ReceiveBuffers& buffers, std::span<InboundDatagram> out);

  [[nodiscard]] std::expected<std::size_t, TransportError> send_segmented(
      const Endpoint& destination, std::span<const std::byte> payload, std::size_t segment_size);

  [[nodiscard]] const OffloadCapabilities& offloads() const noexcept { return offloads_; }

  [[nodiscard]] const TransportStats& stats() const noexcept { return stats_; }

 private:
  FileDescriptor socket_;
#if defined(__linux__)

  AddressFamily family_{AddressFamily::ipv4};
#endif
  OffloadCapabilities offloads_{};
  TransportStats stats_{};
};

}
