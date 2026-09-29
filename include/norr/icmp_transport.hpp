// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <vector>

#include "norr/endpoint.hpp"
#include "norr/file_descriptor.hpp"
#include "norr/udp_transport.hpp"

namespace norr {
inline constexpr std::uint8_t kIcmpEchoRequest = 8;
inline constexpr std::uint8_t kIcmpEchoReply = 0;
inline constexpr std::size_t kIcmpHeaderSize = 8;
inline constexpr std::uint16_t kNorrIcmpId = 0x4E52;

[[nodiscard]] std::uint16_t icmp_checksum(std::span<const std::byte> data) noexcept;

[[nodiscard]] std::size_t build_icmp_echo(std::uint8_t type, std::uint16_t identifier,
                                          std::uint16_t sequence,
                                          std::span<const std::byte> payload,
                                          std::span<std::byte> out) noexcept;

struct IcmpEchoView {
  std::uint8_t type{};
  std::uint16_t identifier{};
  std::uint16_t sequence{};
  std::span<const std::byte> payload;
};

[[nodiscard]] std::expected<IcmpEchoView, TransportError> parse_icmp_echo(
    std::span<const std::byte> datagram, bool includes_ip_header) noexcept;

class IcmpTransport {
 public:
  enum class Role { client, server };

  static constexpr std::size_t kDefaultDatagramSize = 2048;

  [[nodiscard]] static bool supported() noexcept;

  IcmpTransport() = default;
  IcmpTransport(const IcmpTransport&) = delete;
  IcmpTransport& operator=(const IcmpTransport&) = delete;
  IcmpTransport(IcmpTransport&&) noexcept = default;
  IcmpTransport& operator=(IcmpTransport&&) noexcept = default;

  [[nodiscard]] std::expected<void, TransportError> start(const Endpoint& bind_address,
                                                          Role role);

  void stop() noexcept;
  [[nodiscard]] bool started() const noexcept { return socket_.valid(); }

  [[nodiscard]] std::expected<void, TransportError> set_mark(std::uint32_t mark);
  [[nodiscard]] int descriptor() const noexcept { return socket_.get(); }

  [[nodiscard]] std::expected<std::size_t, TransportError> send_batch(
      std::span<const OutboundDatagram> datagrams);

  [[nodiscard]] std::expected<std::size_t, TransportError> receive_batch(
      ReceiveBuffers& buffers, std::span<InboundDatagram> out);

  [[nodiscard]] const TransportStats& stats() const noexcept { return stats_; }

 private:
  FileDescriptor socket_;
  [[maybe_unused]] Role role_{Role::client};
  [[maybe_unused]] std::uint16_t sequence_{};
  TransportStats stats_{};
  [[maybe_unused]] std::vector<std::byte> scratch_;
  [[maybe_unused]] std::vector<std::vector<std::byte>> rx_slots_;
};
}
