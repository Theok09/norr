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
enum class RawProto { ipip, gre, esp, ah, ospf };

inline constexpr int kIpipProtocol = 4;
inline constexpr int kGreProtocol = 47;
inline constexpr int kEspProtocol = 50;
inline constexpr int kAhProtocol = 51;
inline constexpr int kOspfProtocol = 89;

inline constexpr std::size_t kGreHeaderSize = 8;
inline constexpr std::size_t kEspHeaderSize = 6;
inline constexpr std::size_t kAhHeaderSize = 6;
inline constexpr std::size_t kIpipHeaderSize = 20;
inline constexpr std::size_t kOspfHeaderSize = 24;

inline constexpr std::uint16_t kGreProtocolType = 0x0800;
inline constexpr std::uint16_t kGreKeyFlags = 0x2000;
inline constexpr std::uint32_t kEspSpi = 0xDEADBEEFU;
inline constexpr std::uint8_t kIpipInnerProtocol = 253;
inline constexpr std::uint8_t kIpipInnerTtl = 64;
inline constexpr std::uint8_t kOspfVersion = 2;
inline constexpr std::uint8_t kOspfHelloType = 1;
inline constexpr std::uint16_t kNorrRawTag = 0x4E52;

[[nodiscard]] std::size_t rawproto_envelope_size(RawProto proto) noexcept;
[[nodiscard]] int rawproto_number(RawProto proto) noexcept;

class RawProtoTransport {
 public:
  enum class Role { client, server };

  static constexpr std::size_t kDefaultDatagramSize = 2048;

  [[nodiscard]] static bool supported() noexcept;

  RawProtoTransport() = default;
  explicit RawProtoTransport(RawProto proto) noexcept : proto_(proto) {}
  RawProtoTransport(const RawProtoTransport&) = delete;
  RawProtoTransport& operator=(const RawProtoTransport&) = delete;
  RawProtoTransport(RawProtoTransport&&) noexcept = default;
  RawProtoTransport& operator=(RawProtoTransport&&) noexcept = default;

  [[nodiscard]] std::expected<void, TransportError> start(const Endpoint& bind_address, Role role);

  void stop() noexcept;
  [[nodiscard]] bool started() const noexcept { return socket_.valid(); }

  [[nodiscard]] std::expected<void, TransportError> set_mark(std::uint32_t mark);

  void set_tag(std::uint16_t tag) noexcept { tag_ = tag; }
  void set_spi(std::uint32_t spi) noexcept { spi_ = spi; }
  [[nodiscard]] int descriptor() const noexcept { return socket_.get(); }

  [[nodiscard]] std::expected<std::size_t, TransportError> send_batch(
      std::span<const OutboundDatagram> datagrams);

  [[nodiscard]] std::expected<std::size_t, TransportError> receive_batch(
      ReceiveBuffers& buffers, std::span<InboundDatagram> out);

  [[nodiscard]] const TransportStats& stats() const noexcept { return stats_; }

 private:
  [[nodiscard]] bool frame_matches(std::span<const std::byte> body) const noexcept;
  [[nodiscard]] std::size_t build_frame(std::span<const std::byte> payload,
                                        std::span<std::byte> out) const noexcept;

  FileDescriptor socket_;
  RawProto proto_{RawProto::gre};
  Role role_{Role::client};
  AddressFamily family_{AddressFamily::ipv4};
  std::uint16_t tag_{kNorrRawTag};
  std::uint32_t spi_{kEspSpi};
  TransportStats stats_{};
  std::vector<std::byte> scratch_;
  std::vector<std::vector<std::byte>> send_frames_;
};
}
