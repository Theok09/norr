// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#pragma once

#include <algorithm>
#include <cstddef>
#include <chrono>
#include <expected>
#include <memory>
#include <span>
#include <string_view>
#include <vector>

#include "norr/endpoint.hpp"
#include "norr/icmp_transport.hpp"
#include "norr/obfuscation.hpp"
#include "norr/path_selector.hpp"
#include "norr/quic_transport.hpp"
#include "norr/noise.hpp"
#include "norr/tcp_transport.hpp"
#include "norr/udp_transport.hpp"

namespace norr {
class Carrier {
 public:
  virtual ~Carrier() = default;

  [[nodiscard]] virtual TransportKind kind() const noexcept = 0;

  [[nodiscard]] virtual std::expected<std::size_t, TransportError> send_batch(
      std::span<const OutboundDatagram> datagrams) = 0;

  [[nodiscard]] virtual std::expected<std::size_t, TransportError> receive_batch(
      ReceiveBuffers& buffers, std::span<InboundDatagram> out) = 0;

  [[nodiscard]] virtual const TransportStats& stats() const noexcept = 0;

  [[nodiscard]] virtual std::size_t max_payload() const noexcept = 0;
};

class UdpCarrier final : public Carrier {
 public:
  explicit UdpCarrier(UdpTransport& transport) noexcept : transport_(&transport) {}

  void configure_obfuscation(const ObfuscationConfig& config,
                             const PresharedKey& preshared) {
    obfuscator_.configure(config, preshared);
  }

  [[nodiscard]] bool obfuscating() const noexcept { return obfuscator_.enabled(); }

  [[nodiscard]] TransportKind kind() const noexcept override { return TransportKind::udp; }

  [[nodiscard]] std::expected<std::size_t, TransportError> send_batch(
      std::span<const OutboundDatagram> datagrams) override;

  [[nodiscard]] std::expected<std::size_t, TransportError> receive_batch(
      ReceiveBuffers& buffers, std::span<InboundDatagram> out) override;

  [[nodiscard]] const TransportStats& stats() const noexcept override {
    return transport_->stats();
  }

  [[nodiscard]] std::size_t max_payload() const noexcept override {
    const auto base = UdpTransport::kDefaultDatagramSize;
    const auto overhead = obfuscator_.max_overhead();
    return overhead < base ? base - overhead : base;
  }

  void prime() noexcept { priming_pending_ = obfuscator_.config().priming; }

 private:
  UdpTransport* transport_;
  Obfuscator obfuscator_{};
  std::vector<std::vector<std::byte>> wrap_slots_;
  std::vector<OutboundDatagram> wrap_batch_;
  std::vector<std::vector<std::byte>> unwrap_slots_;
  bool priming_pending_{};
};

class IcmpCarrier final : public Carrier {
 public:
  IcmpCarrier(IcmpTransport& transport, const Endpoint& peer) noexcept
      : transport_(&transport), peer_(peer) {}

  void configure_obfuscation(const ObfuscationConfig& config, const PresharedKey& preshared) {
    obfuscator_.configure(config, preshared);
  }
  void prime() noexcept { priming_pending_ = obfuscator_.config().priming; }

  [[nodiscard]] TransportKind kind() const noexcept override { return TransportKind::icmp; }

  [[nodiscard]] std::expected<std::size_t, TransportError> send_batch(
      std::span<const OutboundDatagram> datagrams) override;

  [[nodiscard]] std::expected<std::size_t, TransportError> receive_batch(
      ReceiveBuffers& buffers, std::span<InboundDatagram> out) override;

  [[nodiscard]] const TransportStats& stats() const noexcept override { return transport_->stats(); }

  [[nodiscard]] std::size_t max_payload() const noexcept override {
    const auto base = IcmpTransport::kDefaultDatagramSize;
    const auto overhead = obfuscator_.max_overhead() + kIcmpHeaderSize;
    return overhead < base ? base - overhead : base;
  }

 private:
  IcmpTransport* transport_;
  Endpoint peer_{};
  Obfuscator obfuscator_{};
  std::vector<std::vector<std::byte>> wrap_slots_;
  std::vector<OutboundDatagram> wrap_batch_;
  std::vector<std::vector<std::byte>> unwrap_slots_;
  bool priming_pending_{};
};

class TcpCarrier final : public Carrier {
 public:

  TcpCarrier(TcpTransport& transport, const Endpoint& peer, bool dialing,
             const PresharedKey& preshared) noexcept
      : transport_(&transport), peer_(peer), dialing_(dialing), preshared_(preshared) {}

  [[nodiscard]] TransportKind kind() const noexcept override { return TransportKind::tcp_tls; }

  [[nodiscard]] std::expected<std::size_t, TransportError> send_batch(
      std::span<const OutboundDatagram> datagrams) override;

  [[nodiscard]] std::expected<std::size_t, TransportError> receive_batch(
      ReceiveBuffers& buffers, std::span<InboundDatagram> out) override;

  [[nodiscard]] const TransportStats& stats() const noexcept override { return stats_; }

  [[nodiscard]] std::size_t max_payload() const noexcept override { return kMaximumTcpFrame; }

  void poll(Instant now);

  void set_camouflage(std::string server_name) {
    camouflage_ = true;
    sni_ = std::move(server_name);
  }

  [[nodiscard]] bool ready() const noexcept {
    return transport_->connected() &&
           (camouflage_ ? transport_->camouflage_established() : transport_->tls_established());
  }

  void set_connections(std::size_t count) {
    target_ = std::clamp<std::size_t>(count, 1, 8);
    if (target_ > 1) extra_.reserve(target_ - 1);
  }
  [[nodiscard]] std::size_t target_connections() const noexcept { return target_; }
  [[nodiscard]] bool wants_more() const noexcept { return extra_.size() + 1 < target_; }
  void adopt(TcpTransport&& connection) {
    if (extra_.size() + 1 >= target_) return;
    extra_.push_back(std::move(connection));
    extra_started_.push_back(false);
  }

  template <typename Fn>
  void for_each_descriptor(Fn&& fn) const {
    if (transport_->connected()) fn(transport_->descriptor());
    for (const auto& conn : extra_) {
      if (conn.connected()) fn(conn.descriptor());
    }
  }

 private:
  void drive(TcpTransport& transport, bool& tls_started, bool dialing);

  TcpTransport* transport_;
  Endpoint peer_{};
  bool dialing_{};
  bool tls_started_{};
  bool camouflage_{};
  std::string sni_{};
  PresharedKey preshared_{};
  std::vector<std::span<const std::byte>> inbox_;
  TransportStats stats_{};
  std::size_t target_{1};
  std::vector<TcpTransport> extra_;
  std::vector<bool> extra_started_;
};

class QuicCarrier final : public Carrier {
 public:
  QuicCarrier(QuicConnection& connection, UdpTransport& socket, const Endpoint& peer,
              const Endpoint& local, bool listening) noexcept
      : connection_(&connection), socket_(&socket), peer_(peer), local_(local),
        listening_(listening) {}

  void poll();

  [[nodiscard]] bool ready() const noexcept { return connection_->established(); }

  [[nodiscard]] TransportKind kind() const noexcept override { return TransportKind::quic; }

  [[nodiscard]] std::expected<std::size_t, TransportError> send_batch(
      std::span<const OutboundDatagram> datagrams) override;

  [[nodiscard]] std::expected<std::size_t, TransportError> receive_batch(
      ReceiveBuffers& buffers, std::span<InboundDatagram> out) override;

  [[nodiscard]] const TransportStats& stats() const noexcept override { return stats_; }

  [[nodiscard]] std::size_t max_payload() const noexcept override {
    return connection_->max_datagram_size();
  }

 private:
  void flush();

  QuicConnection* connection_;
  UdpTransport* socket_;
  Endpoint peer_;
  Endpoint local_{};
  static constexpr auto kSetupTimeout = std::chrono::seconds{12};
  static constexpr auto kRedialDelay = std::chrono::seconds{2};

  bool listening_{};
  bool dialed_{};
  bool accepted_{};
  std::chrono::steady_clock::time_point started_{};
  std::chrono::steady_clock::time_point next_dial_{};
  std::vector<std::span<const std::byte>> inbox_;
  TransportStats stats_{};
};
}
