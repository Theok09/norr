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
#include "norr/rawproto_transport.hpp"
#include "norr/spoof_feedback.hpp"
#include "norr/spoof_sender.hpp"
#include "norr/obfuscation.hpp"
#include "norr/path_selector.hpp"
#include "norr/quic_transport.hpp"
#include "norr/noise.hpp"
#include "norr/tcp_transport.hpp"
#include "norr/timers.hpp"
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

  void configure_spoofing(const std::vector<std::uint32_t>& sources_be,
                          std::uint16_t source_port) {
    if (sources_be.empty() || !SpoofSender::supported()) return;
    if (!sender_.open()) return;
    feedback_ = SpoofFeedback{SpoofPool{sources_be}};
    spoof_source_port_ = source_port;
    spoofing_ = true;
  }

  [[nodiscard]] bool spoofing() const noexcept { return spoofing_; }

  [[nodiscard]] std::uint64_t spoof_dropped_oversized() const noexcept {
    return sender_.dropped_oversized();
  }

  [[nodiscard]] std::uint64_t spoof_undeliverable() const noexcept { return spoof_undeliverable_; }

  void apply_spoof_receipt(std::span<const std::uint64_t> bitmap, Instant now) noexcept {
    if (spoofing_) feedback_.apply_receipt(bitmap, now);
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
  [[nodiscard]] std::expected<std::size_t, TransportError> send_spoofed(
      std::span<const OutboundDatagram> datagrams) noexcept;

  UdpTransport* transport_;
  Obfuscator obfuscator_{};
  std::vector<std::vector<std::byte>> wrap_slots_;
  std::vector<OutboundDatagram> wrap_batch_;
  std::vector<std::vector<std::byte>> unwrap_slots_;
  bool priming_pending_{};
  SpoofFeedback feedback_{};
  SpoofSender sender_{};
  std::vector<SpoofDatagram> spoof_batch_;
  std::vector<OutboundDatagram> real_batch_;
  std::uint16_t spoof_source_port_{};
  bool spoofing_{};
  std::uint64_t spoof_undeliverable_{};
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

class RawProtoCarrier final : public Carrier {
 public:
  RawProtoCarrier(RawProtoTransport& transport, const Endpoint& peer, TransportKind kind) noexcept
      : transport_(&transport), peer_(peer), kind_(kind) {}

  void configure_obfuscation(const ObfuscationConfig& config, const PresharedKey& preshared) {
    obfuscator_.configure(config, preshared);
  }
  void prime() noexcept { priming_pending_ = obfuscator_.config().priming; }

  [[nodiscard]] TransportKind kind() const noexcept override { return kind_; }

  [[nodiscard]] std::expected<std::size_t, TransportError> send_batch(
      std::span<const OutboundDatagram> datagrams) override;

  [[nodiscard]] std::expected<std::size_t, TransportError> receive_batch(
      ReceiveBuffers& buffers, std::span<InboundDatagram> out) override;

  [[nodiscard]] const TransportStats& stats() const noexcept override { return transport_->stats(); }

  [[nodiscard]] std::size_t max_payload() const noexcept override {
    const auto base = RawProtoTransport::kDefaultDatagramSize;
    const auto overhead = obfuscator_.max_overhead() + kEspHeaderSize + 2U;
    return overhead < base ? base - overhead : base;
  }

 private:
  RawProtoTransport* transport_;
  Endpoint peer_{};
  TransportKind kind_{TransportKind::gre};
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

  [[nodiscard]] std::size_t max_payload() const noexcept override {
    const auto overhead = obfuscator_.max_overhead();
    return overhead < kMaximumTcpFrame ? kMaximumTcpFrame - overhead : kMaximumTcpFrame;
  }

  void poll(Instant now);

  void set_camouflage(std::string server_name) {
    camouflage_ = true;
    sni_ = std::move(server_name);
  }

  void set_pop3(GreetProfile profile = GreetProfile::pop3) noexcept {
    pop3_ = true;
    greet_profile_ = profile;
  }

  void set_raw() noexcept { raw_ = true; }

  void set_sni_pool(std::vector<std::string> pool) {
    if (pool.empty()) return;
    sni_pool_ = std::move(pool);
    sni_ = sni_pool_.front();
  }

  void configure_obfuscation(const ObfuscationConfig& config,
                             const PresharedKey& preshared) {
    obfuscator_.configure(config, preshared);
  }

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

  [[nodiscard]] bool ready() const noexcept {
    return transport_->connected() &&
           (raw_ ? true
                 : (pop3_ ? transport_->pop3_established() : transport_->tls_established()));
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
    extra_slots_.push_back(ConnectionSlot{});
  }

  void reset_all() noexcept;

  void primary_replaced() noexcept { primary_slot_ = ConnectionSlot{}; }

  void primary_replaced_started() noexcept {
    primary_slot_ = ConnectionSlot{};
    primary_slot_.started = true;
  }

  void set_mark(std::uint32_t mark) noexcept { mark_ = mark; }

  [[nodiscard]] std::size_t ready_count() const noexcept;

  void reap() noexcept;

  template <typename Fn>
  void for_each_descriptor(Fn&& fn) const {
    if (transport_->connected()) fn(transport_->descriptor());
    for (const auto& conn : extra_) {
      if (conn.connected()) fn(conn.descriptor());
    }
  }

 private:
  struct ConnectionSlot {
    bool started{};
    Instant phase_since{};
    Instant next_attempt{};
    std::uint32_t failures{};
    Instant last_rx{};
  };

  [[nodiscard]] bool connection_ready(const TcpTransport& conn) const noexcept;
  void note_failure(ConnectionSlot& slot, Instant now) noexcept;
  void drive(TcpTransport& transport, ConnectionSlot& slot, bool dialing, Instant now);

  TcpTransport* transport_;
  Endpoint peer_{};
  bool dialing_{};
  ConnectionSlot primary_slot_{};
  std::uint32_t mark_{};
  bool camouflage_{};
  bool pop3_{};
  GreetProfile greet_profile_{GreetProfile::pop3};
  bool raw_{};
  std::string sni_{};
  std::vector<std::string> sni_pool_{};
  std::size_t sni_index_{};
  PresharedKey preshared_{};
  Obfuscator obfuscator_{};
  std::vector<std::byte> wrap_scratch_;
  std::vector<std::vector<std::byte>> unwrap_slots_;
  std::vector<std::span<const std::byte>> inbox_;
  TransportStats stats_{};
  std::size_t target_{1};
  std::vector<TcpTransport> extra_;
  std::vector<ConnectionSlot> extra_slots_;

  enum class RealityMode { off, client, server };
  RealityMode reality_mode_{RealityMode::off};
  PublicKey reality_server_public_{};
  PrivateKey reality_server_private_{};
  RealityShortId reality_short_id_{};
  std::uint64_t reality_window_{120};
  void apply_reality(TcpTransport& transport) const {
    if (reality_mode_ == RealityMode::client) {
      transport.set_reality_client(reality_server_public_, reality_short_id_);
    } else if (reality_mode_ == RealityMode::server) {
      transport.set_reality_server(reality_server_private_, reality_window_);
    }
  }
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
