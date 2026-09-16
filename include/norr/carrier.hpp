// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#pragma once

#include <cstddef>
#include <expected>
#include <memory>
#include <span>
#include <string_view>
#include <vector>

#include "norr/endpoint.hpp"
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

  [[nodiscard]] TransportKind kind() const noexcept override { return TransportKind::udp; }

  [[nodiscard]] std::expected<std::size_t, TransportError> send_batch(
      std::span<const OutboundDatagram> datagrams) override {
    return transport_->send_batch(datagrams);
  }

  [[nodiscard]] std::expected<std::size_t, TransportError> receive_batch(
      ReceiveBuffers& buffers, std::span<InboundDatagram> out) override {
    return transport_->receive_batch(buffers, out);
  }

  [[nodiscard]] const TransportStats& stats() const noexcept override {
    return transport_->stats();
  }

  [[nodiscard]] std::size_t max_payload() const noexcept override {
    return UdpTransport::kDefaultDatagramSize;
  }

 private:
  UdpTransport* transport_;
};

// Norr frames over one TLS-protected TCP connection.
//
// TCP is a stream, so a carrier over it serves exactly one peer: there is no
// source address per frame to tell peers apart the way a UDP socket does.
// Every frame that arrives came from the peer at the other end of this
// connection, which is what `peer_` reports.
//
// TLS is not optional here. Without it the carrier would put Norr frames on
// the wire in the clear, and while the frames are themselves sealed, the
// carrier is what a compatibility fallback exists to blend in with.
class TcpCarrier final : public Carrier {
 public:
  // Dialing side: connects, then keeps reconnecting with bounded backoff.
  // The TLS pre-shared key is the peer's own: a second secret would be one
  // more thing to distribute and get wrong.
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

  // Drives connect, TLS handshake and reconnect. The caller polls this from
  // its loop; nothing else advances the connection.
  void poll(Instant now);

  [[nodiscard]] bool ready() const noexcept {
    return transport_->connected() && transport_->tls_established();
  }

 private:
  TcpTransport* transport_;
  Endpoint peer_{};
  bool dialing_{};
  bool tls_started_{};
  PresharedKey preshared_{};
  std::vector<std::span<const std::byte>> inbox_;
  TransportStats stats_{};
};

// Norr frames inside QUIC DATAGRAM.
//
// The socket is shared with QUIC itself: every datagram that arrives is fed to
// ngtcp2, and what comes back out are the DATAGRAM payloads. Norr's own
// handshake rides inside those payloads rather than beside them, so the two
// protocols never contend for the same socket.
//
// A node with a configured peer endpoint dials. One without waits for an
// Initial and answers it, which is what `listening_` selects.
class QuicCarrier final : public Carrier {
 public:
  QuicCarrier(QuicConnection& connection, UdpTransport& socket, const Endpoint& peer,
              const Endpoint& local, bool listening) noexcept
      : connection_(&connection), socket_(&socket), peer_(peer), local_(local),
        listening_(listening) {}

  // Drives the QUIC handshake: dials on the initiating side, answers an
  // Initial on the listening one, and flushes whatever ngtcp2 wants to send.
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
  bool listening_{};
  bool dialed_{};
  bool accepted_{};
  std::vector<std::span<const std::byte>> inbox_;
  TransportStats stats_{};
};

}
