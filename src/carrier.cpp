// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#include "norr/carrier.hpp"

#include <array>

namespace norr {
void TcpCarrier::poll(Instant now) {
  static_cast<void>(now);

  if (dialing_ && transport_->state() == TcpState::closed) {
    tls_started_ = false;
    static_cast<void>(transport_->connect(peer_));
    return;
  }

  if (transport_->state() == TcpState::connecting) {
    const auto connected = transport_->poll_connect();
    if (!connected || !*connected) return;
  }

  if (transport_->state() == TcpState::failed) {
    // A failed connection is closed so the next poll redials. The peer keeps
    // its session: a carrier dropping is not a reason to rekey.
    transport_->close();
    tls_started_ = false;
    return;
  }

  if (!transport_->connected()) return;

  if (!tls_started_) {
    const auto role = dialing_ ? TlsRole::client : TlsRole::server;
    if (transport_->enable_tls(role, "norr", preshared_)) {
      tls_started_ = true;
    } else {
      return;
    }
  }

  if (!transport_->tls_established()) {
    static_cast<void>(transport_->poll_tls());
  }
}

std::expected<std::size_t, TransportError> TcpCarrier::send_batch(
    std::span<const OutboundDatagram> datagrams) {
  if (!ready()) return std::unexpected(TransportError::not_started);

  std::size_t sent = 0;
  for (const auto& datagram : datagrams) {
    const auto result = transport_->send_frame(datagram.payload);
    if (!result) {
      // would_block is back pressure, not a failure: the caller retries.
      if (result.error() == TransportError::would_block) break;
      ++stats_.tx_errors;
      return std::unexpected(result.error());
    }
    ++sent;
    ++stats_.tx_packets;
    stats_.tx_bytes += datagram.payload.size();
  }
  return sent;
}

std::expected<std::size_t, TransportError> TcpCarrier::receive_batch(
    ReceiveBuffers& buffers, std::span<InboundDatagram> out) {
  static_cast<void>(buffers);
  if (out.empty()) return std::size_t{0};
  if (!ready()) return std::size_t{0};

  inbox_.resize(out.size());
  const auto received = transport_->receive_frames(inbox_);
  if (!received) {
    ++stats_.rx_errors;
    return std::unexpected(received.error());
  }

  for (std::size_t index = 0; index < *received; ++index) {
    // Every frame on this connection came from the one peer at the far end,
    // so the source is known rather than read from each datagram.
    out[index] = InboundDatagram{.source = peer_, .payload = inbox_[index]};
    ++stats_.rx_packets;
    stats_.rx_bytes += inbox_[index].size();
  }
  return *received;
}

void QuicCarrier::flush() {
  auto* ngtcp2 = dynamic_cast<Ngtcp2Connection*>(connection_);
  if (ngtcp2 == nullptr) return;

  while (true) {
    const auto pending = ngtcp2->next_outgoing();
    if (pending.empty()) break;
    const std::array<OutboundDatagram, 1> wire{OutboundDatagram{peer_, pending}};
    if (!socket_->send_batch(wire)) break;
  }
}

void QuicCarrier::poll() {
  if (connection_->established()) return;

  // The dialing side starts the handshake once; the listening side has nothing
  // to do until an Initial arrives, which receive_batch handles.
  if (!listening_ && !dialed_) {
    dialed_ = true;
    if (!connection_->connect(peer_)) return;
  }

  flush();
}

std::expected<std::size_t, TransportError> QuicCarrier::send_batch(
    std::span<const OutboundDatagram> datagrams) {
  if (!connection_->established()) return std::unexpected(TransportError::send_failed);

  std::size_t accepted = 0;
  for (const auto& datagram : datagrams) {
    const auto sent = connection_->send_datagram(datagram.payload);
    if (!sent) break;
    ++accepted;
    ++stats_.tx_packets;
    stats_.tx_bytes += datagram.payload.size();
  }

  if (auto* ngtcp2 = dynamic_cast<Ngtcp2Connection*>(connection_); ngtcp2 != nullptr) {
    while (true) {
      const auto out = ngtcp2->next_outgoing();
      if (out.empty()) break;
      const std::array<OutboundDatagram, 1> wire{OutboundDatagram{peer_, out}};
      if (!socket_->send_batch(wire)) {
        ++stats_.tx_errors;
        break;
      }
    }
  }

  if (accepted == 0 && !datagrams.empty()) {
    ++stats_.tx_errors;
    return std::unexpected(TransportError::send_failed);
  }
  return accepted;
}

std::expected<std::size_t, TransportError> QuicCarrier::receive_batch(
    ReceiveBuffers& buffers, std::span<InboundDatagram> out) {
  if (out.empty()) return std::size_t{0};

  const auto received = socket_->receive_batch(buffers, out);
  if (!received) return received;

  auto* ngtcp2 = dynamic_cast<Ngtcp2Connection*>(connection_);
  if (ngtcp2 == nullptr) return received;

  for (std::size_t index = 0; index < *received; ++index) {
    // The listening side has no connection until the first Initial arrives.
    // Accepting it here is what makes a QUIC server possible without a
    // separate listener socket: ngtcp2 needs the datagram, not a socket.
    if (listening_ && !accepted_) {
      const std::vector<std::byte> initial(out[index].payload.begin(),
                                           out[index].payload.end());
      if (ngtcp2->accept(local_, out[index].source, initial)) {
        accepted_ = true;
        peer_ = out[index].source;
        ++stats_.rx_packets;
        continue;
      }
      // Not a valid Initial. Dropped rather than fed to a connection that does
      // not exist yet.
      ++stats_.rx_errors;
      continue;
    }
    static_cast<void>(ngtcp2->feed(out[index].payload));
  }

  flush();

  inbox_.resize(out.size());
  const auto count = connection_->receive_datagrams(inbox_);
  if (!count) return std::size_t{0};

  for (std::size_t index = 0; index < *count; ++index) {
    out[index] = InboundDatagram{.source = peer_, .payload = inbox_[index]};
    ++stats_.rx_packets;
    stats_.rx_bytes += inbox_[index].size();
  }
  return *count;
}

}
