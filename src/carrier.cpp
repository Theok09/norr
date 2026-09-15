#include "norr/carrier.hpp"

#include <array>

namespace norr {
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
    static_cast<void>(ngtcp2->feed(out[index].payload));
  }

  while (true) {
    const auto pending = ngtcp2->next_outgoing();
    if (pending.empty()) break;
    const std::array<OutboundDatagram, 1> wire{OutboundDatagram{peer_, pending}};
    if (!socket_->send_batch(wire)) break;
  }

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
