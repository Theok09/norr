#include "norr/worker.hpp"

#include <algorithm>

namespace norr {
Worker::Worker(TunDevice& tun, Carrier& carrier, RoutingTable& routes,
               SessionTable& sessions)
    : tun_(&tun),
      transport_(&carrier),
      routes_(&routes),
      sessions_(&sessions),
      tun_read_buffer_(kFrameBufferSize),
      encrypt_buffer_(kFrameBufferSize + kPacketHeaderSize + kAeadTagSize +
                      kPaddingAlignment),
      pad_buffer_(kFrameBufferSize + kPaddingAlignment),
      decrypt_buffer_(kFrameBufferSize),
      receive_pool_(UdpTransport::kDefaultBatchSize, UdpTransport::kDefaultDatagramSize),
      inbound_(UdpTransport::kDefaultBatchSize) {}

DropReason Worker::forward_from_tun(std::span<const std::byte> frame) {
  const auto parsed = parse_ip_packet(frame);
  if (!parsed) {
    stats_.record_drop(DropReason::malformed_inner_packet);
    return DropReason::malformed_inner_packet;
  }

  const auto decision = routes_->classify(*parsed, kNoPeer);
  if (!decision) {
    const auto reason = [&] {
      switch (decision.decision) {
        case ForwardDecision::no_route: return DropReason::no_route;
        case ForwardDecision::source_not_authorized: return DropReason::source_not_authorized;
        case ForwardDecision::routing_loop: return DropReason::routing_loop;
        case ForwardDecision::hop_limit_exceeded: return DropReason::hop_limit;
        case ForwardDecision::multicast_denied:
        case ForwardDecision::unspecified_address:
        case ForwardDecision::loopback_address: return DropReason::policy_denied;

        case ForwardDecision::deliver_local:
        case ForwardDecision::forward: return DropReason::none;
      }
      return DropReason::policy_denied;
    }();
    stats_.record_drop(reason);
    return reason;
  }

  if (decision.decision == ForwardDecision::deliver_local) {
    stats_.record_drop(DropReason::no_route);
    return DropReason::no_route;
  }

  auto* session = sessions_->find_by_peer(decision.peer);
  if (session == nullptr) {
    stats_.record_drop(DropReason::no_session);
    return DropReason::no_session;
  }

  if (!session->endpoint().has_value()) {
    stats_.record_drop(DropReason::no_endpoint);
    return DropReason::no_endpoint;
  }

  // Pad the inner packet to a multiple of 16 before sealing, as WireGuard
  // does. Without it the ciphertext length is exactly the inner packet length,
  // so an observer reads the size of every packet the tunnel carries.
  //
  // No length field is needed to undo it: an IP header carries its own total
  // length, so the receiver takes that and ignores the rest.
  const auto padded = padded_length(frame.size());
  if (padded > pad_buffer_.size()) {
    stats_.record_drop(DropReason::oversized);
    return DropReason::oversized;
  }
  std::copy(frame.begin(), frame.end(), pad_buffer_.begin());
  std::fill(pad_buffer_.begin() + static_cast<std::ptrdiff_t>(frame.size()),
            pad_buffer_.begin() + static_cast<std::ptrdiff_t>(padded), std::byte{0});

  const auto sealed =
      session->seal(FrameType::data, std::span{pad_buffer_}.first(padded), encrypt_buffer_);
  if (!sealed) {
    const auto reason = sealed.error() == SessionError::counter_exhausted
                            ? DropReason::counter_exhausted
                            : DropReason::oversized;
    stats_.record_drop(reason);
    return reason;
  }

  const auto wire = std::span{encrypt_buffer_}.first(*sealed);

  if (queueing_enabled_) {
    const auto traffic_class = classify(*parsed, frame);
    const auto now = std::chrono::steady_clock::now();

    if (!scheduler_.enqueue(std::vector<std::byte>(wire.begin(), wire.end()), traffic_class, now,
                            *session->endpoint())) {
      stats_.record_drop(DropReason::send_failed);
      return DropReason::send_failed;
    }

    static_cast<void>(drain_queue(now));
    ++stats_.tun_to_udp;
    return DropReason::none;
  }

  const std::array<OutboundDatagram, 1> datagram{
      OutboundDatagram{.destination = *session->endpoint(), .payload = wire}};
  const auto sent = transport_->send_batch(datagram);
  if (!sent || *sent == 0) {
    stats_.record_drop(DropReason::send_failed);
    return DropReason::send_failed;
  }

  ++stats_.tun_to_udp;
  return DropReason::none;
}

void Worker::enable_queueing(double bytes_per_second, std::size_t burst_bytes, Instant now) {
  pacer_ = Pacer{bytes_per_second, burst_bytes, now};
  queueing_enabled_ = bytes_per_second > 0.0;
}

std::size_t Worker::drain_queue(Instant now) {
  if (!queueing_enabled_) return 0;

  std::size_t sent = 0;
  while (!scheduler_.empty()) {
    auto packet = scheduler_.dequeue(now);
    if (!packet) break;

    if (!pacer_.allow(packet->bytes.size(), now)) {
      static_cast<void>(scheduler_.enqueue(std::move(packet->bytes), packet->traffic_class,
                                           packet->enqueued_at, packet->destination));
      break;
    }

    const std::array<OutboundDatagram, 1> datagram{
        OutboundDatagram{.destination = packet->destination, .payload = packet->bytes}};
    const auto result = transport_->send_batch(datagram);
    if (!result || *result == 0) {
      stats_.record_drop(DropReason::send_failed);
      break;
    }
    ++sent;
  }
  return sent;
}

DropReason Worker::forward_from_transport(const Endpoint& source,
                                          std::span<const std::byte> datagram) {
  const auto view = parse_packet(datagram);
  if (!view) {
    stats_.record_drop(DropReason::malformed_outer_packet);
    return DropReason::malformed_outer_packet;
  }

  std::size_t plaintext_length = 0;
  PeerId ingress_peer = kNoPeer;

  auto* session = sessions_->find_by_key_id(view->header.key_id);
  if (session == nullptr) {
    if (!provisional_opener_) {
      stats_.record_drop(DropReason::no_session);
      return DropReason::no_session;
    }
    const auto promoted =
        provisional_opener_(*view, datagram, decrypt_buffer_, source);
    if (!promoted) {
      stats_.record_drop(DropReason::no_session);
      return DropReason::no_session;
    }

    session = sessions_->find_by_key_id(view->header.key_id);
    if (session == nullptr) {
      stats_.record_drop(DropReason::no_session);
      return DropReason::no_session;
    }
    plaintext_length = *promoted;
    ingress_peer = session->peer();
  } else {
    const auto opened = session->open(*view, datagram, decrypt_buffer_);
    if (!opened) {
      const auto reason = [&] {
        switch (opened.error()) {
          case SessionError::replayed: return DropReason::replayed;
          case SessionError::too_old: return DropReason::too_old;
          case SessionError::buffer_too_small: return DropReason::oversized;
          default: return DropReason::authentication_failed;
        }
      }();
      stats_.record_drop(reason);
      return reason;
    }

    session->note_authenticated_endpoint(source);
    plaintext_length = *opened;
    ingress_peer = session->peer();
  }

  if (view->header.type == FrameType::control) {
    ++stats_.keepalives_received;
    return DropReason::none;
  }

  // The sender padded to a 16-byte boundary, so the buffer is at least as long
  // as the packet and usually longer. `parse_ip_packet` requires the declared
  // length to match the span exactly, so the padding is removed first: the
  // length is read from the header, then the span is trimmed to it.
  const auto padded_plaintext = std::span{decrypt_buffer_}.first(plaintext_length);
  const auto declared = declared_ip_length(padded_plaintext);
  if (!declared || *declared > plaintext_length) {
    stats_.record_drop(DropReason::malformed_inner_packet);
    return DropReason::malformed_inner_packet;
  }
  const auto plaintext = padded_plaintext.first(*declared);

  const auto parsed = parse_ip_packet(plaintext);
  if (!parsed) {
    stats_.record_drop(DropReason::malformed_inner_packet);
    return DropReason::malformed_inner_packet;
  }

  const auto decision = routes_->classify(*parsed, ingress_peer);
  if (!decision) {
    const auto reason = [&] {
      switch (decision.decision) {
        case ForwardDecision::source_not_authorized: return DropReason::source_not_authorized;
        case ForwardDecision::no_route: return DropReason::no_route;
        case ForwardDecision::routing_loop: return DropReason::routing_loop;
        case ForwardDecision::hop_limit_exceeded: return DropReason::hop_limit;
        default: return DropReason::policy_denied;
      }
    }();
    stats_.record_drop(reason);
    return reason;
  }

  const auto written = tun_->write_frame(plaintext);
  if (!written) {
    stats_.record_drop(DropReason::tun_write_failed);
    return DropReason::tun_write_failed;
  }

  ++stats_.udp_to_tun;
  return DropReason::none;
}

std::size_t Worker::pump_tun_to_udp(std::size_t max_frames) {
  std::size_t forwarded = 0;
  for (std::size_t index = 0; index < max_frames; ++index) {
    const auto frame = tun_->read_frame(tun_read_buffer_);
    if (!frame) break;

    if (frame->empty()) break;
    if (forward_from_tun(*frame) == DropReason::none) ++forwarded;
  }
  return forwarded;
}

std::size_t Worker::pump_udp_to_tun(std::size_t max_datagrams) {
  std::size_t delivered = 0;
  std::size_t processed = 0;

  while (processed < max_datagrams) {
    const auto batch = std::min(max_datagrams - processed, inbound_.size());
    const auto received = transport_->receive_batch(receive_pool_, std::span{inbound_}.first(batch));
    if (!received || *received == 0) break;

    for (std::size_t index = 0; index < *received; ++index) {
      if (ingress_filter_ &&
          ingress_filter_(inbound_[index].source, inbound_[index].payload)) {
        continue;
      }
      if (forward_from_transport(inbound_[index].source, inbound_[index].payload) ==
          DropReason::none) {
        ++delivered;
      }
    }
    processed += *received;
  }
  return delivered;
}

std::size_t Worker::poll() { return pump_tun_to_udp() + pump_udp_to_tun(); }

}
