// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#include "norr/carrier.hpp"

#include <algorithm>

#include <array>

namespace norr {
std::expected<std::size_t, TransportError> UdpCarrier::send_batch(
    std::span<const OutboundDatagram> datagrams) {
  if (!obfuscator_.enabled()) return transport_->send_batch(datagrams);

  if (priming_pending_ && !datagrams.empty()) {
    priming_pending_ = false;
    std::array<std::byte, kPrimingMaxSize> scratch{};
    std::array<std::byte, 1> pick{};
    std::size_t count = kPrimingMinPackets;
    if (random_bytes(pick)) {
      count += static_cast<std::size_t>(pick[0]) %
               (kPrimingMaxPackets - kPrimingMinPackets + 1U);
    }
    for (std::size_t index = 0; index < count; ++index) {
      const auto size = obfuscator_.generate_priming(scratch);
      if (!size) break;
      const std::array<OutboundDatagram, 1> wire{
          OutboundDatagram{.destination = datagrams.front().destination,
                           .payload = std::span{scratch}.first(*size)}};
      static_cast<void>(transport_->send_batch(wire));
    }
  }

  wrap_slots_.resize(datagrams.size());
  wrap_batch_.clear();
  wrap_batch_.reserve(datagrams.size());
  for (std::size_t index = 0; index < datagrams.size(); ++index) {
    auto& slot = wrap_slots_[index];
    slot.assign(datagrams[index].payload.size() + obfuscator_.max_overhead(), std::byte{0});
    const auto wrapped = obfuscator_.wrap(datagrams[index].payload, slot);
    if (!wrapped) continue;
    wrap_batch_.push_back(OutboundDatagram{.destination = datagrams[index].destination,
                                           .payload = std::span{slot}.first(*wrapped)});
  }
  if (wrap_batch_.empty()) return std::size_t{0};

  const auto sent = transport_->send_batch(wrap_batch_);
  if (!sent) return std::unexpected(sent.error());
  return std::min(*sent, datagrams.size());
}

std::expected<std::size_t, TransportError> UdpCarrier::receive_batch(
    ReceiveBuffers& buffers, std::span<InboundDatagram> out) {
  const auto received = transport_->receive_batch(buffers, out);
  if (!obfuscator_.enabled() || !received) return received;

  unwrap_slots_.resize(out.size());
  std::size_t kept = 0;
  for (std::size_t index = 0; index < *received; ++index) {
    auto& slot = unwrap_slots_[kept];
    slot.assign(out[index].payload.size(), std::byte{0});
    const auto plain = obfuscator_.unwrap(out[index].payload, slot);
    if (!plain) continue;
    out[kept] = InboundDatagram{.source = out[index].source,
                                .payload = std::span{slot}.first(*plain)};
    ++kept;
  }
  return kept;
}


std::expected<std::size_t, TransportError> IcmpCarrier::send_batch(
    std::span<const OutboundDatagram> datagrams) {
  const auto dest = [&](const OutboundDatagram& d) { return d.destination; };

  if (priming_pending_ && !datagrams.empty() && obfuscator_.enabled()) {
    priming_pending_ = false;
    std::array<std::byte, kPrimingMaxSize> scratch{};
    std::array<std::byte, 1> pick{};
    std::size_t count = kPrimingMinPackets;
    if (random_bytes(pick)) {
      count += static_cast<std::size_t>(pick[0]) % (kPrimingMaxPackets - kPrimingMinPackets + 1U);
    }
    for (std::size_t i = 0; i < count; ++i) {
      const auto size = obfuscator_.generate_priming(scratch);
      if (!size) break;
      const std::array<OutboundDatagram, 1> wire{
          OutboundDatagram{.destination = dest(datagrams.front()),
                           .payload = std::span{scratch}.first(*size)}};
      static_cast<void>(transport_->send_batch(wire));
    }
  }

  if (!obfuscator_.enabled()) return transport_->send_batch(datagrams);

  wrap_slots_.resize(datagrams.size());
  wrap_batch_.clear();
  wrap_batch_.reserve(datagrams.size());
  for (std::size_t i = 0; i < datagrams.size(); ++i) {
    auto& slot = wrap_slots_[i];
    slot.assign(datagrams[i].payload.size() + obfuscator_.max_overhead(), std::byte{0});
    const auto wrapped = obfuscator_.wrap(datagrams[i].payload, slot);
    if (!wrapped) continue;
    wrap_batch_.push_back(OutboundDatagram{.destination = datagrams[i].destination,
                                           .payload = std::span{slot}.first(*wrapped)});
  }
  if (wrap_batch_.empty()) return std::size_t{0};
  const auto sent = transport_->send_batch(wrap_batch_);
  if (!sent) return std::unexpected(sent.error());
  return std::min(*sent, datagrams.size());
}

std::expected<std::size_t, TransportError> IcmpCarrier::receive_batch(
    ReceiveBuffers& buffers, std::span<InboundDatagram> out) {
  const auto received = transport_->receive_batch(buffers, out);
  if (!received) return received;

  std::size_t kept = 0;
  if (obfuscator_.enabled()) unwrap_slots_.resize(out.size());
  for (std::size_t i = 0; i < *received; ++i) {
    const Endpoint source{out[i].source.address(), peer_.port()};
    if (obfuscator_.enabled()) {
      auto& slot = unwrap_slots_[kept];
      slot.assign(out[i].payload.size(), std::byte{0});
      const auto plain = obfuscator_.unwrap(out[i].payload, slot);
      if (!plain) continue;
      out[kept] = InboundDatagram{.source = source, .payload = std::span{slot}.first(*plain)};
    } else {
      out[kept] = InboundDatagram{.source = source, .payload = out[i].payload};
    }
    ++kept;
  }
  return kept;
}

void TcpCarrier::drive(TcpTransport& transport, bool& tls_started, bool dialing) {
  if (dialing && transport.state() == TcpState::closed) {
    tls_started = false;
    if (!sni_pool_.empty()) {
      sni_ = sni_pool_[sni_index_ % sni_pool_.size()];
      ++sni_index_;
    }
    static_cast<void>(transport.connect(peer_));
    return;
  }

  if (transport.state() == TcpState::connecting) {
    const auto connected = transport.poll_connect();
    if (!connected || !*connected) return;
  }

  if (transport.state() == TcpState::failed) {
    transport.close();
    tls_started = false;
    return;
  }

  if (!transport.connected()) return;

  if (camouflage_) {
    if (!tls_started) {
      const auto role = dialing ? CamouflageFramer::Role::client : CamouflageFramer::Role::server;
      apply_reality(transport);
      if (transport.enable_camouflage(role, sni_)) {
        tls_started = true;
      } else {
        return;
      }
    }
    if (!transport.camouflage_established()) {
      static_cast<void>(transport.poll_camouflage());
      return;
    }
    if (transport.has_pending_output()) static_cast<void>(transport.flush_output());
    return;
  }

  if (!tls_started) {
    const auto role = dialing ? TlsRole::client : TlsRole::server;
    if (transport.enable_tls(role, "norr", preshared_)) {
      tls_started = true;
    } else {
      return;
    }
  }

  if (!transport.tls_established()) {
    static_cast<void>(transport.poll_tls());
    return;
  }

  if (transport.has_pending_output()) static_cast<void>(transport.flush_output());
}

void TcpCarrier::poll(Instant now) {
  static_cast<void>(now);
  drive(*transport_, tls_started_, dialing_);

  if (dialing_) {
    while (extra_.size() + 1 < target_) {
      extra_.emplace_back();
      extra_started_.push_back(false);
    }
  }
  for (std::size_t index = 0; index < extra_.size(); ++index) {
    bool started = extra_started_[index];
    drive(extra_[index], started, dialing_);
    extra_started_[index] = started;
  }

  if (!dialing_) reap();
}

void TcpCarrier::reap() noexcept {
  for (std::size_t index = extra_.size(); index-- > 0;) {
    const auto state = extra_[index].state();
    if (state == TcpState::closed || state == TcpState::failed) {
      extra_.erase(extra_.begin() + static_cast<std::ptrdiff_t>(index));
      extra_started_.erase(extra_started_.begin() + static_cast<std::ptrdiff_t>(index));
    }
  }
}

void TcpCarrier::reset_all() noexcept {
  transport_->close();
  tls_started_ = false;
  for (auto& conn : extra_) conn.close();
  std::fill(extra_started_.begin(), extra_started_.end(), false);
}

std::expected<std::size_t, TransportError> TcpCarrier::send_batch(
    std::span<const OutboundDatagram> datagrams) {
  const auto ready = [this](const TcpTransport& conn) {
    return conn.connected() &&
           (camouflage_ ? conn.camouflage_established() : conn.tls_established());
  };
  std::array<TcpTransport*, 8> ready_conns{};
  std::size_t count = 0;
  if (ready(*transport_)) ready_conns[count++] = transport_;
  for (auto& conn : extra_) {
    if (count >= ready_conns.size()) break;
    if (ready(conn)) ready_conns[count++] = &conn;
  }
  if (count == 0) return std::unexpected(TransportError::not_started);

  std::size_t sent = 0;
  for (const auto& datagram : datagrams) {
    auto payload = datagram.payload;
    if (obfuscator_.enabled()) {
      wrap_scratch_.assign(datagram.payload.size() + obfuscator_.max_overhead(), std::byte{0});
      const auto wrapped = obfuscator_.wrap(datagram.payload, wrap_scratch_);
      if (!wrapped) {
        ++stats_.tx_errors;
        continue;
      }
      payload = std::span{wrap_scratch_}.first(*wrapped);
    }

    bool delivered = false;
    const std::size_t base = datagram.flow % count;
    for (std::size_t attempt = 0; attempt < count; ++attempt) {
      auto* conn = ready_conns[(base + attempt) % count];
      const auto result = conn->send_frame(payload);
      if (result) {
        delivered = true;
        break;
      }
      if (result.error() != TransportError::would_block) {
        ++stats_.tx_errors;
        return sent > 0 ? std::expected<std::size_t, TransportError>{sent}
                        : std::unexpected(result.error());
      }
    }
    if (!delivered) break;
    ++sent;
    ++stats_.tx_packets;
    stats_.tx_bytes += payload.size();
  }
  return sent;
}

std::expected<std::size_t, TransportError> TcpCarrier::receive_batch(
    ReceiveBuffers& buffers, std::span<InboundDatagram> out) {
  static_cast<void>(buffers);
  if (out.empty()) return std::size_t{0};

  std::size_t delivered = 0;
  const auto drain = [&](TcpTransport& conn) {
    if (delivered >= out.size()) return;
    if (!conn.connected()) return;
    if (!camouflage_ && !conn.tls_established()) return;
    inbox_.resize(out.size() - delivered);
    const auto received = conn.receive_frames(inbox_);
    if (!received) {
      ++stats_.rx_errors;
      return;
    }
    if (obfuscator_.enabled() && unwrap_slots_.size() < out.size()) {
      unwrap_slots_.resize(out.size());
    }
    for (std::size_t index = 0; index < *received && delivered < out.size(); ++index) {
      stats_.rx_bytes += inbox_[index].size();
      if (obfuscator_.enabled()) {
        auto& slot = unwrap_slots_[delivered];
        slot.assign(inbox_[index].size(), std::byte{0});
        const auto plain = obfuscator_.unwrap(inbox_[index], slot);
        if (!plain) {
          ++stats_.rx_errors;
          continue;
        }
        out[delivered] = InboundDatagram{.source = peer_,
                                         .payload = std::span{slot}.first(*plain)};
      } else {
        out[delivered] = InboundDatagram{.source = peer_, .payload = inbox_[index]};
      }
      ++delivered;
      ++stats_.rx_packets;
    }
  };

  drain(*transport_);
  for (auto& conn : extra_) drain(conn);
  return delivered;
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
  const auto now = std::chrono::steady_clock::now();
  auto* ngtcp2 = dynamic_cast<Ngtcp2Connection*>(connection_);

  if (ngtcp2 != nullptr) {
    const bool stalled =
        ngtcp2->active() && !ngtcp2->established() && now - started_ > kSetupTimeout;
    if (ngtcp2->broken() || stalled) {
      ngtcp2->close();
      ++stats_.tx_errors;
      dialed_ = false;
      accepted_ = false;
      next_dial_ = now + kRedialDelay;
    }
    ngtcp2->service_timers();
  }

  if (!listening_ && !dialed_ && now >= next_dial_) {
    dialed_ = true;
    started_ = now;
    if (!connection_->connect(peer_)) next_dial_ = now + kRedialDelay;
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
    if (listening_ && !accepted_) {
      const std::vector<std::byte> initial(out[index].payload.begin(),
                                           out[index].payload.end());
      if (ngtcp2->accept(local_, out[index].source, initial)) {
        accepted_ = true;
        started_ = std::chrono::steady_clock::now();
        peer_ = out[index].source;
        ++stats_.rx_packets;
        continue;
      }

      ++stats_.rx_errors;
      continue;
    }
    if (!(out[index].source == peer_)) {
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
