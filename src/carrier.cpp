// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#include "norr/log.hpp"
#include "norr/carrier.hpp"

#include <algorithm>

#include <array>
#include <cstdio>

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
                                           .payload = std::span{slot}.first(*wrapped),
                                           .flow = datagrams[index].flow,
                                           .spoofable = datagrams[index].spoofable});
  }
  if (wrap_batch_.empty()) return std::size_t{0};

  if (spoofing_) {
    const auto sent = send_spoofed(wrap_batch_);
    if (!sent) return std::unexpected(sent.error());
    return std::min(*sent, datagrams.size());
  }

  const auto sent = transport_->send_batch(wrap_batch_);
  if (!sent) return std::unexpected(sent.error());
  return std::min(*sent, datagrams.size());
}

std::expected<std::size_t, TransportError> UdpCarrier::send_spoofed(
    std::span<const OutboundDatagram> datagrams) noexcept {
  const auto now = std::chrono::steady_clock::now();
  spoof_batch_.clear();
  spoof_batch_.reserve(datagrams.size());
  real_batch_.clear();
  bool unspoofable = false;
  for (const auto& datagram : datagrams) {
    const auto& address = datagram.destination.address();
    const bool spoofable_v4 = datagram.spoofable && address.family() == AddressFamily::ipv4;
    const auto pick = spoofable_v4 ? feedback_.pick(datagram.flow, now) : std::nullopt;
    if (!pick) {
      if (spoofable_v4) {
        unspoofable = true;
        ++spoof_undeliverable_;
      } else {
        real_batch_.push_back(datagram);
      }
      continue;
    }
    const auto octets = address.bytes();
    const auto dest_be = (static_cast<std::uint32_t>(octets[0]) << 24U) |
                         (static_cast<std::uint32_t>(octets[1]) << 16U) |
                         (static_cast<std::uint32_t>(octets[2]) << 8U) |
                         static_cast<std::uint32_t>(octets[3]);
    spoof_batch_.push_back(SpoofDatagram{.source_be = pick->source_be,
                                         .destination_be = dest_be,
                                         .source_port = spoof_source_port_,
                                         .destination_port = datagram.destination.port(),
                                         .payload = datagram.payload});
  }
  std::size_t real_sent = 0;
  if (!real_batch_.empty()) {
    const auto r = transport_->send_batch(real_batch_);
    real_sent = r.value_or(0);
  }
  if (spoof_batch_.empty()) {
    if (unspoofable && real_sent == 0) return std::unexpected(TransportError::would_block);
    return real_sent;
  }
  const auto sent = sender_.send_batch(spoof_batch_);
  if (!sent) return std::unexpected(TransportError::send_failed);
  return *sent + real_sent;
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

std::expected<std::size_t, TransportError> DnsCarrier::send_batch(
    std::span<const OutboundDatagram> datagrams) {
  wrap_slots_.resize(datagrams.size());
  wrap_batch_.clear();
  wrap_batch_.reserve(datagrams.size());
  std::vector<std::byte> obf_scratch;
  for (std::size_t index = 0; index < datagrams.size(); ++index) {
    std::span<const std::byte> payload = datagrams[index].payload;
    if (obfuscator_.enabled()) {
      obf_scratch.assign(payload.size() + obfuscator_.max_overhead(), std::byte{0});
      const auto wrapped = obfuscator_.wrap(payload, obf_scratch);
      if (!wrapped) continue;
      payload = std::span{obf_scratch}.first(*wrapped);
    }
    auto& slot = wrap_slots_[index];
    slot.assign(framer_.envelope_size() + payload.size(), std::byte{0});
    const auto framed = framer_.wrap(payload, slot);
    if (!framed) continue;
    wrap_batch_.push_back(OutboundDatagram{.destination = peer_,
                                           .payload = std::span{slot}.first(*framed),
                                           .flow = datagrams[index].flow});
  }
  if (wrap_batch_.empty()) return std::size_t{0};
  const auto sent = transport_->send_batch(wrap_batch_);
  if (!sent) return std::unexpected(sent.error());
  return std::min(*sent, datagrams.size());
}

std::expected<std::size_t, TransportError> DnsCarrier::receive_batch(
    ReceiveBuffers& buffers, std::span<InboundDatagram> out) {
  const auto received = transport_->receive_batch(buffers, out);
  if (!received) return received;

  unwrap_slots_.resize(out.size());
  std::vector<std::byte> obf_scratch;
  std::size_t kept = 0;
  for (std::size_t index = 0; index < *received; ++index) {
    auto& slot = unwrap_slots_[kept];
    slot.assign(out[index].payload.size(), std::byte{0});
    const auto unframed = framer_.unwrap(out[index].payload, slot);
    if (!unframed) continue;
    std::span<const std::byte> payload = std::span{slot}.first(*unframed);
    if (obfuscator_.enabled()) {
      obf_scratch.assign(payload.size(), std::byte{0});
      const auto plain = obfuscator_.unwrap(payload, obf_scratch);
      if (!plain) continue;
      slot.assign(obf_scratch.begin(),
                  obf_scratch.begin() + static_cast<std::ptrdiff_t>(*plain));
      payload = std::span{slot};
    }
    out[kept] = InboundDatagram{.source = out[index].source, .payload = payload};
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

std::expected<std::size_t, TransportError> RawProtoCarrier::send_batch(
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

std::expected<std::size_t, TransportError> RawProtoCarrier::receive_batch(
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

bool TcpCarrier::connection_ready(const TcpTransport& conn) const noexcept {
  return conn.connected() && (raw_ ? true : (pop3_ ? conn.pop3_established() : conn.tls_established()));
}

std::size_t TcpCarrier::ready_count() const noexcept {
  std::size_t count = connection_ready(*transport_) ? 1 : 0;
  for (const auto& conn : extra_) {
    if (connection_ready(conn)) ++count;
  }
  return count;
}

void TcpCarrier::note_failure(ConnectionSlot& slot, Instant now) noexcept {
  auto delay = std::chrono::duration_cast<Duration>(kCarrierRetryBase);
  for (std::uint32_t step = 0; step < slot.failures && delay < kCarrierRetryMax; ++step) delay *= 2;
  slot.next_attempt = now + std::min<Duration>(delay, kCarrierRetryMax);
  ++slot.failures;
  slot.started = false;
  slot.phase_since = Instant{};
  slot.last_rx = Instant{};
}

void TcpCarrier::drive(TcpTransport& transport, ConnectionSlot& slot, bool dialing, Instant now) {
  if (dialing && transport.state() == TcpState::closed) {
    if (slot.next_attempt != Instant{} && now < slot.next_attempt) return;
    slot.started = false;
    if (!sni_pool_.empty()) {
      sni_ = sni_pool_[sni_index_ % sni_pool_.size()];
      ++sni_index_;
    }
    transport.set_mark(mark_);
    if (!transport.connect(peer_)) {
      note_failure(slot, now);
      return;
    }
    slot.phase_since = now;
    return;
  }

  if (transport.state() == TcpState::closed) return;
  if (slot.phase_since == Instant{}) slot.phase_since = now;

  if (transport.state() == TcpState::failed) {
    transport.close();
    note_failure(slot, now);
    return;
  }

  const bool ready = connection_ready(transport);
  if (!ready && now - slot.phase_since > kCarrierSetupTimeout) {
    transport.close();
    note_failure(slot, now);
    return;
  }

  if (ready) {
    if (slot.last_rx == Instant{}) slot.last_rx = now;
    if (now - slot.last_rx > kConnectionSilenceTimeout) {
      transport.close();
      note_failure(slot, now);
      NORR_LOG_WARN("tcp carrier: connection silent, reconnecting");
      return;
    }
    slot.failures = 0;
    slot.next_attempt = Instant{};
  }

  if (transport.state() == TcpState::connecting) {
    const auto connected = transport.poll_connect();
    if (!connected) {
      transport.close();
      note_failure(slot, now);
      return;
    }
    if (!*connected) return;
  }

  if (!transport.connected()) return;

  if (raw_) {
    slot.started = true;
    if (transport.has_pending_output()) static_cast<void>(transport.flush_output());
    return;
  }

  if (pop3_) {
    if (!slot.started) {
      if (transport.enable_pop3(dialing, greet_profile_)) {
        slot.started = true;
      } else {
        return;
      }
    }
    if (!transport.pop3_established()) {
      static_cast<void>(transport.poll_pop3());
      return;
    }
    if (transport.has_pending_output()) static_cast<void>(transport.flush_output());
    return;
  }

  if (!slot.started) {
    const auto role = dialing ? TlsRole::client : TlsRole::server;
    const std::string_view server_name = camouflage_ ? std::string_view{sni_} : std::string_view{};
    if (transport.enable_tls(role, "norr", preshared_, server_name)) {
      slot.started = true;
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
  drive(*transport_, primary_slot_, dialing_, now);

  if (dialing_) {
    while (extra_.size() + 1 < target_) {
      extra_.emplace_back();
      extra_slots_.push_back(ConnectionSlot{});
    }
  }
  for (std::size_t index = 0; index < extra_.size(); ++index) {
    drive(extra_[index], extra_slots_[index], dialing_, now);
  }

  if (!dialing_) reap();
}

void TcpCarrier::reap() noexcept {
  for (std::size_t index = extra_.size(); index-- > 0;) {
    const auto state = extra_[index].state();
    if (state == TcpState::closed || state == TcpState::failed) {
      extra_.erase(extra_.begin() + static_cast<std::ptrdiff_t>(index));
      extra_slots_.erase(extra_slots_.begin() + static_cast<std::ptrdiff_t>(index));
    }
  }
}

void TcpCarrier::reset_all() noexcept {
  transport_->close();
  primary_slot_ = ConnectionSlot{};
  for (auto& conn : extra_) conn.close();
  for (auto& slot : extra_slots_) slot = ConnectionSlot{};
}

std::expected<std::size_t, TransportError> TcpCarrier::send_batch(
    std::span<const OutboundDatagram> datagrams) {
  std::array<TcpTransport*, 8> ready_conns{};
  std::size_t count = 0;
  if (connection_ready(*transport_)) ready_conns[count++] = transport_;
  for (auto& conn : extra_) {
    if (count >= ready_conns.size()) break;
    if (connection_ready(conn)) ready_conns[count++] = &conn;
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
        conn->close();
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
    if (!(raw_ ? conn.connected() : (pop3_ ? conn.pop3_established() : conn.tls_established()))) return;
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

  const auto now = std::chrono::steady_clock::now();
  const auto before = delivered;
  drain(*transport_);
  if (delivered > before) primary_slot_.last_rx = now;
  for (std::size_t index = 0; index < extra_.size(); ++index) {
    const auto mark = delivered;
    drain(extra_[index]);
    if (delivered > mark) extra_slots_[index].last_rx = now;
  }
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
