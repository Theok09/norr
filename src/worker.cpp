// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#include "norr/worker.hpp"

#include "norr/flow_hash.hpp"

#include <algorithm>

namespace norr {
Worker::Worker(TunDevice& tun, Carrier& carrier, RoutingTable& routes,
               SessionTable& sessions)
    : tun_(&tun),
      transport_(&carrier),
      routes_(&routes),
      sessions_(&sessions),
      tun_read_buffer_(kVirtioHeaderSize + kMaximumOffloadFrame),
      encrypt_buffer_(kFrameBufferSize + kPacketHeaderSize + kAeadTagSize +
                      kPaddingAlignment),
      pad_buffer_(kFrameBufferSize + kPaddingAlignment),
      decrypt_buffer_(kFrameBufferSize),
      receive_pool_(UdpTransport::kDefaultBatchSize, UdpTransport::kCoalescedDatagramSize),
      inbound_(UdpTransport::kDefaultBatchSize),
      transmit_slots_(UdpTransport::kDefaultBatchSize,
                      std::vector<std::byte>(kFecHeaderSize + encrypt_buffer_.size())),
      transmit_plain_(UdpTransport::kDefaultBatchSize, std::vector<std::byte>(pad_buffer_.size())),
      receive_plain_(UdpTransport::kDefaultBatchSize, std::vector<std::byte>(kFrameBufferSize)) {
  transmit_batch_.reserve(UdpTransport::kDefaultBatchSize);
  transmit_jobs_.reserve(UdpTransport::kDefaultBatchSize);
  receive_jobs_.reserve(UdpTransport::kDefaultBatchSize);
}

void Worker::set_mtu(std::size_t mtu) {
  mtu_ = std::clamp<std::size_t>(mtu, 576, kFrameBufferSize);
  const auto datagram = std::max<std::size_t>(
      UdpTransport::kCoalescedDatagramSize,
      mtu_ + kPacketHeaderSize + kAeadTagSize + kPaddingAlignment + kFecHeaderSize + 64);
  if (datagram != receive_pool_.datagram_size()) {
    receive_pool_ = ReceiveBuffers{UdpTransport::kDefaultBatchSize, datagram};
  }
}

std::size_t Worker::flush_transmit() {
  if (transmit_jobs_.empty()) return 0;

  runner_.run(transmit_jobs_.size(), [&](std::size_t index) {
    auto& job = transmit_jobs_[index];
    const auto sealed = job.session->seal_reserved(
        FrameType::data, job.counter, std::span{transmit_plain_[index]}.first(job.length),
        std::span{transmit_slots_[index]}.subspan(kFecHeaderSize));
    job.ok = sealed.has_value();
    job.sealed = sealed.value_or(0);
  });

  transmit_batch_.clear();
  const auto now = std::chrono::steady_clock::now();
  std::size_t parity_used = 0;
  for (std::size_t index = 0; index < transmit_jobs_.size(); ++index) {
    const auto& job = transmit_jobs_[index];
    if (!job.ok) {
      stats_.record_drop(DropReason::oversized);
      continue;
    }
    const auto slot = std::span<std::byte>{transmit_slots_[index]};
    const auto sealed = slot.subspan(kFecHeaderSize, job.sealed);
    if (job.fec == kNoFec || !fec_peers_[job.fec].encoder.active()) {
      transmit_batch_.push_back(OutboundDatagram{
          .destination = job.destination, .payload = sealed, .flow = job.flow, .spoofable = true});
      continue;
    }
    auto& entry = fec_peers_[job.fec];
    static_cast<void>(serialize_fec_header(entry.encoder.next_header(job.sealed), slot));
    transmit_batch_.push_back(OutboundDatagram{.destination = job.destination,
                                               .payload = slot.first(kFecHeaderSize + job.sealed),
                                               .flow = job.flow,
                                               .spoofable = true});
    entry.destination = job.destination;
    entry.last_symbol = now;
    for (const auto& symbol : entry.encoder.add(sealed)) {
      if (parity_used == parity_slots_.size()) parity_slots_.emplace_back();
      auto& copy = parity_slots_[parity_used++];
      copy.assign(symbol.begin(), symbol.end());
      transmit_batch_.push_back(OutboundDatagram{
          .destination = job.destination, .payload = copy, .flow = job.flow, .spoofable = true});
    }
  }
  transmit_jobs_.clear();
  if (transmit_batch_.empty()) return 0;

  std::size_t offset = 0;
  while (offset < transmit_batch_.size()) {
    const auto sent = transport_->send_batch(std::span{transmit_batch_}.subspan(offset));
    if (!sent || *sent == 0) break;
    for (std::size_t index = offset; index < offset + *sent; ++index) {
      bytes_sent_ += transmit_batch_[index].payload.size();
    }
    stats_.tun_to_udp += *sent;
    offset += *sent;
  }

  for (std::size_t index = offset; index < transmit_batch_.size(); ++index) {
    bytes_dropped_ += transmit_batch_[index].payload.size();
    stats_.record_drop(DropReason::send_failed);
  }

  transmit_batch_.clear();
  if (offset > 0) last_outbound_ = now;
  return offset;
}

DropReason Worker::forward_from_tun(std::span<const std::byte> frame) {
  const auto reason = route_from_tun(frame, true);
  static_cast<void>(flush_transmit());
  return reason;
}

DropReason Worker::route_from_tun(std::span<const std::byte> frame, bool batch) {
  const auto parsed = parse_ip_packet(frame);
  if (!parsed) {
    stats_.record_drop(DropReason::malformed_inner_packet);
    return DropReason::malformed_inner_packet;
  }
  const auto flow = static_cast<std::uint32_t>(hash_flow(flow_key_of(*parsed, frame)));

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

  auto session = sessions_->find_by_peer(decision.peer);
  if (session == nullptr || session->expired(std::chrono::steady_clock::now())) {
    if (session_request_) session_request_(decision.peer);
    stats_.record_drop(DropReason::no_session);
    return DropReason::no_session;
  }

  if (!session->endpoint().has_value()) {
    stats_.record_drop(DropReason::no_endpoint);
    return DropReason::no_endpoint;
  }

  auto padded = profile_padded_length(profile_, frame.size());
  if (padded > mtu_) padded = std::max(frame.size(), mtu_);
  if (padded > pad_buffer_.size()) {
    stats_.record_drop(DropReason::oversized);
    return DropReason::oversized;
  }

  auto fec = kNoFec;
  if (fec_mode_ != FecMode::off) {
    fec = fec_index(session->peer(), *session->endpoint());
    ++fec_peers_[fec].packets;
    if (!fec_peers_[fec].encoder.active()) fec = kNoFec;
  }
  if (batch && !queueing_enabled_) {
    if (transmit_jobs_.size() >= transmit_plain_.size()) static_cast<void>(flush_transmit());
    const auto counter = session->reserve_counter();
    if (!counter) {
      stats_.record_drop(DropReason::counter_exhausted);
      return DropReason::counter_exhausted;
    }
    const auto destination = *session->endpoint();
    auto& plain = transmit_plain_[transmit_jobs_.size()];
    std::copy(frame.begin(), frame.end(), plain.begin());
    std::fill(plain.begin() + static_cast<std::ptrdiff_t>(frame.size()),
              plain.begin() + static_cast<std::ptrdiff_t>(padded), std::byte{0});
    transmit_jobs_.push_back(TransmitJob{.session = std::move(session),
                                         .counter = *counter,
                                         .flow = flow,
                                         .length = padded,
                                         .destination = destination,
                                         .sealed = 0,
                                         .fec = fec,
                                         .ok = false});
    return DropReason::none;
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

  auto wire = std::span<const std::byte>{encrypt_buffer_}.first(*sealed);

  if (fec != kNoFec) {
    auto& fec_state = fec_peers_[fec];
    const auto header = fec_state.encoder.next_header(*sealed);
    if (serialize_fec_header(header, fec_buffer_) == kFecHeaderSize) {
      std::copy(wire.begin(), wire.end(),
                fec_buffer_.begin() + static_cast<std::ptrdiff_t>(kFecHeaderSize));
      const auto framed = std::span<const std::byte>{fec_buffer_}.first(kFecHeaderSize + *sealed);

      fec_state.last_symbol = std::chrono::steady_clock::now();
      fec_state.destination = *session->endpoint();
      const auto parity = fec_state.encoder.add(wire);
      if (!parity.empty()) {
        fec_batch_.clear();
        fec_batch_.push_back(OutboundDatagram{.destination = fec_state.destination,
                                              .payload = framed, .flow = flow, .spoofable = true});
        for (const auto& symbol : parity) {
          fec_batch_.push_back(OutboundDatagram{.destination = fec_state.destination,
                                                .payload = symbol, .flow = flow, .spoofable = true});
        }
        if (send_all(fec_batch_) == 0) {
          bytes_dropped_ += framed.size();
          stats_.record_drop(DropReason::send_failed);
          return DropReason::send_failed;
        }
        ++stats_.tun_to_udp;
        last_outbound_ = fec_state.last_symbol;
        return DropReason::none;
      }
      wire = framed;
    }
  }

  if (queueing_enabled_) {
    const auto traffic_class = classify(*parsed, frame);
    const auto now = std::chrono::steady_clock::now();

    if (!scheduler_.enqueue(std::vector<std::byte>(wire.begin(), wire.end()), traffic_class, now,
                            *session->endpoint())) {
      stats_.record_drop(DropReason::send_failed);
      return DropReason::send_failed;
    }

    static_cast<void>(drain_queue(now));
    last_outbound_ = now;
    ++stats_.tun_to_udp;
    return DropReason::none;
  }

  const std::array<OutboundDatagram, 1> datagram{
      OutboundDatagram{.destination = *session->endpoint(), .payload = wire, .spoofable = true}};
  const auto sent = transport_->send_batch(datagram);
  if (!sent || *sent == 0) {
    bytes_dropped_ += wire.size();
    stats_.record_drop(DropReason::send_failed);
    return DropReason::send_failed;
  }

  bytes_sent_ += wire.size();
  last_outbound_ = std::chrono::steady_clock::now();
  ++stats_.tun_to_udp;
  return DropReason::none;
}

std::size_t Worker::send_chaff(Instant now) {
  if (profile_ == TrafficProfile::standard) return 0;
  if (last_outbound_ != Instant{} && now - last_outbound_ < kChaffInterval) return 0;

  const auto buckets = profile_buckets(profile_);
  if (buckets.empty()) return 0;

  std::size_t sent = 0;
  sessions_->for_each([&](Session& session) {
    if (!session.endpoint().has_value()) return;

    const auto length = buckets.front();
    if (length > pad_buffer_.size()) return;
    std::fill(pad_buffer_.begin(), pad_buffer_.begin() + static_cast<std::ptrdiff_t>(length),
              std::byte{0});

    const auto sealed =
        session.seal(FrameType::control, std::span{pad_buffer_}.first(length), encrypt_buffer_);
    if (!sealed) return;

    const auto wire = std::span<const std::byte>{encrypt_buffer_}.first(*sealed);
    const std::array<OutboundDatagram, 1> datagram{
        OutboundDatagram{.destination = *session.endpoint(), .payload = wire}};
    if (!transport_->send_batch(datagram)) return;

    bytes_sent_ += wire.size();
    ++chaff_sent_;
    ++sent;
  });

  if (sent > 0) last_outbound_ = now;
  return sent;
}

void Worker::enable_fec(FecMode mode) {
  fec_mode_ = mode;
  fec_peers_.clear();
  fec_sources_.clear();
  fec_buffer_.assign(kFrameBufferSize + kPacketHeaderSize + kAeadTagSize +
                         kPaddingAlignment + kFecHeaderSize,
                     std::byte{0});
}

std::size_t Worker::fec_index(PeerId peer, const Endpoint& destination) {
  for (std::size_t index = 0; index < fec_peers_.size(); ++index) {
    if (fec_peers_[index].peer == peer) return index;
  }
  const auto initial = fec_mode_ == FecMode::automatic ? FecMode::off : fec_mode_;
  fec_peers_.push_back(FecPeer{.peer = peer,
                               .destination = destination,
                               .encoder = FecEncoder{initial},
                               .last_symbol = {},
                               .controller = {},
                               .packets = 0,
                               .packets_at_report = 0,
                               .send_failures_at_report = 0,
                               .sent_at_report = 0,
                               .last_report = std::chrono::steady_clock::now()});
  return fec_peers_.size() - 1;
}

Worker::FecPeer& Worker::fec_peer(PeerId peer, const Endpoint& destination) {
  return fec_peers_[fec_index(peer, destination)];
}

FecPlan Worker::peer_fec_plan(PeerId peer) const noexcept {
  for (const auto& entry : fec_peers_) {
    if (entry.peer == peer) return entry.encoder.plan();
  }
  return fec_mode_ == FecMode::automatic ? FecPlan{} : plan_for_mode(fec_mode_);
}

void Worker::send_parity(FecPeer& entry, std::span<const std::vector<std::byte>> parity) {
  if (parity.empty()) return;
  fec_batch_.clear();
  for (const auto& symbol : parity) {
    fec_batch_.push_back(OutboundDatagram{.destination = entry.destination, .payload = symbol,
                                          .flow = 0, .spoofable = true});
  }
  static_cast<void>(send_all(fec_batch_));
}

std::optional<FecPlan> Worker::note_peer_loss(PeerId peer, double raw_loss, double residual_loss,
                                              bool rtt_inflated, Instant now) {
  if (fec_mode_ != FecMode::automatic) return std::nullopt;
  FecPeer* entry = nullptr;
  for (auto& candidate : fec_peers_) {
    if (candidate.peer == peer) entry = &candidate;
  }
  if (entry == nullptr) return std::nullopt;

  const auto elapsed = std::chrono::duration<double>(now - entry->last_report).count();
  const auto packets = entry->packets - entry->packets_at_report;
  const auto failures = stats_.drops_for(DropReason::send_failed) - entry->send_failures_at_report;
  const auto sent = stats_.tun_to_udp - entry->sent_at_report;
  entry->last_report = now;
  entry->packets_at_report = entry->packets;
  entry->send_failures_at_report = stats_.drops_for(DropReason::send_failed);
  entry->sent_at_report = stats_.tun_to_udp;

  const auto local_loss =
      sent + failures == 0 ? 0.0
                           : static_cast<double>(failures) / static_cast<double>(sent + failures);
  const FecLossReport report{
      .raw = raw_loss,
      .residual = residual_loss,
      .packets_per_second = elapsed > 0.0 ? static_cast<double>(packets) / elapsed : 0.0,
      .congested = rtt_inflated || (raw_loss > 0.0 && local_loss >= raw_loss * 0.5)};

  const auto decision = entry->controller.decide(entry->encoder.plan(), report, now);
  if (!decision) return std::nullopt;

  send_parity(*entry, entry->encoder.flush());
  const auto next_block = entry->encoder.current_block();
  entry->encoder = FecEncoder{*decision};
  entry->encoder.resume_at(next_block);
  return decision;
}

Worker::FecSource& Worker::fec_source(const Endpoint& source, Instant now) {
  for (auto& entry : fec_sources_) {
    if (entry.source == source) {
      entry.last_seen = now;
      return entry;
    }
  }
  if (fec_sources_.size() >= kMaximumFecSources) {
    const auto stalest = std::ranges::min_element(
        fec_sources_, {}, [](const FecSource& entry) { return entry.last_seen; });
    fec_sources_.erase(stalest);
  }
  fec_sources_.push_back(FecSource{.source = source, .decoder = {}, .last_seen = now});
  return fec_sources_.back();
}

std::size_t Worker::send_all(std::span<const OutboundDatagram> datagrams) {
  std::size_t offset = 0;
  while (offset < datagrams.size()) {
    const auto sent = transport_->send_batch(datagrams.subspan(offset));
    if (!sent || *sent == 0) break;
    for (std::size_t index = offset; index < offset + *sent; ++index) {
      bytes_sent_ += datagrams[index].payload.size();
    }
    offset += *sent;
  }
  for (std::size_t index = offset; index < datagrams.size(); ++index) {
    bytes_dropped_ += datagrams[index].payload.size();
  }
  return offset;
}

bool Worker::fec_pending() const noexcept {
  return std::ranges::any_of(fec_peers_,
                             [](const FecPeer& entry) { return entry.encoder.pending() > 0; });
}

const FecStats& Worker::fec_stats() const noexcept {
  fec_encode_total_ = {};
  for (const auto& entry : fec_peers_) {
    const auto& stats = entry.encoder.stats();
    fec_encode_total_.blocks_encoded += stats.blocks_encoded;
    fec_encode_total_.parity_sent += stats.parity_sent;
  }
  return fec_encode_total_;
}

const FecStats& Worker::fec_decode_stats() const noexcept {
  fec_decode_total_ = {};
  for (const auto& entry : fec_sources_) {
    const auto& stats = entry.decoder.stats();
    fec_decode_total_.symbols_received += stats.symbols_received;
    fec_decode_total_.recovered += stats.recovered;
    fec_decode_total_.unrecoverable += stats.unrecoverable;
    fec_decode_total_.expired += stats.expired;
  }
  return fec_decode_total_;
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
      scheduler_.restore(std::move(*packet));
      break;
    }

    const std::array<OutboundDatagram, 1> datagram{
        OutboundDatagram{.destination = packet->destination, .payload = packet->bytes,
                         .flow = 0, .spoofable = true}};
    const auto result = transport_->send_batch(datagram);
    if (!result || *result == 0) {
      bytes_dropped_ += packet->bytes.size();
      stats_.record_drop(DropReason::send_failed);
      break;
    }
    bytes_sent_ += packet->bytes.size();
    ++sent;
  }
  return sent;
}

void Worker::flush_fec(Instant now) {
  for (auto& entry : fec_sources_) static_cast<void>(entry.decoder.expire(now));
  std::erase_if(fec_sources_, [&](const FecSource& entry) {
    return now - entry.last_seen > std::chrono::minutes{2} && entry.decoder.outstanding() == 0;
  });

  if (fec_mode_ == FecMode::off) return;
  for (auto& entry : fec_peers_) {
    if (entry.encoder.pending() == 0) continue;
    if (now - entry.last_symbol < kFecFlushInterval) continue;
    send_parity(entry, entry.encoder.flush());
  }
}

DropReason Worker::forward_from_transport(const Endpoint& source,
                                          std::span<const std::byte> datagram) {
  if (looks_like_fec_symbol(datagram)) {
    const auto header = parse_fec_header(datagram);
    if (!header) {
      stats_.record_drop(DropReason::malformed_outer_packet);
      return DropReason::malformed_outer_packet;
    }

    const auto body = datagram.subspan(kFecHeaderSize);
    const auto now = std::chrono::steady_clock::now();
    const auto recovered = fec_source(source, now).decoder.receive(*header, body, now);

    auto reason = header->parity ? DropReason::none : forward_sealed(source, body);
    for (const auto& packet : recovered) {
      const auto outcome = forward_sealed(source, packet, true);
      if (header->parity && reason == DropReason::none) reason = outcome;
    }
    return reason;
  }

  return forward_sealed(source, datagram);
}

DropReason Worker::forward_sealed(const Endpoint& source, std::span<const std::byte> datagram,
                                  bool recovered) {
  const auto view = parse_packet(datagram);
  if (!view) {
    stats_.record_drop(DropReason::malformed_outer_packet);
    return DropReason::malformed_outer_packet;
  }

  std::size_t plaintext_length = 0;
  PeerId ingress_peer = kNoPeer;

  auto session = sessions_->find_by_key_id(view->header.key_id);
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

    if (recovered) {
      session->note_recovered();
    } else {
      session->note_authenticated_endpoint(source);
    }
    plaintext_length = *opened;
    ingress_peer = session->peer();
  }

  return deliver_opened(ingress_peer, view->header.type,
                        std::span{decrypt_buffer_}.first(plaintext_length), false);
}

DropReason Worker::deliver_opened(PeerId ingress_peer, FrameType type,
                                  std::span<const std::byte> padded_plaintext, bool stable) {
  const auto plaintext_length = padded_plaintext.size();
  if (type == FrameType::control) {
    ++stats_.keepalives_received;

    const auto payload = padded_plaintext;
    if (payload.size() > 1 && ingress_peer != kNoPeer) {
      const auto token = payload.subspan(1);
      if (payload[0] == kEchoRequest && echo_responder_) {
        echo_responder_(ingress_peer, token);
      } else if (payload[0] == kEchoReply && echo_reply_handler_) {
        echo_reply_handler_(ingress_peer, token);
      } else if (payload[0] == kLossReport && payload.size() == kLossReportSize &&
                 loss_report_handler_) {
        const auto read = [&](std::size_t offset) {
          const auto permille = (static_cast<unsigned>(payload[offset]) << 8U) |
                                static_cast<unsigned>(payload[offset + 1]);
          return std::min(1.0, static_cast<double>(permille) / 1000.0);
        };
        loss_report_handler_(ingress_peer, read(1), read(3));
      }
    }
    return DropReason::none;
  }

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

  if (tun_->offload_enabled()) {
    coalescer_.add(plaintext, stable);
    ++stats_.udp_to_tun;
    return DropReason::none;
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
    if (!tun_->offload_enabled()) {
      if (route_from_tun(*frame, true) == DropReason::none) ++forwarded;
      continue;
    }
    if (frame->size() <= kVirtioHeaderSize) continue;
    const auto header = parse_virtio_header(frame->first(kVirtioHeaderSize));
    const auto packet = std::span<std::byte>{tun_read_buffer_}.subspan(
        kVirtioHeaderSize, frame->size() - kVirtioHeaderSize);
    const bool expanded =
        expand_offloaded(header, packet, segment_scratch_, [&](std::span<const std::byte> segment) {
          if (route_from_tun(segment, true) == DropReason::none) ++forwarded;
        });
    if (!expanded) stats_.record_drop(DropReason::malformed_inner_packet);
  }
  static_cast<void>(flush_transmit());
  return forwarded;
}

bool Worker::stage_receive(const Endpoint& source, std::span<const std::byte> datagram) {
  const auto view = parse_packet(datagram);
  if (!view) return false;
  auto session = sessions_->find_by_key_id(view->header.key_id);
  if (session == nullptr) return false;
  if (receive_jobs_.size() >= receive_plain_.size()) static_cast<void>(settle_receive());

  if (const auto window = session->check_window(view->header.counter); !window) {
    stats_.record_drop(DropReason::too_old);
    return true;
  }
  receive_jobs_.push_back(ReceiveJob{.session = std::move(session),
                                     .view = *view,
                                     .datagram = datagram,
                                     .source = source,
                                     .length = 0,
                                     .error = SessionError::authentication_failed,
                                     .ok = false});
  return true;
}

std::size_t Worker::settle_receive() {
  if (receive_jobs_.empty()) return 0;

  runner_.run(receive_jobs_.size(), [&](std::size_t index) {
    auto& job = receive_jobs_[index];
    const auto opened = job.session->decrypt(job.view, job.datagram, receive_plain_[index]);
    job.ok = opened.has_value();
    if (opened) {
      job.length = *opened;
    } else {
      job.error = opened.error();
    }
  });

  std::size_t delivered = 0;
  for (std::size_t index = 0; index < receive_jobs_.size(); ++index) {
    auto& job = receive_jobs_[index];
    if (!job.ok) {
      if (job.error == SessionError::authentication_failed) job.session->note_authentication_failure();
      stats_.record_drop(job.error == SessionError::buffer_too_small
                             ? DropReason::oversized
                             : DropReason::authentication_failed);
      continue;
    }
    if (const auto committed = job.session->commit(job.view.header.counter); !committed) {
      stats_.record_drop(committed.error() == SessionError::replayed ? DropReason::replayed
                                                                     : DropReason::too_old);
      continue;
    }
    job.session->note_authenticated_endpoint(job.source);
    const auto reason =
        deliver_opened(job.session->peer(), job.view.header.type,
                       std::span<const std::byte>{receive_plain_[index]}.first(job.length), true);
    if (reason == DropReason::none) ++delivered;
  }
  flush_tun_writes();
  receive_jobs_.clear();
  return delivered;
}

std::size_t Worker::pump_udp_to_tun(std::size_t max_datagrams) {
  std::size_t delivered = 0;
  std::size_t processed = 0;

  while (processed < max_datagrams) {
    const auto batch = std::min(max_datagrams - processed, inbound_.size());
    const auto received = transport_->receive_batch(receive_pool_, std::span{inbound_}.first(batch));
    if (!received || *received == 0) break;

    for (std::size_t index = 0; index < *received; ++index) {
      const auto& datagram = inbound_[index];
      if (ingress_filter_ && ingress_filter_(datagram.source, datagram.payload)) continue;
      if (!looks_like_fec_symbol(datagram.payload)) {
        if (stage_receive(datagram.source, datagram.payload)) continue;
      } else if (const auto header = parse_fec_header(datagram.payload)) {
        const auto body = datagram.payload.subspan(kFecHeaderSize);
        const auto now = std::chrono::steady_clock::now();
        auto recovered = fec_source(datagram.source, now).decoder.receive(*header, body, now);
        const bool staged = !header->parity && stage_receive(datagram.source, body);
        if (!recovered.empty()) delivered += settle_receive();
        for (const auto& packet : recovered) {
          if (forward_sealed(datagram.source, packet, true) == DropReason::none) ++delivered;
        }
        if (staged || header->parity) continue;
        delivered += settle_receive();
        if (forward_sealed(datagram.source, body) == DropReason::none) ++delivered;
        continue;
      }
      delivered += settle_receive();
      if (forward_from_transport(datagram.source, datagram.payload) == DropReason::none) ++delivered;
    }
    delivered += settle_receive();
    processed += *received;
  }
  flush_tun_writes();
  return delivered;
}

void Worker::flush_tun_writes() {
  if (coalescer_.empty()) return;
  coalescer_.flush([&](std::span<const std::byte> header, std::span<const std::byte> head,
                       std::span<const std::span<const std::byte>> payloads) {
    if (!tun_->write_vectored(header, head, payloads)) {
      stats_.record_drop(DropReason::tun_write_failed);
    }
  });
}

std::size_t Worker::poll() { return pump_tun_to_udp() + pump_udp_to_tun(); }
}
