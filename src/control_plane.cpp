#include "norr/control_plane.hpp"

#include <algorithm>

#include "norr/capability.hpp"
#include "norr/handshake_frame.hpp"

namespace norr {
namespace {
[[nodiscard]] std::uint64_t handshake_timestamp() noexcept {
  const auto since = std::chrono::system_clock::now().time_since_epoch();
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(since).count());
}

[[nodiscard]] std::vector<std::byte> build_payload(const ProtocolVersion& version,
                                                   std::uint32_t capabilities,
                                                   std::uint16_t key_id,
                                                   std::uint64_t timestamp) {
  std::vector<std::byte> payload(16);
  payload[0] = static_cast<std::byte>(version.major);
  payload[1] = static_cast<std::byte>(version.minor);
  payload[2] = static_cast<std::byte>((capabilities >> 24U) & 0xFFU);
  payload[3] = static_cast<std::byte>((capabilities >> 16U) & 0xFFU);
  payload[4] = static_cast<std::byte>((capabilities >> 8U) & 0xFFU);
  payload[5] = static_cast<std::byte>(capabilities & 0xFFU);
  payload[6] = static_cast<std::byte>((key_id >> 8U) & 0xFFU);
  payload[7] = static_cast<std::byte>(key_id & 0xFFU);
  for (std::size_t index = 0; index < 8; ++index) {
    payload[8 + index] = static_cast<std::byte>((timestamp >> ((7 - index) * 8U)) & 0xFFU);
  }
  return payload;
}

[[nodiscard]] std::uint64_t payload_timestamp(std::span<const std::byte> payload) noexcept {
  if (payload.size() < 16) return 0;
  std::uint64_t value = 0;
  for (std::size_t index = 0; index < 8; ++index) {
    value = (value << 8U) | static_cast<std::uint64_t>(payload[8 + index]);
  }
  return value;
}

[[nodiscard]] std::uint16_t payload_key_id(std::span<const std::byte> payload) noexcept {
  if (payload.size() < 8) return kPreSessionKeyId;
  return static_cast<std::uint16_t>((static_cast<std::uint16_t>(payload[6]) << 8U) |
                                    static_cast<std::uint16_t>(payload[7]));
}

constexpr std::size_t kHandshakePayloadSize = 16;

}

ControlPlane::ControlPlane(const KeyPair& local_static, SessionTable& sessions, TimerWheel& timers)
    : local_static_(local_static),
      sessions_(&sessions),
      timers_(&timers),
      issuer_(local_static.public_key) {}

std::expected<void, ControlError> ControlPlane::add_peer(const PeerConfig& peer) {
  if (peer.id == kNoPeer) return std::unexpected(ControlError::unknown_peer);
  peers_[peer.id] = peer;
  return {};
}

const PeerConfig* ControlPlane::find_peer(PeerId peer) const noexcept {
  const auto entry = peers_.find(peer);
  return entry == peers_.end() ? nullptr : &entry->second;
}

std::expected<OutgoingHandshake, ControlError> ControlPlane::build_initiation(Pending& entry,
                                                                              Instant now) {
  const auto* config = find_peer(entry.peer);
  if (config == nullptr) return std::unexpected(ControlError::unknown_peer);

  auto handshake = NoiseHandshake::create(HandshakeRole::initiator, local_static_,
                                          config->static_public, config->preshared);
  if (!handshake) {
    return std::unexpected(handshake.error() == NoiseError::unsupported_platform
                               ? ControlError::crypto_unavailable
                               : ControlError::handshake_failed);
  }

  const auto payload = build_payload(ProtocolVersion{}, 0, entry.local_key_id, handshake_timestamp());
  std::vector<std::byte> message(kNoiseMessage1Overhead + payload.size());
  const auto written = handshake->write_message_1(payload, message);
  if (!written) return std::unexpected(ControlError::handshake_failed);

  auto frame = serialize_handshake_frame_with_macs(HandshakeMessage::init,
                                                   std::span{message}.first(*written));
  if (!frame) return std::unexpected(ControlError::handshake_failed);

  if (!entry.cookies.has_value()) entry.cookies.emplace(config->static_public);

  const auto first = mac1_offset(*written);
  const auto second = mac2_offset(*written);

  const auto mac1 = entry.cookies->compute_mac1(std::span{*frame}.first(first));
  std::copy(mac1.begin(), mac1.end(), frame->begin() + static_cast<std::ptrdiff_t>(first));
  entry.last_mac1 = mac1;

  const auto mac2 = entry.cookies->compute_mac2(std::span{*frame}.first(second));
  std::copy(mac2.begin(), mac2.end(), frame->begin() + static_cast<std::ptrdiff_t>(second));

  entry.handshake = std::move(*handshake);
  entry.started = now;

  if (!timers_->schedule(TimerKind::handshake_timeout, entry.peer, now + kHandshakeTimeout)) {
    return std::unexpected(ControlError::timer_capacity);
  }
  if (!timers_->schedule(TimerKind::handshake_retry, entry.peer,
                         now + retry_backoff(entry.attempt))) {
    return std::unexpected(ControlError::timer_capacity);
  }

  return OutgoingHandshake{.destination = entry.destination, .datagram = std::move(*frame)};
}

std::expected<OutgoingHandshake, ControlError> ControlPlane::start_handshake(PeerId peer,
                                                                             Instant now) {
  if (!crypto_available()) return std::unexpected(ControlError::crypto_unavailable);

  const auto* config = find_peer(peer);
  if (config == nullptr) return std::unexpected(ControlError::unknown_peer);
  if (!config->endpoint.has_value()) return std::unexpected(ControlError::unknown_peer);

  if (pending_.size() >= kMaximumPending && !pending_.contains(peer)) {
    ++stats_.pending_rejected;
    return std::unexpected(ControlError::too_many_pending);
  }

  const auto key_id = sessions_->allocate_key_id();
  if (!key_id) return std::unexpected(ControlError::session_install_failed);

  Pending entry;
  entry.peer = peer;
  entry.local_key_id = *key_id;
  entry.destination = *config->endpoint;
  entry.attempt = 0;

  auto initiation = build_initiation(entry, now);
  if (!initiation) return std::unexpected(initiation.error());

  pending_[peer] = std::move(entry);
  ++stats_.handshakes_started;
  return std::move(*initiation);
}

std::expected<void, ControlError> ControlPlane::install_session(PeerId peer,
                                                                std::uint16_t local_key_id,
                                                                std::uint16_t remote_key_id,
                                                                const NoiseResult& result,
                                                                const Endpoint& endpoint) {
  TrafficKeys send{result.send, 0};
  TrafficKeys receive{result.receive, 0};

  const auto installed =
      sessions_->install(peer, local_key_id, remote_key_id, std::move(send), std::move(receive));
  if (!installed) return std::unexpected(ControlError::session_install_failed);

  (*installed)->note_authenticated_endpoint(endpoint);

  timers_->cancel(TimerKind::handshake_timeout, peer);
  timers_->cancel(TimerKind::handshake_retry, peer);
  static_cast<void>(timers_->schedule(TimerKind::rekey, peer,
                                      std::chrono::steady_clock::now() + kRekeyAfter));
  static_cast<void>(timers_->schedule(TimerKind::keepalive, peer,
                                      std::chrono::steady_clock::now() + kKeepaliveInterval));
  return {};
}

std::expected<std::optional<OutgoingHandshake>, ControlError> ControlPlane::handle_datagram(
    const Endpoint& source, std::span<const std::byte> datagram, Instant now) {
  if (!crypto_available()) return std::unexpected(ControlError::crypto_unavailable);

  if (!global_limiter_.allow(now)) {
    ++stats_.rate_limited;
    return std::unexpected(ControlError::rate_limited);
  }
  if (!rate_limiter_.allow(source, now)) {
    ++stats_.rate_limited;
    return std::unexpected(ControlError::rate_limited);
  }

  ++handshakes_seen_;

  const auto frame = parse_handshake_frame(datagram);
  if (!frame) return std::unexpected(ControlError::invalid_message);

  if (frame->message == HandshakeMessage::cookie_reply) {
    const auto reply = parse_cookie_reply(frame->noise_message);
    if (!reply) return std::unexpected(ControlError::invalid_message);

    for (auto& [peer_id, entry] : pending_) {
      if (!entry.cookies.has_value()) continue;

      if (!entry.cookies->accept_reply(*reply, entry.last_mac1, now)) continue;

      ++stats_.cookies_accepted;

      auto retry = build_initiation(entry, now);
      if (!retry) return std::unexpected(retry.error());
      return std::optional<OutgoingHandshake>{std::move(*retry)};
    }
    return std::unexpected(ControlError::not_pending);
  }

  if (frame->message == HandshakeMessage::init) {
    if (pending_.size() >= kMaximumPending) {
      ++stats_.pending_rejected;
      return std::unexpected(ControlError::too_many_pending);
    }

    if (frame->has_macs) {
      Mac received_mac1{};
      std::copy(frame->mac1.begin(), frame->mac1.end(), received_mac1.begin());

      if (!issuer_.verify_mac1(frame->mac1_covered, received_mac1)) {
        ++stats_.mac1_failures;
        return std::unexpected(ControlError::invalid_message);
      }

      if (issuer_.under_load()) {
        Mac received_mac2{};
        std::copy(frame->mac2.begin(), frame->mac2.end(), received_mac2.begin());

        if (!issuer_.verify_mac2(source, frame->mac2_covered, received_mac2, now)) {
          ++stats_.mac2_failures;
          const auto cookie_reply = issuer_.build_reply(source, 0, received_mac1, now);
          if (!cookie_reply) return std::unexpected(ControlError::handshake_failed);

          std::array<std::byte, kCookieReplySize> encoded{};
          if (!serialize_cookie_reply(*cookie_reply, encoded)) {
            return std::unexpected(ControlError::handshake_failed);
          }
          auto cookie_datagram =
              serialize_handshake_frame(HandshakeMessage::cookie_reply, encoded);
          if (!cookie_datagram) return std::unexpected(ControlError::handshake_failed);

          ++stats_.cookies_issued;
          return std::optional<OutgoingHandshake>{
              OutgoingHandshake{.destination = source, .datagram = std::move(*cookie_datagram)}};
        }
      }
    } else if (issuer_.under_load()) {
      ++stats_.mac1_failures;
      return std::unexpected(ControlError::invalid_message);
    }

    const PeerConfig* matched = nullptr;
    PeerId matched_id = kNoPeer;
    {
      PresharedKey probe{};
      auto identify = NoiseHandshake::create(HandshakeRole::responder, local_static_,
                                             PublicKey{}, probe);
      if (!identify) return std::unexpected(ControlError::handshake_failed);

      std::vector<std::byte> payload(kHandshakePayloadSize);
      if (!identify->read_message_1(frame->noise_message, payload)) {
        ++stats_.handshakes_failed;
        return std::unexpected(ControlError::handshake_failed);
      }

      const auto& claimed = identify->learned_remote_static();
      for (const auto& [peer_id, config] : peers_) {
        if (constant_time_equal(claimed, config.static_public)) {
          matched = &config;
          matched_id = peer_id;
          break;
        }
      }
    }

    if (matched == nullptr) {
      ++stats_.handshakes_failed;
      return std::unexpected(ControlError::unknown_peer);
    }

    {
      auto handshake = NoiseHandshake::create(HandshakeRole::responder, local_static_,
                                              PublicKey{}, matched->preshared);
      if (!handshake) return std::unexpected(ControlError::handshake_failed);

      std::vector<std::byte> payload(kHandshakePayloadSize);
      if (!handshake->read_message_1(frame->noise_message, payload)) {
        ++stats_.handshakes_failed;
        return std::unexpected(ControlError::handshake_failed);
      }

      const auto remote_key_id = payload_key_id(payload);
      if (remote_key_id == kPreSessionKeyId) {
        ++stats_.handshakes_failed;
        return std::unexpected(ControlError::invalid_message);
      }

      const auto timestamp = payload_timestamp(payload);
      if (const auto seen = greatest_timestamp_.find(matched_id);
          seen != greatest_timestamp_.end() && timestamp <= seen->second) {
        ++stats_.replayed_initiations;
        return std::unexpected(ControlError::invalid_message);
      }
      greatest_timestamp_[matched_id] = timestamp;

      const auto key_id = sessions_->allocate_key_id();
      if (!key_id) return std::unexpected(ControlError::session_install_failed);

      const auto reply_payload = build_payload(ProtocolVersion{}, 0, *key_id, handshake_timestamp());
      std::vector<std::byte> message(kNoiseMessage2Overhead + reply_payload.size());
      const auto written = handshake->write_message_2(reply_payload, message);
      if (!written) {
        ++stats_.handshakes_failed;
        return std::unexpected(ControlError::handshake_failed);
      }

      const auto completed = handshake->result();
      if (!completed) {
        ++stats_.handshakes_failed;
        return std::unexpected(ControlError::handshake_failed);
      }

      if (!constant_time_equal(completed->remote_static, matched->static_public)) {
        ++stats_.handshakes_failed;
        return std::unexpected(ControlError::handshake_failed);
      }

      if (provisional_.size() >= kMaximumPending) {
        ++stats_.pending_rejected;
        return std::unexpected(ControlError::too_many_pending);
      }
      provisional_[*key_id] = Provisional{.peer = matched_id,
                                          .local_key_id = *key_id,
                                          .remote_key_id = remote_key_id,
                                          .result = *completed,
                                          .endpoint = source,
                                          .created = now};

      static_cast<void>(timers_->schedule(TimerKind::handshake_timeout,
                                          static_cast<std::uint32_t>(*key_id),
                                          now + kHandshakeTimeout));

      auto reply = serialize_handshake_frame_with_macs(HandshakeMessage::response,
                                                       std::span{message}.first(*written));
      if (!reply) return std::unexpected(ControlError::handshake_failed);

      const auto first = mac1_offset(*written);
      const auto mac = issuer_.compute_mac1(std::span{*reply}.first(first));
      std::copy(mac.begin(), mac.end(), reply->begin() + static_cast<std::ptrdiff_t>(first));

      ++stats_.responder_handshakes;
      return OutgoingHandshake{.destination = source, .datagram = std::move(*reply)};
    }

    ++stats_.handshakes_failed;
    return std::unexpected(ControlError::handshake_failed);
  }

  if (frame->message == HandshakeMessage::response) {
    for (auto& [peer_id, entry] : pending_) {
      if (!entry.handshake.has_value()) continue;

      std::vector<std::byte> payload(kHandshakePayloadSize);
      const auto read = entry.handshake->read_message_2(frame->noise_message, payload);
      if (!read) continue;

      const auto completed = entry.handshake->result();
      if (!completed) continue;

      const auto responder_key_id = payload_key_id(payload);
      if (responder_key_id == kPreSessionKeyId) continue;

      const auto installed =
          install_session(peer_id, entry.local_key_id, responder_key_id, *completed, source);
      if (!installed) return std::unexpected(installed.error());

      const auto finished_peer = peer_id;
      pending_.erase(finished_peer);
      ++stats_.handshakes_completed;

      keepalive_due_.push_back(finished_peer);
      return std::optional<OutgoingHandshake>{};
    }

    ++stats_.handshakes_failed;
    return std::unexpected(ControlError::not_pending);
  }

  return std::unexpected(ControlError::invalid_message);
}

void ControlPlane::evaluate_load(std::size_t queue_depth, std::size_t queue_capacity,
                                 Instant now) {
  const LoadSample sample{
      .handshakes_received = handshakes_seen_,
      .handshakes_completed = stats_.handshakes_completed,
      .queue_depth = queue_depth,
      .queue_capacity = queue_capacity,
      .pending_handshakes = pending_.size() + provisional_.size(),
      .pending_capacity = kMaximumPending,
  };

  load_monitor_.observe(sample, now);
  issuer_.set_under_load(load_monitor_.under_load());
}

std::expected<std::size_t, ControlError> ControlPlane::try_promote_provisional(
    const PacketView& view, std::span<const std::byte> datagram, std::span<std::byte> out,
    const Endpoint& source) {
  const auto entry = provisional_.find(view.header.key_id);
  if (entry == provisional_.end()) return std::unexpected(ControlError::not_pending);

  Session candidate{entry->second.peer, entry->second.local_key_id, entry->second.remote_key_id,
                    TrafficKeys{entry->second.result.send, 0},
                    TrafficKeys{entry->second.result.receive, 0}};

  const auto opened = candidate.open(view, datagram, out);
  if (!opened) {
    return std::unexpected(ControlError::handshake_failed);
  }

  const auto installed =
      sessions_->install(entry->second.peer, entry->second.local_key_id, std::move(candidate));
  provisional_.erase(entry);
  if (!installed) return std::unexpected(ControlError::session_install_failed);

  (*installed)->note_authenticated_endpoint(source);

  const auto peer = (*installed)->peer();
  timers_->cancel(TimerKind::handshake_timeout, peer);
  timers_->cancel(TimerKind::handshake_retry, peer);
  static_cast<void>(timers_->schedule(TimerKind::rekey, peer,
                                      std::chrono::steady_clock::now() + kRekeyAfter));
  static_cast<void>(timers_->schedule(TimerKind::keepalive, peer,
                                      std::chrono::steady_clock::now() + kKeepaliveInterval));

  ++stats_.provisional_promoted;
  ++stats_.handshakes_completed;
  return *opened;
}

std::vector<OutgoingHandshake> ControlPlane::on_timers(std::span<const TimerEvent> events,
                                                       Instant now) {
  std::vector<OutgoingHandshake> outgoing;

  for (const auto& event : events) {
    switch (event.kind) {
      case TimerKind::handshake_timeout: {
        if (pending_.erase(event.subject) > 0) {
          ++stats_.handshakes_timed_out;
          timers_->cancel(TimerKind::handshake_retry, event.subject);
        }

        if (event.subject <= 0xFFFFU &&
            provisional_.erase(static_cast<std::uint16_t>(event.subject)) > 0) {
          ++stats_.handshakes_timed_out;
        }
        break;
      }

      case TimerKind::handshake_retry: {
        const auto entry = pending_.find(event.subject);
        if (entry == pending_.end()) break;

        ++entry->second.attempt;
        ++stats_.retries;
        auto retry = build_initiation(entry->second, now);
        if (retry) outgoing.push_back(std::move(*retry));
        break;
      }

      case TimerKind::rekey: {
        auto started = start_handshake(event.subject, now);
        if (started) outgoing.push_back(std::move(*started));
        break;
      }

      case TimerKind::keepalive:

        keepalive_due_.push_back(event.subject);
        static_cast<void>(
            timers_->schedule(TimerKind::keepalive, event.subject, now + kKeepaliveInterval));
        break;

      case TimerKind::session_expiry:
      case TimerKind::path_probe:
      case TimerKind::dead_peer:

        break;
    }
  }

  return outgoing;
}

}
