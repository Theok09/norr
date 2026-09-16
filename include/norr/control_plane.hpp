#pragma once

#include <cstdint>
#include <expected>
#include <optional>
#include <utility>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "norr/cookie.hpp"
#include "norr/load_monitor.hpp"
#include "norr/noise.hpp"
#include "norr/packet.hpp"
#include "norr/rate_limit.hpp"
#include "norr/session.hpp"
#include "norr/timers.hpp"

namespace norr {
enum class ControlError {
  unknown_peer,
  rate_limited,
  too_many_pending,
  handshake_failed,
  session_install_failed,
  invalid_message,
  not_pending,
  crypto_unavailable,
  timer_capacity,
};

[[nodiscard]] constexpr std::string_view control_error_message(ControlError error) noexcept {
  switch (error) {
    case ControlError::unknown_peer: return "unknown peer";
    case ControlError::rate_limited: return "rate limited";
    case ControlError::too_many_pending: return "too many pending handshakes";
    case ControlError::handshake_failed: return "handshake failed";
    case ControlError::session_install_failed: return "session install failed";
    case ControlError::invalid_message: return "invalid handshake message";
    case ControlError::not_pending: return "no pending handshake for this peer";
    case ControlError::crypto_unavailable: return "crypto backend not available";
    case ControlError::timer_capacity: return "timer capacity reached";
  }
  return "unknown control error";
}

struct PeerConfig {
  PeerId id{kNoPeer};
  PublicKey static_public{};
  PresharedKey preshared{};

  std::optional<Endpoint> endpoint;
};

struct ControlStats {
  std::uint64_t handshakes_started{};
  std::uint64_t handshakes_completed{};
  std::uint64_t handshakes_failed{};
  std::uint64_t handshakes_timed_out{};
  std::uint64_t retries{};
  std::uint64_t rate_limited{};
  std::uint64_t pending_rejected{};
  std::uint64_t responder_handshakes{};
  std::uint64_t provisional_promoted{};
  std::uint64_t cookies_issued{};
  std::uint64_t cookies_accepted{};
  std::uint64_t mac1_failures{};
  std::uint64_t mac2_failures{};
  std::uint64_t replayed_initiations{};
};

struct OutgoingHandshake {
  Endpoint destination;
  std::vector<std::byte> datagram;
};

class ControlPlane {
 public:

  static constexpr std::size_t kMaximumPending = 256;

  ControlPlane(const KeyPair& local_static, SessionTable& sessions, TimerWheel& timers);

  [[nodiscard]] std::expected<void, ControlError> add_peer(const PeerConfig& peer);

  [[nodiscard]] const PeerConfig* find_peer(PeerId peer) const noexcept;

  // Forgets a peer's configuration and any half-open handshake for it.
  //
  // Established sessions are left alone: a reload that removed a peer from the
  // configuration should stop new handshakes, and the datapath drops its
  // traffic once the routes are gone, but tearing a live session down inside
  // the reload would drop packets that are already in flight.
  void forget_peer(PeerId peer);

  [[nodiscard]] std::size_t peer_count() const noexcept { return peers_.size(); }

  [[nodiscard]] std::expected<OutgoingHandshake, ControlError> start_handshake(PeerId peer,
                                                                               Instant now);

  [[nodiscard]] std::expected<std::optional<OutgoingHandshake>, ControlError> handle_datagram(
      const Endpoint& source, std::span<const std::byte> datagram, Instant now);

  [[nodiscard]] std::vector<OutgoingHandshake> on_timers(std::span<const TimerEvent> events,
                                                         Instant now);

  [[nodiscard]] std::size_t pending() const noexcept { return pending_.size(); }

  [[nodiscard]] std::size_t provisional() const noexcept { return provisional_.size(); }

  [[nodiscard]] std::expected<std::size_t, ControlError> try_promote_provisional(
      const PacketView& view, std::span<const std::byte> datagram, std::span<std::byte> out,
      const Endpoint& source);

  [[nodiscard]] bool has_provisional(std::uint16_t local_key_id) const noexcept {
    return provisional_.contains(local_key_id);
  }

  [[nodiscard]] std::vector<PeerId> take_expired_keepalives() {
    return std::exchange(keepalive_due_, {});
  }

  [[nodiscard]] const ControlStats& stats() const noexcept { return stats_; }

  [[nodiscard]] SourceRateLimiter& rate_limiter() noexcept { return rate_limiter_; }

  void set_under_load(bool value) noexcept { issuer_.set_under_load(value); }
  [[nodiscard]] bool under_load() const noexcept { return issuer_.under_load(); }

  void evaluate_load(std::size_t queue_depth, std::size_t queue_capacity, Instant now);

  [[nodiscard]] const LoadMonitor& load() const noexcept { return load_monitor_; }
  [[nodiscard]] LoadMonitor& load() noexcept { return load_monitor_; }

 private:
  struct Pending {
    PeerId peer{kNoPeer};
    std::optional<NoiseHandshake> handshake;
    std::uint16_t local_key_id{};
    std::uint32_t attempt{};
    Endpoint destination;
    Instant started{};

    std::optional<CookieHolder> cookies;
    Mac last_mac1{};
  };

  struct Provisional {
    PeerId peer{kNoPeer};
    std::uint16_t local_key_id{};
    std::uint16_t remote_key_id{};
    NoiseResult result{};
    Endpoint endpoint;
    Instant created{};
  };

  [[nodiscard]] std::expected<OutgoingHandshake, ControlError> build_initiation(Pending& entry,
                                                                                Instant now);

  [[nodiscard]] std::expected<void, ControlError> install_session(PeerId peer,
                                                                  std::uint16_t local_key_id,
                                                                  std::uint16_t remote_key_id,
                                                                  const NoiseResult& result,
                                                                  const Endpoint& endpoint);

  KeyPair local_static_{};
  SessionTable* sessions_;
  TimerWheel* timers_;
  std::unordered_map<PeerId, PeerConfig> peers_;
  std::unordered_map<PeerId, Pending> pending_;

  std::unordered_map<std::uint16_t, Provisional> provisional_;
  std::vector<PeerId> keepalive_due_;
  std::unordered_map<PeerId, std::uint64_t> greatest_timestamp_;
  SourceRateLimiter rate_limiter_;
  GlobalLimiter global_limiter_;
  CookieIssuer issuer_;
  LoadMonitor load_monitor_;

  std::uint64_t handshakes_seen_{};
  ControlStats stats_{};
};

}
