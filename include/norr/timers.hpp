#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <vector>

#include "norr/rate_limit.hpp"

namespace norr {
enum class TimerKind {
  handshake_timeout,
  handshake_retry,
  keepalive,
  rekey,
  session_expiry,
  path_probe,
  dead_peer,
};

[[nodiscard]] constexpr std::string_view timer_kind_name(TimerKind kind) noexcept {
  switch (kind) {
    case TimerKind::handshake_timeout: return "handshake_timeout";
    case TimerKind::handshake_retry: return "handshake_retry";
    case TimerKind::keepalive: return "keepalive";
    case TimerKind::rekey: return "rekey";
    case TimerKind::session_expiry: return "session_expiry";
    case TimerKind::path_probe: return "path_probe";
    case TimerKind::dead_peer: return "dead_peer";
  }
  return "unknown";
}

struct TimerEvent {
  TimerKind kind{};
  std::uint32_t subject{};
  Instant due{};
};

inline constexpr auto kHandshakeTimeout = std::chrono::seconds{5};
inline constexpr auto kHandshakeRetryBase = std::chrono::milliseconds{500};
inline constexpr auto kHandshakeRetryMax = std::chrono::seconds{30};
inline constexpr auto kKeepaliveInterval = std::chrono::seconds{25};

// How often transport health is judged, and how long a freshly selected
// carrier is left alone to complete its own handshakes before it is judged at
// all. The settle time has to exceed a TCP connect plus a TLS handshake plus a
// Noise handshake, or a carrier is abandoned while it is still coming up.
inline constexpr auto kTransportCheckInterval = std::chrono::seconds{5};
inline constexpr auto kTransportSettleTime = std::chrono::seconds{15};

// How long a peer may be silent before the carrier it is reached over is
// judged unhealthy. This is deliberately far shorter than kDeadPeerTimeout:
// dropping a session is destructive and waits ninety seconds to be sure, while
// moving to another carrier is cheap and reversible, and waiting the same
// ninety seconds would leave a blocked tunnel dark for a minute and a half.
inline constexpr auto kTransportSilenceTimeout = std::chrono::seconds{15};

// An echo reply claiming a longer round trip than this did not measure one:
// the token predates a restart, or the clock moved. Such a reading is dropped
// rather than allowed to distort the estimate.
inline constexpr auto kMaximumPlausibleRtt = std::chrono::seconds{30};

// How often congestion control reconsiders the sending rate. Frequent enough
// to react within a few round trips on a real path, rare enough that a sample
// covers more than a handful of packets.
inline constexpr auto kCongestionSampleInterval = std::chrono::milliseconds{500};
inline constexpr auto kDeadPeerTimeout = std::chrono::seconds{90};
inline constexpr auto kRekeyAfter = std::chrono::minutes{2};
inline constexpr auto kSessionExpiry = std::chrono::minutes{3};

inline constexpr std::uint64_t kRekeyAfterMessages = 1ULL << 60U;

inline constexpr std::uint64_t kRejectAfterMessages = UINT64_MAX - (1ULL << 13U);
inline constexpr auto kRetireAfter = std::chrono::seconds{10};

[[nodiscard]] Duration retry_backoff(std::uint32_t attempt) noexcept;

class TimerWheel {
 public:
  static constexpr std::size_t kMaximumTimers = 8192;

  [[nodiscard]] bool schedule(TimerKind kind, std::uint32_t subject, Instant due);

  std::size_t cancel(TimerKind kind, std::uint32_t subject);

  std::size_t cancel_subject(std::uint32_t subject);

  [[nodiscard]] std::vector<TimerEvent> expire(Instant now);

  [[nodiscard]] bool empty() const noexcept { return timers_.empty(); }
  [[nodiscard]] std::size_t size() const noexcept { return timers_.size(); }

  [[nodiscard]] Instant next_due() const noexcept;

 private:
  std::vector<TimerEvent> timers_;
};

}
