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
