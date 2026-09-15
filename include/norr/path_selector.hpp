#pragma once

#include <array>
#include <cstdint>
#include <string_view>

#include "norr/rate_limit.hpp"

namespace norr {
enum class TransportKind : std::uint8_t { udp, quic, tcp_tls };

[[nodiscard]] constexpr std::string_view transport_kind_name(TransportKind kind) noexcept {
  switch (kind) {
    case TransportKind::udp: return "udp";
    case TransportKind::quic: return "quic";
    case TransportKind::tcp_tls: return "tcp-tls";
  }
  return "unknown";
}

enum class PathState : std::uint8_t { probing, healthy, degraded, failed, recovering };

[[nodiscard]] constexpr std::string_view path_state_name(PathState state) noexcept {
  switch (state) {
    case PathState::probing: return "probing";
    case PathState::healthy: return "healthy";
    case PathState::degraded: return "degraded";
    case PathState::failed: return "failed";
    case PathState::recovering: return "recovering";
  }
  return "unknown";
}

struct PathSample {
  double rtt_microseconds{};
  double loss_fraction{};
  std::uint64_t transport_errors{};
  bool reachable{true};
};

struct PathThresholds {
  double loss_degraded{0.05};
  double loss_healthy{0.02};
  double rtt_degraded_microseconds{200'000.0};
  double rtt_healthy_microseconds{120'000.0};

  std::uint32_t promotion_window{5};

  std::uint32_t demotion_threshold{3};

  Duration cooldown{std::chrono::seconds{10}};

  double minimum_improvement{0.15};
};

class Path {
 public:
  Path() = default;
  explicit Path(TransportKind kind) noexcept : kind_(kind) {}

  void observe(const PathSample& sample, const PathThresholds& thresholds);

  [[nodiscard]] TransportKind kind() const noexcept { return kind_; }
  [[nodiscard]] PathState state() const noexcept { return state_; }
  [[nodiscard]] bool usable() const noexcept {
    return state_ == PathState::healthy || state_ == PathState::degraded;
  }

  [[nodiscard]] double score() const noexcept { return score_; }

  [[nodiscard]] std::uint32_t consecutive_good() const noexcept { return good_; }
  [[nodiscard]] std::uint32_t consecutive_bad() const noexcept { return bad_; }

 private:
  TransportKind kind_{TransportKind::udp};
  PathState state_{PathState::probing};
  double score_{1.0};
  double smoothed_loss_{};
  double smoothed_rtt_{};
  std::uint32_t good_{};
  std::uint32_t bad_{};
  bool primed_{};
};

struct SelectorStats {
  std::uint64_t switches{};
  std::uint64_t switches_suppressed_by_cooldown{};
  std::uint64_t switches_suppressed_by_margin{};
  std::uint64_t failovers{};
};

class PathSelector {
 public:
  explicit PathSelector(PathThresholds thresholds = {}) noexcept : thresholds_(thresholds) {}

  void add_path(TransportKind kind);

  void observe(TransportKind kind, const PathSample& sample);

  [[nodiscard]] bool evaluate(Instant now);

  [[nodiscard]] TransportKind active() const noexcept { return active_; }
  [[nodiscard]] const Path* path(TransportKind kind) const noexcept;
  [[nodiscard]] std::size_t size() const noexcept { return count_; }
  [[nodiscard]] const SelectorStats& stats() const noexcept { return stats_; }

  [[nodiscard]] Instant last_switch() const noexcept { return last_switch_; }

 private:
  [[nodiscard]] Path* find(TransportKind kind) noexcept;

  PathThresholds thresholds_;
  std::array<Path, 3> paths_{};
  std::size_t count_{};
  TransportKind active_{TransportKind::udp};
  Instant last_switch_{};
  bool has_active_{};
  SelectorStats stats_{};
};

}
