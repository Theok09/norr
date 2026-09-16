// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <string_view>

#include "norr/rate_limit.hpp"

namespace norr {
struct CongestionConfig {
  Duration delay_threshold{std::chrono::milliseconds{5}};

  Duration maximum_jitter_tolerance{std::chrono::milliseconds{15}};

  double loss_threshold{0.10};

  double backoff_delay{0.85};
  double backoff_loss{0.75};
  double probe_gain{1.05};

  double probe_ceiling{1.25};

  double minimum_rate_bytes{8'000.0};
  double maximum_rate_bytes{1'250'000'000.0};

  Duration minimum_rtt_window{std::chrono::seconds{10}};
};

enum class CongestionAction : std::uint8_t { hold, probe, back_off_delay, back_off_loss };

[[nodiscard]] constexpr std::string_view congestion_action_name(CongestionAction action) noexcept {
  switch (action) {
    case CongestionAction::hold: return "hold";
    case CongestionAction::probe: return "probe";
    case CongestionAction::back_off_delay: return "back_off_delay";
    case CongestionAction::back_off_loss: return "back_off_loss";
  }
  return "unknown";
}

struct DeliverySample {
  Duration rtt{};
  std::uint64_t bytes_delivered{};
  std::uint64_t bytes_lost{};
  Duration interval{};
};

struct CongestionStats {
  std::uint64_t samples{};
  std::uint64_t probes{};
  std::uint64_t delay_backoffs{};
  std::uint64_t loss_backoffs{};
};

class CongestionController {
 public:
  explicit CongestionController(CongestionConfig config = {},
                                double initial_rate_bytes = 125'000.0) noexcept
      : config_(config), rate_(initial_rate_bytes) {}

  void observe(const DeliverySample& sample, Instant now);

  [[nodiscard]] double rate_bytes_per_second() const noexcept { return rate_; }

  [[nodiscard]] Duration smoothed_rtt() const noexcept { return smoothed_rtt_; }
  [[nodiscard]] Duration rtt_variance() const noexcept { return rtt_variance_; }
  [[nodiscard]] Duration minimum_rtt() const noexcept { return minimum_rtt_; }

  [[nodiscard]] Duration queueing_delay() const noexcept;

  [[nodiscard]] double delivery_rate_bytes_per_second() const noexcept { return delivery_rate_; }
  [[nodiscard]] double loss_fraction() const noexcept { return loss_fraction_; }
  [[nodiscard]] CongestionAction last_action() const noexcept { return last_action_; }
  [[nodiscard]] const CongestionStats& stats() const noexcept { return stats_; }

 private:
  void update_rtt(Duration sample, Instant now);

  struct RttSample {
    Duration rtt{};
    Instant at{};
  };

  CongestionConfig config_;
  double rate_{};
  double delivery_rate_{};
  double loss_fraction_{};

  Duration smoothed_rtt_{};
  Duration rtt_variance_{};
  Duration minimum_rtt_{};
  std::deque<RttSample> minimum_window_;

  bool primed_{};
  CongestionAction last_action_{CongestionAction::hold};
  CongestionStats stats_{};
};

}
