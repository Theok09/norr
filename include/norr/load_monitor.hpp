// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "norr/rate_limit.hpp"

namespace norr {
enum class LoadState { normal, elevated, overloaded };

[[nodiscard]] constexpr std::string_view load_state_name(LoadState state) noexcept {
  switch (state) {
    case LoadState::normal: return "normal";
    case LoadState::elevated: return "elevated";
    case LoadState::overloaded: return "overloaded";
  }
  return "unknown";
}

struct LoadSample {
  std::uint64_t handshakes_received{};

  std::uint64_t handshakes_completed{};

  std::size_t queue_depth{};
  std::size_t queue_capacity{};

  std::size_t pending_handshakes{};
  std::size_t pending_capacity{};
};

struct LoadThresholds {
  double handshakes_per_second_high{50.0};
  double handshakes_per_second_low{20.0};

  double queue_fraction_high{0.60};
  double queue_fraction_low{0.30};

  double pending_fraction_high{0.50};
  double pending_fraction_low{0.20};

  double completion_ratio_low{0.25};

  std::uint64_t completion_ratio_minimum{20};
};

class LoadMonitor {
 public:
  explicit LoadMonitor(LoadThresholds thresholds = {}) noexcept : thresholds_(thresholds) {}

  void observe(const LoadSample& sample, Instant now);

  [[nodiscard]] LoadState state() const noexcept { return state_; }

  [[nodiscard]] bool under_load() const noexcept { return state_ == LoadState::overloaded; }

  [[nodiscard]] double handshakes_per_second() const noexcept { return handshake_rate_; }
  [[nodiscard]] double queue_fraction() const noexcept { return queue_fraction_; }
  [[nodiscard]] double pending_fraction() const noexcept { return pending_fraction_; }

  [[nodiscard]] std::uint64_t transitions() const noexcept { return transitions_; }

 private:
  [[nodiscard]] bool any_high() const noexcept;
  [[nodiscard]] bool all_low() const noexcept;

  LoadThresholds thresholds_;
  LoadState state_{LoadState::normal};

  Instant last_{};
  std::uint64_t last_received_{};
  std::uint64_t last_completed_{};
  bool primed_{};

  double handshake_rate_{};
  double queue_fraction_{};
  double pending_fraction_{};
  double completion_ratio_{1.0};

  std::uint64_t transitions_{};
};

}
