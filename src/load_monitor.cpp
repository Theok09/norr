// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#include "norr/load_monitor.hpp"

#include <algorithm>
#include <chrono>

namespace norr {
namespace {
constexpr double kSmoothing = 0.33;

[[nodiscard]] double smooth(double previous, double sample) noexcept {
  return previous + kSmoothing * (sample - previous);
}

[[nodiscard]] double fraction_of(std::size_t used, std::size_t capacity) noexcept {
  if (capacity == 0) return 0.0;
  return static_cast<double>(used) / static_cast<double>(capacity);
}

}

bool LoadMonitor::any_high() const noexcept {
  if (handshake_rate_ >= thresholds_.handshakes_per_second_high) return true;
  if (queue_fraction_ >= thresholds_.queue_fraction_high) return true;
  if (pending_fraction_ >= thresholds_.pending_fraction_high) return true;
  return false;
}

bool LoadMonitor::all_low() const noexcept {
  return handshake_rate_ <= thresholds_.handshakes_per_second_low &&
         queue_fraction_ <= thresholds_.queue_fraction_low &&
         pending_fraction_ <= thresholds_.pending_fraction_low;
}

void LoadMonitor::observe(const LoadSample& sample, Instant now) {
  queue_fraction_ = smooth(queue_fraction_,
                           fraction_of(sample.queue_depth, sample.queue_capacity));
  pending_fraction_ = smooth(pending_fraction_,
                             fraction_of(sample.pending_handshakes, sample.pending_capacity));

  if (!primed_) {
    primed_ = true;
    last_ = now;
    last_received_ = sample.handshakes_received;
    last_completed_ = sample.handshakes_completed;
    return;
  }

  const auto elapsed = std::chrono::duration<double>(now - last_).count();

  if (elapsed > 0.0) {
    const auto received = sample.handshakes_received >= last_received_
                              ? sample.handshakes_received - last_received_
                              : 0;
    const auto completed = sample.handshakes_completed >= last_completed_
                               ? sample.handshakes_completed - last_completed_
                               : 0;

    handshake_rate_ = smooth(handshake_rate_, static_cast<double>(received) / elapsed);

    if (received >= thresholds_.completion_ratio_minimum) {
      completion_ratio_ =
          smooth(completion_ratio_, static_cast<double>(completed) / static_cast<double>(received));
    }

    last_ = now;
    last_received_ = sample.handshakes_received;
    last_completed_ = sample.handshakes_completed;
  }

  const auto suspicious_pattern = handshake_rate_ >= thresholds_.handshakes_per_second_low &&
                                  completion_ratio_ < thresholds_.completion_ratio_low;

  const auto previous = state_;

  if (any_high() || suspicious_pattern) {
    state_ = LoadState::overloaded;
  } else if (all_low()) {
    state_ = LoadState::normal;
  } else {
    state_ = state_ == LoadState::overloaded ? LoadState::overloaded : LoadState::elevated;
  }

  if (state_ != previous) ++transitions_;
}

}
