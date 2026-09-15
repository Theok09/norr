#include "norr/congestion.hpp"

#include <algorithm>
#include <cmath>

namespace norr {
namespace {
[[nodiscard]] double to_seconds(Duration duration) noexcept {
  return std::chrono::duration<double>(duration).count();
}

}

Duration CongestionController::queueing_delay() const noexcept {
  if (smoothed_rtt_ <= minimum_rtt_) return Duration::zero();
  return smoothed_rtt_ - minimum_rtt_;
}

void CongestionController::update_rtt(Duration sample, Instant now) {
  if (sample <= Duration::zero()) return;

  if (!primed_) {
    smoothed_rtt_ = sample;
    rtt_variance_ = sample / 2;
    minimum_rtt_ = sample;
    primed_ = true;
  } else {
    const auto difference = sample > smoothed_rtt_ ? sample - smoothed_rtt_ : smoothed_rtt_ - sample;
    rtt_variance_ = (rtt_variance_ * 3 + difference) / 4;
    smoothed_rtt_ = (smoothed_rtt_ * 7 + sample) / 8;
  }

  minimum_window_.push_back(RttSample{.rtt = sample, .at = now});

  while (!minimum_window_.empty() && now - minimum_window_.front().at > config_.minimum_rtt_window) {
    minimum_window_.pop_front();
  }

  minimum_rtt_ = minimum_window_.empty() ? sample : minimum_window_.front().rtt;
  for (const auto& entry : minimum_window_) {
    minimum_rtt_ = std::min(minimum_rtt_, entry.rtt);
  }
}

void CongestionController::observe(const DeliverySample& sample, Instant now) {
  ++stats_.samples;
  update_rtt(sample.rtt, now);

  const auto seconds = to_seconds(sample.interval);
  if (seconds > 0.0) {
    delivery_rate_ = static_cast<double>(sample.bytes_delivered) / seconds;
  }

  const auto total = sample.bytes_delivered + sample.bytes_lost;
  loss_fraction_ = total > 0 ? static_cast<double>(sample.bytes_lost) / static_cast<double>(total)
                             : 0.0;

  const auto queueing = queueing_delay();

  const auto tolerance = std::min<Duration>(rtt_variance_ * 2, config_.maximum_jitter_tolerance);
  const auto delay_limit = tolerance + config_.delay_threshold;

  if (queueing > delay_limit) {
    rate_ *= config_.backoff_delay;
    last_action_ = CongestionAction::back_off_delay;
    ++stats_.delay_backoffs;
  } else if (loss_fraction_ > config_.loss_threshold) {
    rate_ *= config_.backoff_loss;
    last_action_ = CongestionAction::back_off_loss;
    ++stats_.loss_backoffs;
  } else if (queueing < rtt_variance_) {
    const auto probed = rate_ * config_.probe_gain;
    const auto ceiling = delivery_rate_ > 0.0 ? delivery_rate_ * config_.probe_ceiling
                                              : probed;
    rate_ = std::min(probed, ceiling);
    last_action_ = CongestionAction::probe;
    ++stats_.probes;
  } else {
    last_action_ = CongestionAction::hold;
  }

  rate_ = std::clamp(rate_, config_.minimum_rate_bytes, config_.maximum_rate_bytes);
}

}
