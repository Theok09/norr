// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#include "norr/pacer.hpp"

#include <algorithm>
#include <chrono>

namespace norr {
Pacer::Pacer(double bytes_per_second, std::size_t burst_bytes, Instant now) noexcept
    : rate_(bytes_per_second),
      capacity_(static_cast<double>(std::max(burst_bytes, kMinimumBurstBytes))),
      available_(static_cast<double>(std::max(burst_bytes, kMinimumBurstBytes))),
      last_(now),
      enabled_(bytes_per_second > 0.0) {}

void Pacer::refill(Instant now) noexcept {
  if (now <= last_) return;
  const auto elapsed = std::chrono::duration<double>(now - last_).count();
  available_ = std::min(capacity_, available_ + elapsed * rate_);
  last_ = now;
}

bool Pacer::allow(std::size_t bytes, Instant now) noexcept {
  if (!enabled_) return true;
  refill(now);

  const auto needed = static_cast<double>(bytes);

  if (needed > capacity_) {
    available_ = 0.0;
    paced_bytes_ += bytes;
    return true;
  }

  if (available_ < needed) {
    ++deferred_;
    return false;
  }

  available_ -= needed;
  paced_bytes_ += bytes;
  return true;
}

Duration Pacer::delay_for(std::size_t bytes, Instant now) noexcept {
  if (!enabled_) return Duration::zero();
  refill(now);

  const auto needed = static_cast<double>(bytes);
  if (needed > capacity_ || available_ >= needed) return Duration::zero();
  if (rate_ <= 0.0) return Duration::zero();

  const auto seconds = (needed - available_) / rate_;
  return std::chrono::duration_cast<Duration>(std::chrono::duration<double>(seconds));
}

}
