// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#pragma once

#include <cstddef>
#include <cstdint>

#include "norr/rate_limit.hpp"

namespace norr {
class Pacer {
 public:

  static constexpr std::size_t kMinimumBurstBytes = 1500;

  Pacer() = default;
  Pacer(double bytes_per_second, std::size_t burst_bytes, Instant now) noexcept;

  [[nodiscard]] bool allow(std::size_t bytes, Instant now) noexcept;

  [[nodiscard]] Duration delay_for(std::size_t bytes, Instant now) noexcept;

  [[nodiscard]] bool enabled() const noexcept { return enabled_; }

  [[nodiscard]] double rate_bytes_per_second() const noexcept { return rate_; }

  void set_rate_bytes_per_second(double rate) noexcept {
    rate_ = rate > 0.0 ? rate : 0.0;
    enabled_ = rate_ > 0.0;
  }
  [[nodiscard]] std::uint64_t paced_bytes() const noexcept { return paced_bytes_; }
  [[nodiscard]] std::uint64_t deferred() const noexcept { return deferred_; }

 private:
  void refill(Instant now) noexcept;

  double rate_{};
  double capacity_{};
  double available_{};
  Instant last_{};
  bool enabled_{};
  std::uint64_t paced_bytes_{};
  std::uint64_t deferred_{};
};
}
