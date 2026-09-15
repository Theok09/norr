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
