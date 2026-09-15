#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "norr/endpoint.hpp"

namespace norr {
using Instant = std::chrono::steady_clock::time_point;
using Duration = std::chrono::steady_clock::duration;

class TokenBucket {
 public:
  TokenBucket() = default;
  TokenBucket(double capacity, double refill_per_second, Instant now) noexcept
      : capacity_(capacity), refill_per_second_(refill_per_second), tokens_(capacity),
        last_(now), initialized_(true) {}

  [[nodiscard]] bool initialized() const noexcept { return initialized_; }

  [[nodiscard]] bool consume(Instant now, double tokens = 1.0) noexcept;

  [[nodiscard]] double available(Instant now) noexcept;

 private:
  void refill(Instant now) noexcept;

  double capacity_{};
  double refill_per_second_{};
  double tokens_{};
  Instant last_{};
  bool initialized_{};
};

class SourceRateLimiter {
 public:
  static constexpr std::size_t kBucketCount = 4096;

  static constexpr double kDefaultBurst = 8.0;
  static constexpr double kDefaultPerSecond = 2.0;

  explicit SourceRateLimiter(double burst = kDefaultBurst,
                             double per_second = kDefaultPerSecond);

  [[nodiscard]] bool allow(const Endpoint& source, Instant now) noexcept;

  [[nodiscard]] std::uint64_t allowed() const noexcept { return allowed_; }
  [[nodiscard]] std::uint64_t rejected() const noexcept { return rejected_; }

 private:
  [[nodiscard]] std::size_t index_of(const Endpoint& source) const noexcept;

  double burst_{};
  double per_second_{};
  std::vector<TokenBucket> buckets_;
  std::uint64_t allowed_{};
  std::uint64_t rejected_{};
};

class GlobalLimiter {
 public:
  static constexpr double kDefaultBurst = 256.0;
  static constexpr double kDefaultPerSecond = 64.0;

  explicit GlobalLimiter(double burst = kDefaultBurst, double per_second = kDefaultPerSecond,
                         Instant now = Instant{})
      : bucket_(burst, per_second, now) {}

  [[nodiscard]] bool allow(Instant now) noexcept { return bucket_.consume(now); }

 private:
  TokenBucket bucket_;
};

}
