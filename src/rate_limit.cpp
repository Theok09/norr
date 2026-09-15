#include "norr/rate_limit.hpp"

#include <algorithm>

namespace norr {
namespace {
[[nodiscard]] std::uint64_t hash_endpoint(const Endpoint& endpoint) noexcept {
  constexpr std::uint64_t kOffsetBasis = 1469598103934665603ULL;
  constexpr std::uint64_t kPrime = 1099511628211ULL;

  std::uint64_t hash = kOffsetBasis;
  for (const auto octet : endpoint.address().bytes()) {
    hash ^= static_cast<std::uint64_t>(octet);
    hash *= kPrime;
  }

  return hash;
}

}

void TokenBucket::refill(Instant now) noexcept {
  if (now <= last_) return;
  const auto elapsed = std::chrono::duration<double>(now - last_).count();
  tokens_ = std::min(capacity_, tokens_ + elapsed * refill_per_second_);
  last_ = now;
}

bool TokenBucket::consume(Instant now, double tokens) noexcept {
  refill(now);
  if (tokens_ < tokens) return false;
  tokens_ -= tokens;
  return true;
}

double TokenBucket::available(Instant now) noexcept {
  refill(now);
  return tokens_;
}

SourceRateLimiter::SourceRateLimiter(double burst, double per_second)
    : burst_(burst), per_second_(per_second), buckets_(kBucketCount) {}

std::size_t SourceRateLimiter::index_of(const Endpoint& source) const noexcept {
  return static_cast<std::size_t>(hash_endpoint(source) % kBucketCount);
}

bool SourceRateLimiter::allow(const Endpoint& source, Instant now) noexcept {
  auto& bucket = buckets_[index_of(source)];

  if (!bucket.initialized()) {
    bucket = TokenBucket{burst_, per_second_, now};
  }

  if (bucket.consume(now)) {
    ++allowed_;
    return true;
  }
  ++rejected_;
  return false;
}

}
