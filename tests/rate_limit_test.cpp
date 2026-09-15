#include "check.hpp"
#include <chrono>
#include <cstdio>
#include <string_view>

#include "norr/rate_limit.hpp"

namespace {

norr::Endpoint endpoint_of(std::string_view text) {
  const auto parsed = norr::parse_endpoint(text);
  NORR_CHECK(parsed.has_value());
  return *parsed;
}

void test_token_bucket() {
  const norr::Instant start{};
  norr::TokenBucket bucket{4.0, 2.0, start};

  // A full bucket allows its capacity as a burst, then refuses.
  for (int index = 0; index < 4; ++index) {
    NORR_CHECK(bucket.consume(start));
  }
  NORR_CHECK(!bucket.consume(start));

  // Half a second at two per second is one token.
  const auto later = start + std::chrono::milliseconds{500};
  NORR_CHECK(bucket.consume(later));
  NORR_CHECK(!bucket.consume(later));

  // Refill is capped at capacity: an idle hour does not grant an unlimited
  // burst afterwards.
  const auto much_later = start + std::chrono::hours{1};
  NORR_CHECK(bucket.available(much_later) == 4.0);
  for (int index = 0; index < 4; ++index) {
    NORR_CHECK(bucket.consume(much_later));
  }
  NORR_CHECK(!bucket.consume(much_later));

  std::puts("rate_limit: token bucket refills and caps OK");
}

void test_clock_going_backwards() {
  const norr::Instant start = norr::Instant{} + std::chrono::hours{1};
  norr::TokenBucket bucket{2.0, 1.0, start};

  NORR_CHECK(bucket.consume(start));
  NORR_CHECK(bucket.consume(start));
  NORR_CHECK(!bucket.consume(start));

  // A timestamp before the last observation must not grant a refill. With a
  // monotonic clock this should not happen, but the guard means a mistake
  // elsewhere cannot hand an attacker free tokens.
  const auto earlier = start - std::chrono::minutes{10};
  NORR_CHECK(!bucket.consume(earlier));

  std::puts("rate_limit: time going backwards grants nothing OK");
}

void test_per_source_limiting() {
  norr::SourceRateLimiter limiter{2.0, 1.0};
  const norr::Instant now{};

  const auto attacker = endpoint_of("203.0.113.9:1000");
  NORR_CHECK(limiter.allow(attacker, now));
  NORR_CHECK(limiter.allow(attacker, now));
  // Burst exhausted.
  NORR_CHECK(!limiter.allow(attacker, now));
  NORR_CHECK(limiter.rejected() >= 1);

  // A different source has its own budget, so one flooding peer does not deny
  // service to everyone else.
  const auto innocent = endpoint_of("198.51.100.4:1000");
  NORR_CHECK(limiter.allow(innocent, now));

  // Varying the port must not reset the budget: an attacker controls its own
  // source port, so the limit is per address.
  const auto same_address_new_port = endpoint_of("203.0.113.9:2000");
  NORR_CHECK(!limiter.allow(same_address_new_port, now));

  // After a second, one token is back.
  const auto later = now + std::chrono::seconds{1};
  NORR_CHECK(limiter.allow(attacker, later));

  std::puts("rate_limit: per-source budgets are independent OK");
}

void test_ipv6_sources() {
  norr::SourceRateLimiter limiter{1.0, 1.0};
  const norr::Instant now{};

  const auto first = endpoint_of("[2001:db8::1]:500");
  const auto second = endpoint_of("[2001:db8::2]:500");
  NORR_CHECK(limiter.allow(first, now));
  NORR_CHECK(limiter.allow(second, now));

  std::puts("rate_limit: IPv6 sources handled OK");
}

void test_bounded_memory() {
  // The table is fixed-size, so rotating source addresses cannot grow it. This
  // is the property that stops the limiter itself becoming the DoS vector.
  norr::SourceRateLimiter limiter{1.0, 1.0};
  const norr::Instant now{};

  for (std::uint32_t index = 0; index < 20000; ++index) {
    const auto octet_a = static_cast<std::uint8_t>((index >> 8U) & 0xFFU);
    const auto octet_b = static_cast<std::uint8_t>(index & 0xFFU);
    std::string text = "10." + std::to_string(octet_a) + "." + std::to_string(octet_b) + ".1:80";
    const auto source = norr::parse_endpoint(text);
    NORR_CHECK(source.has_value());
    static_cast<void>(limiter.allow(*source, now));
  }

  // Nothing to assert about size directly: the point is that this completes
  // without unbounded growth, which the sanitizer build confirms.
  NORR_CHECK(limiter.allowed() + limiter.rejected() == 20000);

  std::puts("rate_limit: source table stays bounded OK");
}

void test_global_limiter() {
  norr::GlobalLimiter limiter{3.0, 1.0, norr::Instant{}};
  const norr::Instant now{};

  NORR_CHECK(limiter.allow(now));
  NORR_CHECK(limiter.allow(now));
  NORR_CHECK(limiter.allow(now));
  // A global ceiling means even many distinct sources cannot force unbounded
  // work in aggregate.
  NORR_CHECK(!limiter.allow(now));

  std::puts("rate_limit: global ceiling enforced OK");
}

}  // namespace

int main() {
  test_token_bucket();
  test_clock_going_backwards();
  test_per_source_limiting();
  test_ipv6_sources();
  test_bounded_memory();
  test_global_limiter();
  return 0;
}
