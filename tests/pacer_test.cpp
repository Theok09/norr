
#include "check.hpp"
#include <chrono>
#include <cstdio>

#include "norr/pacer.hpp"

namespace {
void test_disabled_by_default() {
  norr::Pacer pacer;
  NORR_CHECK(!pacer.enabled());

  NORR_CHECK(pacer.allow(1'000'000, norr::Instant{}));
  NORR_CHECK(pacer.delay_for(1'000'000, norr::Instant{}) == norr::Duration::zero());

  std::puts("pacer: disabled by default OK");
}

void test_burst_then_rate() {
  const auto start = norr::Instant{};

  norr::Pacer pacer{1'000'000.0, 10'000, start};
  NORR_CHECK(pacer.enabled());

  NORR_CHECK(pacer.allow(5'000, start));
  NORR_CHECK(pacer.allow(5'000, start));

  NORR_CHECK(!pacer.allow(1'000, start));
  NORR_CHECK(pacer.deferred() == 1);

  const auto later = start + std::chrono::milliseconds{1};
  NORR_CHECK(pacer.allow(1'000, later));
  NORR_CHECK(!pacer.allow(1'000, later));

  std::puts("pacer: burst then sustained rate OK");
}

void test_refill_is_capped() {
  const auto start = norr::Instant{};
  norr::Pacer pacer{1'000'000.0, 10'000, start};

  NORR_CHECK(pacer.allow(10'000, start));

  const auto much_later = start + std::chrono::hours{1};
  NORR_CHECK(pacer.allow(10'000, much_later));
  NORR_CHECK(!pacer.allow(1, much_later));

  std::puts("pacer: refill capped at the burst size OK");
}

void test_oversized_packet_is_not_stalled() {
  const auto start = norr::Instant{};

  norr::Pacer pacer{1'000'000.0, norr::Pacer::kMinimumBurstBytes, start};

  NORR_CHECK(pacer.allow(9'000, start));
  NORR_CHECK(pacer.delay_for(9'000, start) == norr::Duration::zero());

  std::puts("pacer: oversized packet is not stalled forever OK");
}

void test_minimum_burst() {
  const auto start = norr::Instant{};

  norr::Pacer pacer{1'000'000.0, 1, start};
  NORR_CHECK(pacer.allow(norr::Pacer::kMinimumBurstBytes, start));

  std::puts("pacer: minimum burst enforced OK");
}

void test_delay_for() {
  const auto start = norr::Instant{};
  norr::Pacer pacer{1'000'000.0, 10'000, start};

  NORR_CHECK(pacer.delay_for(1'000, start) == norr::Duration::zero());

  NORR_CHECK(pacer.allow(10'000, start));

  const auto wait = pacer.delay_for(1'000, start);
  NORR_CHECK(wait > norr::Duration::zero());
  const auto milliseconds =
      std::chrono::duration_cast<std::chrono::microseconds>(wait).count();
  NORR_CHECK(milliseconds >= 900 && milliseconds <= 1100);

  std::puts("pacer: delay_for reports a usable wait OK");
}

void test_clock_going_backwards() {
  const auto start = norr::Instant{} + std::chrono::hours{1};
  norr::Pacer pacer{1'000'000.0, 10'000, start};

  NORR_CHECK(pacer.allow(10'000, start));
  NORR_CHECK(!pacer.allow(1'000, start));

  const auto earlier = start - std::chrono::minutes{5};
  NORR_CHECK(!pacer.allow(1'000, earlier));

  std::puts("pacer: time going backwards grants nothing OK");
}

void test_accounting() {
  const auto start = norr::Instant{};
  norr::Pacer pacer{1'000'000.0, 10'000, start};

  NORR_CHECK(pacer.allow(4'000, start));
  NORR_CHECK(pacer.allow(4'000, start));
  NORR_CHECK(pacer.paced_bytes() == 8'000);

  std::puts("pacer: byte accounting OK");
}
}

int main() {
  test_disabled_by_default();
  test_burst_then_rate();
  test_refill_is_capped();
  test_oversized_packet_is_not_stalled();
  test_minimum_burst();
  test_delay_for();
  test_clock_going_backwards();
  test_accounting();
  return 0;
}
