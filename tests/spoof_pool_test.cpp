#include "check.hpp"
#include <chrono>
#include <cstdio>
#include <set>
#include <vector>

#include "norr/spoof_pool.hpp"

namespace {
std::uint32_t ip(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) {
  return (static_cast<std::uint32_t>(a) << 24U) | (static_cast<std::uint32_t>(b) << 16U) |
         (static_cast<std::uint32_t>(c) << 8U) | static_cast<std::uint32_t>(d);
}

void test_empty_pool() {
  norr::SpoofPool pool;
  NORR_CHECK(pool.empty());
  NORR_CHECK(!pool.pick(123, norr::Instant{}).has_value());
  std::puts("spoof_pool: empty pool yields nothing OK");
}

void test_dedup_and_drop_zero() {
  norr::SpoofPool pool{{ip(1, 1, 1, 1), ip(1, 1, 1, 1), 0, ip(2, 2, 2, 2)}};
  NORR_CHECK(pool.size() == 2);
  std::puts("spoof_pool: duplicates and zero dropped OK");
}

void test_flow_stable() {
  norr::SpoofPool pool{{ip(1, 1, 1, 1), ip(2, 2, 2, 2), ip(3, 3, 3, 3)}};
  const norr::Instant now{};
  const auto first = pool.pick(0xABCD, now);
  NORR_CHECK(first.has_value());
  for (int i = 0; i < 20; ++i) {
    const auto again = pool.pick(0xABCD, now);
    NORR_CHECK(again.has_value());
    NORR_CHECK(again->source_be == first->source_be);
  }
  std::puts("spoof_pool: same flow pins to same source OK");
}

void test_flow_spread() {
  norr::SpoofPool pool{{ip(1, 1, 1, 1), ip(2, 2, 2, 2), ip(3, 3, 3, 3), ip(4, 4, 4, 4)}};
  const norr::Instant now{};
  std::set<std::uint32_t> seen;
  for (std::uint64_t flow = 0; flow < 200; ++flow) {
    const auto p = pool.pick(flow * 0x9E3779B1U + 7, now);
    NORR_CHECK(p.has_value());
    seen.insert(p->source_be);
  }
  NORR_CHECK(seen.size() >= 3);
  std::puts("spoof_pool: distinct flows spread across sources OK");
}

void test_quarantine_and_failover() {
  norr::SpoofPool pool{{ip(1, 1, 1, 1), ip(2, 2, 2, 2)}, {.death_threshold = 2}};
  norr::Instant now{};
  const auto first = pool.pick(0x1234, now);
  NORR_CHECK(first.has_value());

  pool.blame(first->index, now);
  NORR_CHECK(!pool.quarantined(first->index, now));
  pool.blame(first->index, now);
  NORR_CHECK(pool.quarantined(first->index, now));

  const auto next = pool.pick(0x1234, now);
  NORR_CHECK(next.has_value());
  NORR_CHECK(next->source_be != first->source_be);
  std::puts("spoof_pool: blamed source quarantines and flow fails over OK");
}

void test_exponential_backoff() {
  norr::SpoofPool pool{{ip(5, 5, 5, 5)},
                       {.death_threshold = 1,
                        .initial_cooldown = std::chrono::seconds{30},
                        .max_cooldown = std::chrono::minutes{5}}};
  norr::Instant now{};
  pool.blame(0, now);
  NORR_CHECK(pool.quarantined(0, now + std::chrono::seconds{29}));
  NORR_CHECK(!pool.quarantined(0, now + std::chrono::seconds{31}));

  now += std::chrono::seconds{31};
  pool.blame(0, now);
  NORR_CHECK(pool.quarantined(0, now + std::chrono::seconds{59}));
  NORR_CHECK(!pool.quarantined(0, now + std::chrono::seconds{61}));
  std::puts("spoof_pool: cooldown backs off exponentially OK");
}

void test_reward_decays_one_step() {
  norr::SpoofPool pool{{ip(8, 8, 8, 8)},
                       {.death_threshold = 1,
                        .initial_cooldown = std::chrono::seconds{30},
                        .max_cooldown = std::chrono::minutes{30}}};
  norr::Instant now{};
  for (int i = 0; i < 8; ++i) {
    pool.blame(0, now);
    now += std::chrono::minutes{31};
  }
  pool.reward(0);
  pool.blame(0, now);
  NORR_CHECK(pool.quarantined(0, now + std::chrono::minutes{10}));
  std::puts("spoof_pool: one reward only decays backoff one step, not to zero OK");
}

void test_blame_never_overflows_time_point() {
  norr::SpoofPool pool{{ip(3, 3, 3, 3)},
                       {.death_threshold = 1,
                        .initial_cooldown = std::chrono::hours{24},
                        .max_cooldown = norr::Duration::max()}};
  const norr::Instant now = norr::Instant{} + std::chrono::hours{1};
  for (int i = 0; i < 40; ++i) pool.blame(0, now);
  NORR_CHECK(pool.quarantined(0, now));
  NORR_CHECK(pool.quarantined(0, norr::Instant::max() - std::chrono::hours{1}));
  std::puts("spoof_pool: unbounded max_cooldown saturates, no time_point overflow OK");
}

void test_all_quarantined_still_picks() {
  norr::SpoofPool pool{{ip(1, 1, 1, 1), ip(2, 2, 2, 2)}, {.death_threshold = 1}};
  norr::Instant now{};
  pool.blame(0, now);
  pool.blame(1, now);
  NORR_CHECK(pool.healthy_count(now) == 0);
  const auto p = pool.pick(0x9, now);
  NORR_CHECK(p.has_value());
  std::puts("spoof_pool: all quarantined still returns least-cooling source OK");
}

void test_out_of_range_index_noop() {
  norr::SpoofPool pool{{ip(1, 1, 1, 1)}};
  const norr::Instant now{};
  pool.blame(99, now);
  pool.reward(99);
  NORR_CHECK(pool.quarantined(99, now));
  NORR_CHECK(pool.sent(99) == 0);
  NORR_CHECK(pool.source(99) == 0);
  NORR_CHECK(!pool.quarantined(0, now));
  std::puts("spoof_pool: out-of-range index is a safe no-op OK");
}

void test_randomized_invariants() {
  std::vector<std::uint32_t> src;
  for (std::uint32_t i = 1; i <= 16; ++i) src.push_back(ip(10, 0, 0, static_cast<std::uint8_t>(i)));
  norr::SpoofPool pool{src, {.death_threshold = 3}};
  std::uint64_t state = 0x243F6A8885A308D3ULL;
  auto rng = [&state]() {
    state ^= state << 13U;
    state ^= state >> 7U;
    state ^= state << 17U;
    return state;
  };
  norr::Instant now{};
  for (int step = 0; step < 50000; ++step) {
    now += std::chrono::milliseconds{static_cast<int>(rng() % 1000)};
    const auto p = pool.pick(rng(), now);
    NORR_CHECK(p.has_value());
    NORR_CHECK(p->index < pool.size());
    NORR_CHECK(p->source_be == pool.source(p->index));
    NORR_CHECK(!pool.quarantined(p->index, now) || pool.healthy_count(now) == 0);
    if (rng() % 3 == 0) {
      pool.blame(p->index, now);
    } else {
      pool.reward(p->index);
    }
    NORR_CHECK(pool.healthy_count(now) <= pool.size());
  }
  std::puts("spoof_pool: 50k randomized ops hold all invariants OK");
}

void test_sent_counter() {
  norr::SpoofPool pool{{ip(7, 7, 7, 7)}};
  const norr::Instant now{};
  NORR_CHECK(pool.pick(1, now).has_value());
  NORR_CHECK(pool.pick(2, now).has_value());
  NORR_CHECK(pool.sent(0) == 2);
  std::puts("spoof_pool: sent counter increments OK");
}
}

int main() {
  test_empty_pool();
  test_dedup_and_drop_zero();
  test_flow_stable();
  test_flow_spread();
  test_quarantine_and_failover();
  test_exponential_backoff();
  test_reward_decays_one_step();
  test_blame_never_overflows_time_point();
  test_all_quarantined_still_picks();
  test_out_of_range_index_noop();
  test_randomized_invariants();
  test_sent_counter();
  std::puts("spoof_pool: all tests passed");
  return 0;
}
