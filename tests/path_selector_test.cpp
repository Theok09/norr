// Path selection and failover: gate G's mechanism.
//
// The property that matters is not that it switches, but that it does not
// switch when it should not. An oscillating tunnel is worse than a
// consistently mediocre one.

#include "check.hpp"
#include <chrono>
#include <cstdio>

#include "norr/path_selector.hpp"

namespace {

norr::PathSample good() {
  return norr::PathSample{.rtt_microseconds = 20'000, .loss_fraction = 0.0};
}

norr::PathSample bad() {
  return norr::PathSample{.rtt_microseconds = 400'000, .loss_fraction = 0.20};
}

norr::PathSample unreachable() {
  return norr::PathSample{.rtt_microseconds = 0, .loss_fraction = 1.0, .reachable = false};
}

void feed(norr::PathSelector& selector, norr::TransportKind kind, const norr::PathSample& sample,
          int times, norr::Instant now) {
  for (int index = 0; index < times; ++index) selector.observe(kind, sample);
}

void test_first_path_is_active() {
  norr::PathSelector selector;
  selector.add_path(norr::TransportKind::udp);
  selector.add_path(norr::TransportKind::tcp_tls);

  // UDP is the primary path; it is registered first and must stay active
  // until something justifies moving.
  NORR_CHECK(selector.active() == norr::TransportKind::udp);
  NORR_CHECK(selector.size() == 2);

  std::puts("path: first registered path is active OK");
}

void test_promotion_requires_a_window() {
  norr::PathSelector selector;
  selector.add_path(norr::TransportKind::udp);
  const auto now = norr::Instant{};

  const auto* path = selector.path(norr::TransportKind::udp);
  NORR_CHECK(path->state() == norr::PathState::probing);

  // One good sample is not enough: a new path must earn promotion.
  selector.observe(norr::TransportKind::udp, good());
  NORR_CHECK(selector.path(norr::TransportKind::udp)->state() == norr::PathState::probing);

  feed(selector, norr::TransportKind::udp, good(), 10, now);
  NORR_CHECK(selector.path(norr::TransportKind::udp)->state() == norr::PathState::healthy);

  std::puts("path: promotion needs a sustained window OK");
}

void test_one_bad_sample_is_not_a_failover() {
  norr::PathSelector selector;
  selector.add_path(norr::TransportKind::udp);
  selector.add_path(norr::TransportKind::tcp_tls);
  auto now = norr::Instant{};

  feed(selector, norr::TransportKind::udp, good(), 10, now);
  feed(selector, norr::TransportKind::tcp_tls, good(), 10, now);
  now += std::chrono::minutes{1};

  // A single bad sample must not move the traffic: probes get lost.
  selector.observe(norr::TransportKind::udp, bad());
  NORR_CHECK(!selector.evaluate(now));
  NORR_CHECK(selector.active() == norr::TransportKind::udp);

  std::puts("path: one bad sample does not trigger failover OK");
}

void test_sustained_failure_fails_over() {
  norr::PathSelector selector;
  selector.add_path(norr::TransportKind::udp);
  selector.add_path(norr::TransportKind::tcp_tls);
  auto now = norr::Instant{};

  feed(selector, norr::TransportKind::udp, good(), 10, now);
  feed(selector, norr::TransportKind::tcp_tls, good(), 10, now);
  now += std::chrono::minutes{1};

  // The primary goes away entirely.
  feed(selector, norr::TransportKind::udp, unreachable(), 5, now);
  feed(selector, norr::TransportKind::tcp_tls, good(), 5, now);

  NORR_CHECK(selector.evaluate(now));
  NORR_CHECK(selector.active() == norr::TransportKind::tcp_tls);
  NORR_CHECK(selector.stats().failovers == 1);

  std::puts("path: sustained failure fails over OK");
}

void test_cooldown_prevents_flapping() {
  norr::PathSelector selector;
  selector.add_path(norr::TransportKind::udp);
  selector.add_path(norr::TransportKind::tcp_tls);
  auto now = norr::Instant{};

  feed(selector, norr::TransportKind::udp, good(), 10, now);
  feed(selector, norr::TransportKind::tcp_tls, good(), 10, now);
  now += std::chrono::minutes{1};

  feed(selector, norr::TransportKind::udp, unreachable(), 5, now);
  NORR_CHECK(selector.evaluate(now));
  NORR_CHECK(selector.active() == norr::TransportKind::tcp_tls);

  // A failed path re-enters through `recovering` rather than jumping straight
  // to healthy, so a flapping link cannot win the traffic back on one good
  // sample. Partway through the promotion window it is still not a candidate.
  feed(selector, norr::TransportKind::udp, good(), 2, now);
  NORR_CHECK(selector.path(norr::TransportKind::udp)->state() == norr::PathState::recovering);
  NORR_CHECK(!selector.evaluate(now));
  NORR_CHECK(selector.active() == norr::TransportKind::tcp_tls);

  // Completing the window makes it usable again.
  feed(selector, norr::TransportKind::udp, good(), 5, now);
  feed(selector, norr::TransportKind::tcp_tls, bad(), 5, now);
  NORR_CHECK(selector.path(norr::TransportKind::udp)->state() == norr::PathState::healthy);
  now += std::chrono::seconds{1};

  // Even then, the cooldown still holds the switch off.
  NORR_CHECK(!selector.evaluate(now));
  NORR_CHECK(selector.active() == norr::TransportKind::tcp_tls);
  NORR_CHECK(selector.stats().switches_suppressed_by_cooldown > 0);

  // Once the cooldown has passed, the switch is allowed.
  now += std::chrono::seconds{30};
  NORR_CHECK(selector.evaluate(now));
  NORR_CHECK(selector.active() == norr::TransportKind::udp);

  std::puts("path: cooldown prevents flapping OK");
}

void test_margin_prevents_pointless_switches() {
  norr::PathSelector selector;
  selector.add_path(norr::TransportKind::udp);
  selector.add_path(norr::TransportKind::tcp_tls);
  auto now = norr::Instant{};

  // Both healthy, the alternate only marginally better.
  feed(selector, norr::TransportKind::udp,
       norr::PathSample{.rtt_microseconds = 21'000, .loss_fraction = 0.0}, 10, now);
  feed(selector, norr::TransportKind::tcp_tls,
       norr::PathSample{.rtt_microseconds = 20'000, .loss_fraction = 0.0}, 10, now);
  now += std::chrono::minutes{1};

  // A marginally better candidate is not worth the round trip and reordering
  // a switch costs.
  NORR_CHECK(!selector.evaluate(now));
  NORR_CHECK(selector.active() == norr::TransportKind::udp);
  NORR_CHECK(selector.stats().switches_suppressed_by_margin > 0);

  std::puts("path: marginal improvement does not justify a switch OK");
}

void test_failed_path_recovers_through_recovering() {
  norr::PathSelector selector;
  selector.add_path(norr::TransportKind::udp);
  const auto now = norr::Instant{};

  feed(selector, norr::TransportKind::udp, good(), 10, now);
  feed(selector, norr::TransportKind::udp, unreachable(), 3, now);
  NORR_CHECK(selector.path(norr::TransportKind::udp)->state() == norr::PathState::failed);

  // A failed path must not jump straight back to healthy on one good sample:
  // a flapping link would win back the traffic instantly.
  selector.observe(norr::TransportKind::udp, good());
  NORR_CHECK(selector.path(norr::TransportKind::udp)->state() == norr::PathState::recovering);

  feed(selector, norr::TransportKind::udp, good(), 10, now);
  NORR_CHECK(selector.path(norr::TransportKind::udp)->state() == norr::PathState::healthy);

  std::puts("path: failed path recovers through an intermediate state OK");
}

void test_no_alternate_means_no_switch() {
  norr::PathSelector selector;
  selector.add_path(norr::TransportKind::udp);
  auto now = norr::Instant{};

  feed(selector, norr::TransportKind::udp, unreachable(), 5, now);
  now += std::chrono::minutes{1};

  // With nowhere to go, the selector must not claim to have switched.
  NORR_CHECK(!selector.evaluate(now));
  NORR_CHECK(selector.active() == norr::TransportKind::udp);
  NORR_CHECK(selector.stats().switches == 0);

  std::puts("path: no alternate means no switch OK");
}

void test_duplicate_registration_ignored() {
  norr::PathSelector selector;
  selector.add_path(norr::TransportKind::udp);
  selector.add_path(norr::TransportKind::udp);
  NORR_CHECK(selector.size() == 1);

  std::puts("path: duplicate registration ignored OK");
}

}  // namespace

int main() {
  test_first_path_is_active();
  test_promotion_requires_a_window();
  test_one_bad_sample_is_not_a_failover();
  test_sustained_failure_fails_over();
  test_cooldown_prevents_flapping();
  test_margin_prevents_pointless_switches();
  test_failed_path_recovers_through_recovering();
  test_no_alternate_means_no_switch();
  test_duplicate_registration_ignored();
  return 0;
}
