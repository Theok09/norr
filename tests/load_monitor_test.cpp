// The load signal that turns the cookie challenge on.
//
// Time is supplied explicitly so these tests are deterministic and never sleep.

#include "check.hpp"
#include <chrono>
#include <cstdio>

#include "norr/load_monitor.hpp"

namespace {

norr::LoadSample quiet() {
  return norr::LoadSample{.handshakes_received = 0,
                          .handshakes_completed = 0,
                          .queue_depth = 0,
                          .queue_capacity = 1024,
                          .pending_handshakes = 0,
                          .pending_capacity = 256};
}

void test_starts_normal() {
  norr::LoadMonitor monitor;
  NORR_CHECK(monitor.state() == norr::LoadState::normal);
  NORR_CHECK(!monitor.under_load());

  // The first observation only establishes a baseline: a rate needs two points,
  // and a node must not demand cookies the instant it starts.
  const auto now = norr::Instant{};
  monitor.observe(quiet(), now);
  NORR_CHECK(!monitor.under_load());

  std::puts("load: starts normal OK");
}

void test_quiet_traffic_never_engages() {
  norr::LoadMonitor monitor;
  auto now = norr::Instant{};
  auto sample = quiet();

  // A handful of handshakes per second from real peers, all completing.
  for (int tick = 0; tick < 20; ++tick) {
    sample.handshakes_received += 2;
    sample.handshakes_completed += 2;
    sample.pending_handshakes = 1;
    now += std::chrono::seconds{1};
    monitor.observe(sample, now);
    NORR_CHECK(!monitor.under_load());
  }

  std::puts("load: legitimate traffic never engages cookies OK");
}

void test_handshake_flood_engages() {
  norr::LoadMonitor monitor;
  auto now = norr::Instant{};
  auto sample = quiet();

  // A flood: many initiations, almost none completing.
  for (int tick = 0; tick < 10; ++tick) {
    sample.handshakes_received += 500;
    sample.handshakes_completed += 1;
    now += std::chrono::seconds{1};
    monitor.observe(sample, now);
  }

  NORR_CHECK(monitor.under_load());
  NORR_CHECK(monitor.state() == norr::LoadState::overloaded);
  NORR_CHECK(monitor.handshakes_per_second() > 100.0);

  std::puts("load: handshake flood engages cookies OK");
}

void test_pending_state_pressure_engages() {
  norr::LoadMonitor monitor;
  auto now = norr::Instant{};
  auto sample = quiet();

  // Even at a modest rate, pre-auth state filling up is itself the attack:
  // that is exactly the resource limits/anti-dos.md protects.
  for (int tick = 0; tick < 10; ++tick) {
    sample.handshakes_received += 5;
    sample.handshakes_completed += 5;
    sample.pending_handshakes = 200;  // of 256
    now += std::chrono::seconds{1};
    monitor.observe(sample, now);
  }

  NORR_CHECK(monitor.under_load());
  NORR_CHECK(monitor.pending_fraction() > 0.5);

  std::puts("load: pre-auth state pressure engages cookies OK");
}

void test_queue_pressure_engages() {
  norr::LoadMonitor monitor;
  auto now = norr::Instant{};
  auto sample = quiet();

  for (int tick = 0; tick < 10; ++tick) {
    sample.handshakes_received += 1;
    sample.handshakes_completed += 1;
    sample.queue_depth = 900;  // of 1024
    now += std::chrono::seconds{1};
    monitor.observe(sample, now);
  }

  NORR_CHECK(monitor.under_load());

  std::puts("load: queue pressure engages cookies OK");
}

void test_hysteresis() {
  norr::LoadMonitor monitor;
  auto now = norr::Instant{};
  auto sample = quiet();

  // Drive it into overload.
  for (int tick = 0; tick < 10; ++tick) {
    sample.handshakes_received += 500;
    sample.handshakes_completed += 1;
    now += std::chrono::seconds{1};
    monitor.observe(sample, now);
  }
  NORR_CHECK(monitor.under_load());
  const auto transitions_after_rise = monitor.transitions();

  // Traffic drops to a middling level: between the two thresholds the state
  // must hold rather than flapping, because each flip costs peers a round trip.
  for (int tick = 0; tick < 3; ++tick) {
    sample.handshakes_received += 35;
    sample.handshakes_completed += 30;
    now += std::chrono::seconds{1};
    monitor.observe(sample, now);
  }
  NORR_CHECK(monitor.transitions() == transitions_after_rise);

  // Sustained quiet finally clears it.
  for (int tick = 0; tick < 25; ++tick) {
    sample.handshakes_received += 1;
    sample.handshakes_completed += 1;
    now += std::chrono::seconds{1};
    monitor.observe(sample, now);
  }
  NORR_CHECK(!monitor.under_load());
  NORR_CHECK(monitor.transitions() > transitions_after_rise);

  std::puts("load: hysteresis prevents flapping OK");
}

void test_clock_not_advancing() {
  norr::LoadMonitor monitor;
  const auto now = norr::Instant{};
  auto sample = quiet();

  monitor.observe(sample, now);
  // A repeated timestamp must not divide by zero or produce a spurious rate.
  for (int tick = 0; tick < 5; ++tick) {
    sample.handshakes_received += 100;
    monitor.observe(sample, now);
  }
  NORR_CHECK(monitor.handshakes_per_second() >= 0.0);

  // A clock going backwards must not produce a negative rate either.
  monitor.observe(sample, now - std::chrono::seconds{10});
  NORR_CHECK(monitor.handshakes_per_second() >= 0.0);

  std::puts("load: degenerate clocks handled OK");
}

void test_zero_capacity() {
  norr::LoadMonitor monitor;
  auto now = norr::Instant{};
  norr::LoadSample sample{};
  sample.queue_capacity = 0;
  sample.pending_capacity = 0;

  // An unconfigured capacity must not divide by zero or read as fully loaded.
  monitor.observe(sample, now);
  now += std::chrono::seconds{1};
  monitor.observe(sample, now);
  NORR_CHECK(!monitor.under_load());

  std::puts("load: zero capacity handled OK");
}

}  // namespace

int main() {
  test_starts_normal();
  test_quiet_traffic_never_engages();
  test_handshake_flood_engages();
  test_pending_state_pressure_engages();
  test_queue_pressure_engages();
  test_hysteresis();
  test_clock_not_advancing();
  test_zero_capacity();
  return 0;
}
