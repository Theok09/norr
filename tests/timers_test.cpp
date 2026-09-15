#include <algorithm>
#include "check.hpp"
#include <chrono>
#include <cstdio>

#include "norr/timers.hpp"

namespace {

void test_ordering() {
  norr::TimerWheel wheel;
  const norr::Instant base{};

  NORR_CHECK(wheel.empty());

  // Scheduled out of order; they must come back in due order.
  NORR_CHECK(wheel.schedule(norr::TimerKind::keepalive, 3, base + std::chrono::seconds{30}));
  NORR_CHECK(wheel.schedule(norr::TimerKind::handshake_timeout, 1, base + std::chrono::seconds{5}));
  NORR_CHECK(wheel.schedule(norr::TimerKind::rekey, 2, base + std::chrono::seconds{10}));
  NORR_CHECK(wheel.size() == 3);
  NORR_CHECK(wheel.next_due() == base + std::chrono::seconds{5});

  // Nothing is due yet.
  NORR_CHECK(wheel.expire(base).empty());
  NORR_CHECK(wheel.size() == 3);

  const auto first = wheel.expire(base + std::chrono::seconds{5});
  NORR_CHECK(first.size() == 1);
  NORR_CHECK(first[0].kind == norr::TimerKind::handshake_timeout);
  NORR_CHECK(first[0].subject == 1);

  // Expiring far ahead returns the rest, still in order.
  const auto rest = wheel.expire(base + std::chrono::minutes{1});
  NORR_CHECK(rest.size() == 2);
  NORR_CHECK(rest[0].due <= rest[1].due);
  NORR_CHECK(rest[0].kind == norr::TimerKind::rekey);
  NORR_CHECK(wheel.empty());

  std::puts("timers: due ordering OK");
}

void test_cancel() {
  norr::TimerWheel wheel;
  const norr::Instant base{};

  NORR_CHECK(wheel.schedule(norr::TimerKind::handshake_timeout, 7, base + std::chrono::seconds{5}));
  NORR_CHECK(wheel.schedule(norr::TimerKind::handshake_retry, 7, base + std::chrono::seconds{1}));
  NORR_CHECK(wheel.schedule(norr::TimerKind::keepalive, 8, base + std::chrono::seconds{2}));

  // Cancelling one kind for one subject leaves the others alone. This is what
  // a completing handshake does to its own timeout.
  NORR_CHECK(wheel.cancel(norr::TimerKind::handshake_retry, 7) == 1);
  NORR_CHECK(wheel.size() == 2);

  // The heap must still be valid after a removal from the middle.
  NORR_CHECK(wheel.next_due() == base + std::chrono::seconds{2});

  // Cancelling something absent is harmless.
  NORR_CHECK(wheel.cancel(norr::TimerKind::handshake_retry, 7) == 0);

  // Cancelling a whole subject removes every timer it owns, which is what a
  // peer going away does.
  NORR_CHECK(wheel.cancel_subject(7) == 1);
  NORR_CHECK(wheel.size() == 1);

  const auto remaining = wheel.expire(base + std::chrono::minutes{1});
  NORR_CHECK(remaining.size() == 1 && remaining[0].subject == 8);

  std::puts("timers: cancellation keeps the heap valid OK");
}

void test_capacity_is_bounded() {
  norr::TimerWheel wheel;
  const norr::Instant base{};

  // Timers are attacker-influenced state, since a handshake attempt schedules
  // one, so the wheel must refuse rather than grow without limit.
  for (std::size_t index = 0; index < norr::TimerWheel::kMaximumTimers; ++index) {
    NORR_CHECK(wheel.schedule(norr::TimerKind::handshake_timeout,
                          static_cast<std::uint32_t>(index), base + std::chrono::seconds{1}));
  }
  NORR_CHECK(wheel.size() == norr::TimerWheel::kMaximumTimers);
  NORR_CHECK(!wheel.schedule(norr::TimerKind::keepalive, 0, base + std::chrono::seconds{1}));

  std::puts("timers: capacity bounded OK");
}

void test_backoff() {
  // Exponential, and capped. An uncapped backoff would eventually schedule a
  // retry so far out that the peer is effectively abandoned silently.
  NORR_CHECK(norr::retry_backoff(0) == norr::kHandshakeRetryBase);
  NORR_CHECK(norr::retry_backoff(1) == norr::kHandshakeRetryBase * 2);
  NORR_CHECK(norr::retry_backoff(2) == norr::kHandshakeRetryBase * 4);
  NORR_CHECK(norr::retry_backoff(3) == norr::kHandshakeRetryBase * 8);

  // Each step is at least as long as the previous one.
  for (std::uint32_t attempt = 1; attempt < 40; ++attempt) {
    NORR_CHECK(norr::retry_backoff(attempt) >= norr::retry_backoff(attempt - 1));
  }

  // A very large attempt count must not overflow into a short or negative
  // delay; it clamps.
  NORR_CHECK(norr::retry_backoff(1000) == norr::kHandshakeRetryMax);
  NORR_CHECK(norr::retry_backoff(0xFFFFFFFFU) == norr::kHandshakeRetryMax);

  std::puts("timers: backoff grows and clamps OK");
}

void test_same_due_time() {
  norr::TimerWheel wheel;
  const norr::Instant base{};

  // Several timers due at the same instant must all come back together.
  for (std::uint32_t subject = 0; subject < 5; ++subject) {
    NORR_CHECK(wheel.schedule(norr::TimerKind::keepalive, subject, base + std::chrono::seconds{1}));
  }
  const auto due = wheel.expire(base + std::chrono::seconds{1});
  NORR_CHECK(due.size() == 5);
  NORR_CHECK(wheel.empty());

  std::puts("timers: simultaneous expiry OK");
}

}  // namespace

int main() {
  test_ordering();
  test_cancel();
  test_capacity_is_bounded();
  test_backoff();
  test_same_due_time();
  return 0;
}
