#include "norr/timers.hpp"

#include <algorithm>

namespace norr {
namespace {
constexpr auto later_first = [](const TimerEvent& left, const TimerEvent& right) noexcept {
  return left.due > right.due;
};

}

Duration retry_backoff(std::uint32_t attempt) noexcept {
  auto delay = kHandshakeRetryBase;

  for (std::uint32_t step = 0; step < attempt && delay < kHandshakeRetryMax; ++step) {
    delay *= 2;
  }
  return std::min<Duration>(delay, kHandshakeRetryMax);
}

bool TimerWheel::schedule(TimerKind kind, std::uint32_t subject, Instant due) {
  if (timers_.size() >= kMaximumTimers) return false;
  timers_.push_back(TimerEvent{.kind = kind, .subject = subject, .due = due});
  std::push_heap(timers_.begin(), timers_.end(), later_first);
  return true;
}

std::size_t TimerWheel::cancel(TimerKind kind, std::uint32_t subject) {
  const auto removed = std::erase_if(timers_, [&](const TimerEvent& event) {
    return event.kind == kind && event.subject == subject;
  });
  if (removed > 0) std::make_heap(timers_.begin(), timers_.end(), later_first);
  return removed;
}

std::size_t TimerWheel::cancel_subject(std::uint32_t subject) {
  const auto removed = std::erase_if(
      timers_, [&](const TimerEvent& event) { return event.subject == subject; });
  if (removed > 0) std::make_heap(timers_.begin(), timers_.end(), later_first);
  return removed;
}

std::vector<TimerEvent> TimerWheel::expire(Instant now) {
  std::vector<TimerEvent> due;
  while (!timers_.empty() && timers_.front().due <= now) {
    std::pop_heap(timers_.begin(), timers_.end(), later_first);
    due.push_back(timers_.back());
    timers_.pop_back();
  }
  return due;
}

Instant TimerWheel::next_due() const noexcept {
  return timers_.empty() ? Instant{} : timers_.front().due;
}

}
