#include "norr/replay_window.hpp"

namespace norr {
namespace {
[[nodiscard]] constexpr std::size_t word_of(std::uint64_t counter) noexcept {
  return static_cast<std::size_t>((counter / 64U) % (ReplayWindow::kWindowSize / 64U));
}

[[nodiscard]] constexpr std::uint64_t bit_of(std::uint64_t counter) noexcept {
  return UINT64_C(1) << (counter % 64U);
}

}

bool ReplayWindow::test(std::uint64_t counter) const noexcept {
  return (seen_[word_of(counter)] & bit_of(counter)) != 0U;
}

void ReplayWindow::set(std::uint64_t counter) noexcept {
  seen_[word_of(counter)] |= bit_of(counter);
}

void ReplayWindow::clear_range(std::uint64_t first, std::uint64_t last) noexcept {
  if (last - first + 1 >= kWindowSize) {
    seen_.fill(0);
    return;
  }
  for (std::uint64_t counter = first; counter <= last; ++counter) {
    seen_[word_of(counter)] &= ~bit_of(counter);
    if (counter == last) break;
  }
}

ReplayResult ReplayWindow::accept(std::uint64_t counter) noexcept {
  if (!initialized_) {
    initialized_ = true;
    highest_ = counter;
    set(counter);
    return ReplayResult::accepted;
  }

  if (counter > highest_) {
    clear_range(highest_ + 1, counter);
    highest_ = counter;
    set(counter);
    return ReplayResult::accepted;
  }

  if (highest_ - counter >= kWindowSize) return ReplayResult::too_old;
  if (test(counter)) return ReplayResult::replayed;
  set(counter);
  return ReplayResult::accepted;
}

}
