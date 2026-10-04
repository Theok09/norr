// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#include "norr/spoof_feedback.hpp"

#include <utility>

namespace norr {
namespace {
[[nodiscard]] constexpr std::uint64_t mix64(std::uint64_t value) noexcept {
  value += 0x9E3779B97F4A7C15ULL;
  value = (value ^ (value >> 30U)) * 0xBF58476D1CE4E5B9ULL;
  value = (value ^ (value >> 27U)) * 0x94D049BB133111EBULL;
  return value ^ (value >> 31U);
}
}

SpoofFeedback::SpoofFeedback(SpoofPool pool, SpoofFeedbackConfig config)
    : pool_(std::move(pool)), config_(config), windows_(pool_.size()) {
  if (config_.miss_windows == 0) config_.miss_windows = 1;
}

std::uint64_t SpoofFeedback::epoch_salt(Instant now) const noexcept {
  if (config_.reroll_interval <= Duration::zero()) return 0;
  const auto since = now.time_since_epoch();
  const auto epoch = static_cast<std::uint64_t>(since / config_.reroll_interval);
  return mix64(epoch);
}

std::optional<SpoofPick> SpoofFeedback::pick(std::uint64_t flow_hash, Instant now) noexcept {
  const auto chosen = pool_.pick(flow_hash ^ epoch_salt(now), now);
  if (chosen) windows_[chosen->index].sent_at_window = window_counter_ + 1;
  return chosen;
}

void SpoofFeedback::apply_receipt(std::span<const std::uint64_t> confirmed_bitmap,
                                  Instant now) noexcept {
  ++window_counter_;
  for (std::size_t index = 0; index < windows_.size(); ++index) {
    auto& window = windows_[index];
    if (window.sent_at_window != window_counter_) continue;

    if (receipt_bit(confirmed_bitmap, index)) {
      pool_.reward(index);
      window.miss_streak = 0;
      continue;
    }

    ++window.miss_streak;
    if (window.miss_streak >= config_.miss_windows) {
      pool_.blame(index, now);
      window.miss_streak = 0;
    }
  }
}

std::uint32_t SpoofFeedback::miss_streak(std::size_t index) const noexcept {
  return index < windows_.size() ? windows_[index].miss_streak : 0;
}

std::vector<std::uint64_t> make_receipt_bitmap(std::span<const std::size_t> received,
                                               std::size_t pool_size) {
  std::vector<std::uint64_t> bitmap((pool_size + 63) / 64, 0);
  for (const auto index : received) {
    if (index >= pool_size) continue;
    bitmap[index / 64] |= (1ULL << (index % 64));
  }
  return bitmap;
}

bool receipt_bit(std::span<const std::uint64_t> bitmap, std::size_t index) noexcept {
  const auto word = index / 64;
  if (word >= bitmap.size()) return false;
  return ((bitmap[word] >> (index % 64)) & 1ULL) != 0;
}
}
