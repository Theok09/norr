// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#include "norr/spoof_pool.hpp"

#include <algorithm>

namespace norr {
namespace {
[[nodiscard]] constexpr std::uint64_t mix64(std::uint64_t value) noexcept {
  value += 0x9E3779B97F4A7C15ULL;
  value = (value ^ (value >> 30U)) * 0xBF58476D1CE4E5B9ULL;
  value = (value ^ (value >> 27U)) * 0x94D049BB133111EBULL;
  return value ^ (value >> 31U);
}

[[nodiscard]] constexpr std::uint64_t score(std::uint64_t flow_hash, std::uint32_t ip_be) noexcept {
  return mix64(flow_hash ^ mix64(static_cast<std::uint64_t>(ip_be)));
}
}

SpoofPool::SpoofPool(const std::vector<std::uint32_t>& sources_be, SpoofPoolConfig config)
    : config_(config) {
  if (config_.death_threshold == 0) config_.death_threshold = 1;
  if (config_.max_cooldown < config_.initial_cooldown) {
    config_.max_cooldown = config_.initial_cooldown;
  }

  entries_.reserve(sources_be.size());
  for (const auto ip : sources_be) {
    if (ip == 0) continue;
    const auto duplicate =
        std::ranges::any_of(entries_, [ip](const Entry& entry) { return entry.ip_be == ip; });
    if (duplicate) continue;
    entries_.push_back(Entry{.ip_be = ip});
  }
}

Duration SpoofPool::cooldown_for(std::uint32_t level) const noexcept {
  auto cooldown = config_.initial_cooldown;
  const auto cap = config_.max_cooldown;
  for (std::uint32_t step = 0; step < level; ++step) {
    if (cooldown >= cap - cooldown) return cap;
    cooldown *= 2;
    if (cooldown >= cap) return cap;
  }
  return cooldown;
}

bool SpoofPool::quarantined(std::size_t index, Instant now) const noexcept {
  if (index >= entries_.size()) return true;
  return now < entries_[index].cooldown_until;
}

std::optional<SpoofPick> SpoofPool::pick(std::uint64_t flow_hash, Instant now) noexcept {
  if (entries_.empty()) return std::nullopt;

  std::size_t healthy_best = entries_.size();
  std::uint64_t healthy_score = 0;
  std::size_t soonest = 0;
  Instant soonest_until = entries_[0].cooldown_until;

  for (std::size_t index = 0; index < entries_.size(); ++index) {
    const auto& entry = entries_[index];
    if (entry.cooldown_until < soonest_until) {
      soonest_until = entry.cooldown_until;
      soonest = index;
    }
    if (now < entry.cooldown_until) continue;
    const auto candidate = score(flow_hash, entry.ip_be);
    if (healthy_best == entries_.size() || candidate > healthy_score) {
      healthy_best = index;
      healthy_score = candidate;
    }
  }

  const auto chosen = healthy_best != entries_.size() ? healthy_best : soonest;
  auto& entry = entries_[chosen];
  ++entry.sent;
  return SpoofPick{.index = chosen, .source_be = entry.ip_be};
}

void SpoofPool::blame(std::size_t index, Instant now) noexcept {
  if (index >= entries_.size()) return;
  auto& entry = entries_[index];
  ++entry.death_streak;
  if (entry.death_streak < config_.death_threshold) return;

  entry.death_streak = 0;
  const auto cooldown = cooldown_for(entry.cooldown_level);
  const auto headroom = Instant::max() - now;
  entry.cooldown_until = cooldown >= headroom ? Instant::max() : now + cooldown;
  if (entry.cooldown_level < 30) ++entry.cooldown_level;
}

void SpoofPool::reward(std::size_t index) noexcept {
  if (index >= entries_.size()) return;
  auto& entry = entries_[index];
  entry.death_streak = 0;
  if (entry.cooldown_level > 0) --entry.cooldown_level;
}

std::size_t SpoofPool::healthy_count(Instant now) const noexcept {
  return static_cast<std::size_t>(std::ranges::count_if(
      entries_, [now](const Entry& entry) { return now >= entry.cooldown_until; }));
}

std::uint64_t SpoofPool::sent(std::size_t index) const noexcept {
  return index < entries_.size() ? entries_[index].sent : 0;
}

std::uint32_t SpoofPool::source(std::size_t index) const noexcept {
  return index < entries_.size() ? entries_[index].ip_be : 0;
}
}
