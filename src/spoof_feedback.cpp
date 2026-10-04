// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#include "norr/spoof_feedback.hpp"

#include <algorithm>
#include <ranges>
#include <utility>

#include "norr/packet.hpp"

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

void SpoofFeedback::apply_source_receipt(std::span<const std::byte> frame, Instant now) {
  const auto sources = decode_source_receipt(frame);
  apply_receipt(receipt_bitmap_for_pool(sources, pool_), now);
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

std::vector<std::byte> encode_spoof_receipt(std::span<const std::uint64_t> bitmap) {
  const auto words = std::min<std::size_t>(bitmap.size(), kSpoofReceiptMaxWords);
  std::vector<std::byte> out;
  out.reserve(1 + words * 8);
  out.push_back(kSpoofReceipt);
  for (std::size_t w = 0; w < words; ++w) {
    for (int shift = 56; shift >= 0; shift -= 8) {
      out.push_back(static_cast<std::byte>((bitmap[w] >> static_cast<unsigned>(shift)) & 0xFFU));
    }
  }
  return out;
}

std::vector<std::uint64_t> decode_spoof_receipt(std::span<const std::byte> payload) {
  std::vector<std::uint64_t> bitmap;
  if (payload.empty() || payload[0] != kSpoofReceipt) return bitmap;
  const auto body = payload.subspan(1);
  const auto words = std::min<std::size_t>(body.size() / 8, kSpoofReceiptMaxWords);
  bitmap.reserve(words);
  for (std::size_t w = 0; w < words; ++w) {
    std::uint64_t value = 0;
    for (std::size_t b = 0; b < 8; ++b) {
      value = (value << 8U) | static_cast<std::uint64_t>(body[w * 8 + b]);
    }
    bitmap.push_back(value);
  }
  return bitmap;
}

void SpoofReceiptTracker::observe(std::uint32_t source_be) noexcept {
  if (source_be == 0) return;
  if (seen_.size() >= kSpoofReceiptMaxWords * 64) return;
  if (std::ranges::find(seen_, source_be) != seen_.end()) return;
  seen_.push_back(source_be);
}

std::vector<std::byte> SpoofReceiptTracker::drain_receipt() noexcept {
  auto frame = encode_source_receipt(seen_);
  seen_.clear();
  return frame;
}

std::vector<std::byte> encode_source_receipt(std::span<const std::uint32_t> sources_be) {
  const auto count = std::min<std::size_t>(sources_be.size(), kSpoofReceiptMaxWords * 64);
  std::vector<std::byte> out;
  out.reserve(1 + count * 4);
  out.push_back(kSpoofReceipt);
  for (std::size_t i = 0; i < count; ++i) {
    for (int shift = 24; shift >= 0; shift -= 8) {
      out.push_back(static_cast<std::byte>((sources_be[i] >> static_cast<unsigned>(shift)) & 0xFFU));
    }
  }
  return out;
}

std::vector<std::uint32_t> decode_source_receipt(std::span<const std::byte> payload) {
  std::vector<std::uint32_t> sources;
  if (payload.empty() || payload[0] != kSpoofReceipt) return sources;
  const auto body = payload.subspan(1);
  const auto count = std::min<std::size_t>(body.size() / 4, kSpoofReceiptMaxWords * 64);
  sources.reserve(count);
  for (std::size_t i = 0; i < count; ++i) {
    std::uint32_t value = 0;
    for (std::size_t b = 0; b < 4; ++b) {
      value = (value << 8U) | static_cast<std::uint32_t>(body[i * 4 + b]);
    }
    sources.push_back(value);
  }
  return sources;
}

std::vector<std::uint64_t> receipt_bitmap_for_pool(std::span<const std::uint32_t> sources_be,
                                                   const SpoofPool& pool) {
  std::vector<std::size_t> indices;
  indices.reserve(sources_be.size());
  for (const auto ip : sources_be) {
    for (std::size_t index = 0; index < pool.size(); ++index) {
      if (pool.source(index) == ip) {
        indices.push_back(index);
        break;
      }
    }
  }
  return make_receipt_bitmap(indices, pool.size());
}
}
