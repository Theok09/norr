// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "norr/spoof_pool.hpp"

namespace norr {
struct SpoofFeedbackConfig {
  std::uint32_t miss_windows{3};
  Duration reroll_interval{std::chrono::seconds{0}};
};

class SpoofFeedback {
 public:
  SpoofFeedback() = default;
  explicit SpoofFeedback(SpoofPool pool, SpoofFeedbackConfig config = {});

  [[nodiscard]] std::size_t size() const noexcept { return pool_.size(); }
  [[nodiscard]] bool empty() const noexcept { return pool_.empty(); }

  [[nodiscard]] std::optional<SpoofPick> pick(std::uint64_t flow_hash, Instant now) noexcept;

  void apply_receipt(std::span<const std::uint64_t> confirmed_bitmap, Instant now) noexcept;

  void apply_source_receipt(std::span<const std::byte> frame, Instant now);

  [[nodiscard]] std::size_t healthy_count(Instant now) const noexcept {
    return pool_.healthy_count(now);
  }

  [[nodiscard]] std::uint32_t miss_streak(std::size_t index) const noexcept;

  [[nodiscard]] const SpoofPool& pool() const noexcept { return pool_; }

 private:
  struct Window {
    std::uint64_t sent_at_window{};
    std::uint32_t miss_streak{};
  };

  [[nodiscard]] std::uint64_t epoch_salt(Instant now) const noexcept;

  SpoofPool pool_;
  SpoofFeedbackConfig config_{};
  std::vector<Window> windows_;
  std::uint64_t window_counter_{};
};

[[nodiscard]] std::vector<std::uint64_t> make_receipt_bitmap(std::span<const std::size_t> received,
                                                             std::size_t pool_size);

[[nodiscard]] bool receipt_bit(std::span<const std::uint64_t> bitmap, std::size_t index) noexcept;

[[nodiscard]] std::vector<std::byte> encode_spoof_receipt(std::span<const std::uint64_t> bitmap);

[[nodiscard]] std::vector<std::uint64_t> decode_spoof_receipt(std::span<const std::byte> payload);

class SpoofReceiptTracker {
 public:
  void observe(std::uint32_t source_be) noexcept;

  [[nodiscard]] std::vector<std::byte> drain_receipt() noexcept;

  [[nodiscard]] std::size_t pending() const noexcept { return seen_.size(); }

 private:
  std::vector<std::uint32_t> seen_;
};

[[nodiscard]] std::vector<std::byte> encode_source_receipt(std::span<const std::uint32_t> sources_be);

[[nodiscard]] std::vector<std::uint32_t> decode_source_receipt(std::span<const std::byte> payload);

[[nodiscard]] std::vector<std::uint64_t> receipt_bitmap_for_pool(
    std::span<const std::uint32_t> sources_be, const SpoofPool& pool);
}
