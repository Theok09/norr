// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include "norr/rate_limit.hpp"

namespace norr {
struct SpoofPoolConfig {
  std::uint32_t death_threshold{4};
  Duration initial_cooldown{std::chrono::seconds{30}};
  Duration max_cooldown{std::chrono::minutes{5}};
};

struct SpoofPick {
  std::size_t index{};
  std::uint32_t source_be{};
};

class SpoofPool {
 public:
  SpoofPool() = default;
  explicit SpoofPool(const std::vector<std::uint32_t>& sources_be, SpoofPoolConfig config = {});

  [[nodiscard]] std::size_t size() const noexcept { return entries_.size(); }
  [[nodiscard]] bool empty() const noexcept { return entries_.empty(); }

  [[nodiscard]] std::optional<SpoofPick> pick(std::uint64_t flow_hash, Instant now) noexcept;

  void blame(std::size_t index, Instant now) noexcept;

  void reward(std::size_t index) noexcept;

  [[nodiscard]] bool quarantined(std::size_t index, Instant now) const noexcept;

  [[nodiscard]] std::size_t healthy_count(Instant now) const noexcept;

  [[nodiscard]] std::uint64_t sent(std::size_t index) const noexcept;

  [[nodiscard]] std::uint32_t source(std::size_t index) const noexcept;

 private:
  struct Entry {
    std::uint32_t ip_be{};
    std::uint32_t death_streak{};
    std::uint32_t cooldown_level{};
    Instant cooldown_until{};
    std::uint64_t sent{};
  };

  [[nodiscard]] Duration cooldown_for(std::uint32_t level) const noexcept;

  std::vector<Entry> entries_;
  SpoofPoolConfig config_{};
};
}
