// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#pragma once

#include <cstddef>
#include <utility>
#include <vector>

#include "norr/address.hpp"

namespace norr {
class SpoofPool {
 public:
  SpoofPool() = default;
  explicit SpoofPool(std::vector<Address> sources) noexcept : sources_(std::move(sources)) {}

  [[nodiscard]] bool enabled() const noexcept { return !sources_.empty(); }
  [[nodiscard]] std::size_t size() const noexcept { return sources_.size(); }

  [[nodiscard]] const Address& next() noexcept {
    const auto& picked = sources_[cursor_ % sources_.size()];
    ++cursor_;
    return picked;
  }

 private:
  std::vector<Address> sources_;
  std::size_t cursor_{};
};
}
