#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>

#include "norr/error.hpp"

namespace norr {
using Nonce = std::array<std::byte, 12>;

[[nodiscard]] Nonce make_nonce(std::uint64_t counter) noexcept;

class PacketCounter {
 public:
  explicit PacketCounter(std::uint64_t initial = 0) noexcept : value_(initial) {}
  [[nodiscard]] std::expected<std::uint64_t, Error> next() noexcept;
  [[nodiscard]] bool exhausted() const noexcept { return exhausted_; }

 private:
  std::uint64_t value_{};
  bool exhausted_{};
};

}
