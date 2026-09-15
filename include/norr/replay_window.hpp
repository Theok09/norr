#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace norr {
enum class ReplayResult { accepted, replayed, too_old };

class ReplayWindow {
 public:
  static constexpr std::uint64_t kWindowSize = 8192;

  [[nodiscard]] ReplayResult accept(std::uint64_t counter) noexcept;

  [[nodiscard]] std::uint64_t highest_accepted() const noexcept { return highest_; }

 private:
  static constexpr std::size_t kWordBits = 64;
  static constexpr std::size_t kWordCount = kWindowSize / kWordBits;

  [[nodiscard]] bool test(std::uint64_t counter) const noexcept;
  void set(std::uint64_t counter) noexcept;
  void clear_range(std::uint64_t first, std::uint64_t last) noexcept;

  bool initialized_{};
  std::uint64_t highest_{};
  std::array<std::uint64_t, kWordCount> seen_{};
};

}
