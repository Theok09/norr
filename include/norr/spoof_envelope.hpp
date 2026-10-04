// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

namespace norr {
enum class SpoofClass : std::uint8_t {
  same_host_24,
  same_host_16,
  same_isp_block,
  neighbor_random,
  foreign_random,
};

[[nodiscard]] std::string_view spoof_class_name(SpoofClass cls) noexcept;

struct SpoofCandidate {
  std::uint32_t ip_be{};
  SpoofClass cls{};
};

struct SpoofEnvelopeConfig {
  std::uint32_t per_class{8};
  std::uint64_t seed{0x9E3779B97F4A7C15ULL};
};

[[nodiscard]] std::vector<SpoofCandidate> build_spoof_candidates(std::uint32_t real_ip_be,
                                                                 SpoofEnvelopeConfig config = {});

[[nodiscard]] std::vector<SpoofCandidate> build_spoof_candidates(
    std::uint32_t real_ip_be, const std::vector<std::uint32_t>& isp_blocks_be,
    SpoofEnvelopeConfig config = {});

class SpoofClassTally {
 public:
  void record_survivor(SpoofClass cls) noexcept;
  void record_sent(SpoofClass cls) noexcept;

  [[nodiscard]] std::uint32_t survivors(SpoofClass cls) const noexcept;
  [[nodiscard]] std::uint32_t sent(SpoofClass cls) const noexcept;

  [[nodiscard]] bool class_usable(SpoofClass cls) const noexcept;

  [[nodiscard]] std::vector<SpoofClass> usable_classes() const noexcept;

 private:
  [[nodiscard]] static std::size_t slot(SpoofClass cls) noexcept;

  std::uint32_t survivors_[5]{};
  std::uint32_t sent_[5]{};
};
}
