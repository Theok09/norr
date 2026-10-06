// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#pragma once

#include <cstdint>
#include <string_view>

namespace norr {
enum class TuningProfile : std::uint8_t { off, balanced, throughput, saver };

[[nodiscard]] constexpr std::string_view tuning_profile_name(TuningProfile profile) noexcept {
  switch (profile) {
    case TuningProfile::balanced: return "balanced";
    case TuningProfile::throughput: return "throughput";
    case TuningProfile::saver: return "saver";
    case TuningProfile::off: break;
  }
  return "off";
}

[[nodiscard]] constexpr TuningProfile parse_tuning_profile(std::string_view text) noexcept {
  if (text == "balanced") return TuningProfile::balanced;
  if (text == "throughput") return TuningProfile::throughput;
  if (text == "saver") return TuningProfile::saver;
  return TuningProfile::off;
}

struct TuningReport {
  std::uint32_t applied{};
  std::uint32_t skipped{};
};

TuningReport apply_kernel_tuning(TuningProfile profile) noexcept;
}
