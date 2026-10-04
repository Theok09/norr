// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#include "norr/spoof_envelope.hpp"

#include <algorithm>

namespace norr {
namespace {
constexpr std::uint32_t kSurvivorThreshold = 2;

[[nodiscard]] constexpr std::uint64_t next_random(std::uint64_t& state) noexcept {
  state ^= state << 13U;
  state ^= state >> 7U;
  state ^= state << 17U;
  return state;
}

[[nodiscard]] constexpr bool reserved_host(std::uint32_t host, std::uint32_t mask) noexcept {
  return host == 0 || host == mask;
}

void fill_prefix(std::vector<SpoofCandidate>& out, std::uint32_t network, std::uint32_t host_mask,
                 SpoofClass cls, std::uint32_t count, std::uint64_t& state) {
  for (std::uint32_t added = 0, tries = 0; added < count && tries < count * 16; ++tries) {
    const auto host = static_cast<std::uint32_t>(next_random(state)) & host_mask;
    if (reserved_host(host, host_mask)) continue;
    const auto ip = network | host;
    const auto duplicate = std::ranges::any_of(
        out, [ip](const SpoofCandidate& candidate) { return candidate.ip_be == ip; });
    if (duplicate) continue;
    out.push_back(SpoofCandidate{.ip_be = ip, .cls = cls});
    ++added;
  }
}
}

std::string_view spoof_class_name(SpoofClass cls) noexcept {
  switch (cls) {
    case SpoofClass::same_host_24: return "same-/24";
    case SpoofClass::same_host_16: return "same-/16";
    case SpoofClass::same_isp_block: return "isp-block";
    case SpoofClass::neighbor_random: return "neighbor";
    case SpoofClass::foreign_random: return "foreign";
  }
  return "unknown";
}

std::vector<SpoofCandidate> build_spoof_candidates(std::uint32_t real_ip_be,
                                                   SpoofEnvelopeConfig config) {
  return build_spoof_candidates(real_ip_be, {}, config);
}

std::vector<SpoofCandidate> build_spoof_candidates(std::uint32_t real_ip_be,
                                                   const std::vector<std::uint32_t>& isp_blocks_be,
                                                   SpoofEnvelopeConfig config) {
  std::vector<SpoofCandidate> out;
  if (config.per_class == 0) return out;
  std::uint64_t state = config.seed ^ real_ip_be;

  fill_prefix(out, real_ip_be & 0xFFFFFF00U, 0x000000FFU, SpoofClass::same_host_24, config.per_class,
              state);
  fill_prefix(out, real_ip_be & 0xFFFF0000U, 0x0000FFFFU, SpoofClass::same_host_16, config.per_class,
              state);

  for (const auto block : isp_blocks_be) {
    fill_prefix(out, block & 0xFFFFFF00U, 0x000000FFU, SpoofClass::same_isp_block, config.per_class,
                state);
  }

  fill_prefix(out, (real_ip_be & 0xFFFF0000U) ^ 0x00010000U, 0x0000FFFFU,
              SpoofClass::neighbor_random, config.per_class, state);

  for (std::uint32_t added = 0, tries = 0; added < config.per_class && tries < config.per_class * 16;
       ++tries) {
    const auto ip = static_cast<std::uint32_t>(next_random(state));
    const auto octet = (ip >> 24U) & 0xFFU;
    if (octet == 0 || octet == 10 || octet == 127 || octet >= 224) continue;
    if (octet == 172 && ((ip >> 16U) & 0xF0U) == 0x10U) continue;
    if (octet == 192 && ((ip >> 16U) & 0xFFU) == 168) continue;
    if ((ip & 0xFFFFFF00U) == (real_ip_be & 0xFFFFFF00U)) continue;
    out.push_back(SpoofCandidate{.ip_be = ip, .cls = SpoofClass::foreign_random});
    ++added;
  }

  return out;
}

std::size_t SpoofClassTally::slot(SpoofClass cls) noexcept {
  return static_cast<std::size_t>(cls);
}

void SpoofClassTally::record_survivor(SpoofClass cls) noexcept { ++survivors_[slot(cls)]; }

void SpoofClassTally::record_sent(SpoofClass cls) noexcept { ++sent_[slot(cls)]; }

std::uint32_t SpoofClassTally::survivors(SpoofClass cls) const noexcept {
  return survivors_[slot(cls)];
}

std::uint32_t SpoofClassTally::sent(SpoofClass cls) const noexcept { return sent_[slot(cls)]; }

bool SpoofClassTally::class_usable(SpoofClass cls) const noexcept {
  return survivors_[slot(cls)] >= kSurvivorThreshold;
}

std::vector<SpoofClass> SpoofClassTally::usable_classes() const noexcept {
  std::vector<SpoofClass> out;
  for (std::uint8_t value = 0; value < 5; ++value) {
    const auto cls = static_cast<SpoofClass>(value);
    if (class_usable(cls)) out.push_back(cls);
  }
  return out;
}
}
