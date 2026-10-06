// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#include "norr/tuning.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <span>
#include <string>

#include "norr/log.hpp"

namespace norr {
namespace {
struct Knob {
  std::string_view path;
  std::string_view value;
};

constexpr std::array<Knob, 12> kThroughput{{
    {"/proc/sys/net/core/rmem_max", "268435456"},
    {"/proc/sys/net/core/wmem_max", "67108864"},
    {"/proc/sys/net/core/rmem_default", "26214400"},
    {"/proc/sys/net/core/wmem_default", "26214400"},
    {"/proc/sys/net/core/netdev_max_backlog", "250000"},
    {"/proc/sys/net/core/default_qdisc", "fq"},
    {"/proc/sys/net/ipv4/tcp_rmem", "4096 87380 268435456"},
    {"/proc/sys/net/ipv4/tcp_wmem", "4096 65536 67108864"},
    {"/proc/sys/net/ipv4/tcp_congestion_control", "bbr"},
    {"/proc/sys/net/ipv4/tcp_mtu_probing", "1"},
    {"/proc/sys/net/ipv4/tcp_slow_start_after_idle", "0"},
    {"/proc/sys/net/ipv4/tcp_adv_win_scale", "-2"},
}};

constexpr std::array<Knob, 10> kBalanced{{
    {"/proc/sys/net/core/rmem_max", "134217728"},
    {"/proc/sys/net/core/wmem_max", "134217728"},
    {"/proc/sys/net/core/rmem_default", "16777216"},
    {"/proc/sys/net/core/wmem_default", "16777216"},
    {"/proc/sys/net/core/netdev_max_backlog", "100000"},
    {"/proc/sys/net/core/default_qdisc", "fq"},
    {"/proc/sys/net/ipv4/tcp_rmem", "4096 87380 134217728"},
    {"/proc/sys/net/ipv4/tcp_wmem", "4096 65536 134217728"},
    {"/proc/sys/net/ipv4/tcp_congestion_control", "bbr"},
    {"/proc/sys/net/ipv4/tcp_mtu_probing", "1"},
}};

constexpr std::array<Knob, 6> kSaver{{
    {"/proc/sys/net/core/rmem_max", "16777216"},
    {"/proc/sys/net/core/wmem_max", "16777216"},
    {"/proc/sys/net/core/default_qdisc", "fq"},
    {"/proc/sys/net/ipv4/tcp_rmem", "4096 87380 16777216"},
    {"/proc/sys/net/ipv4/tcp_wmem", "4096 65536 16777216"},
    {"/proc/sys/net/ipv4/tcp_congestion_control", "bbr"},
}};

[[nodiscard]] bool write_knob(const Knob& knob) noexcept {
  std::array<char, 256> path{};
  if (knob.path.size() + 1 > path.size()) return false;
  std::copy(knob.path.begin(), knob.path.end(), path.begin());
  path[knob.path.size()] = '\0';

  std::FILE* file = std::fopen(path.data(), "we");
  if (file == nullptr) return false;
  const auto written = std::fwrite(knob.value.data(), 1, knob.value.size(), file);
  const auto closed = std::fclose(file);
  return written == knob.value.size() && closed == 0;
}

[[nodiscard]] std::span<const Knob> knobs_for(TuningProfile profile) noexcept {
  switch (profile) {
    case TuningProfile::throughput: return std::span{kThroughput};
    case TuningProfile::balanced: return std::span{kBalanced};
    case TuningProfile::saver: return std::span{kSaver};
    case TuningProfile::off: break;
  }
  return std::span<const Knob>{};
}
}

TuningReport apply_kernel_tuning(TuningProfile profile) noexcept {
  TuningReport report{};
  const auto knobs = knobs_for(profile);
  if (knobs.empty()) return report;

  for (const auto& knob : knobs) {
    if (write_knob(knob)) {
      ++report.applied;
    } else {
      ++report.skipped;
    }
  }

  NORR_LOG_INFO("tuning %s: applied %u knobs, skipped %u",
                std::string{tuning_profile_name(profile)}.c_str(), report.applied,
                report.skipped);
  return report;
}
}
