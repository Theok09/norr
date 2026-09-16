// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace norr {
enum class IoBackend : std::uint8_t {
  batched_syscalls,
  io_uring,
  af_xdp,
  dpdk,
};

[[nodiscard]] constexpr std::string_view io_backend_name(IoBackend backend) noexcept {
  switch (backend) {
    case IoBackend::batched_syscalls: return "batched-syscalls";
    case IoBackend::io_uring: return "io_uring";
    case IoBackend::af_xdp: return "af_xdp";
    case IoBackend::dpdk: return "dpdk";
  }
  return "unknown";
}

enum class BackendStatus : std::uint8_t {
  available,
  kernel_too_old,
  not_compiled_in,
  insufficient_privilege,
  hardware_unsupported,
};

[[nodiscard]] constexpr std::string_view backend_status_name(BackendStatus status) noexcept {
  switch (status) {
    case BackendStatus::available: return "available";
    case BackendStatus::kernel_too_old: return "kernel too old";
    case BackendStatus::not_compiled_in: return "not compiled in";
    case BackendStatus::insufficient_privilege: return "insufficient privilege";
    case BackendStatus::hardware_unsupported: return "hardware unsupported";
  }
  return "unknown";
}

struct BackendReport {
  IoBackend backend{};
  BackendStatus status{};
  std::string detail;
};

[[nodiscard]] std::vector<BackendReport> probe_io_backends();

[[nodiscard]] std::string kernel_release();

[[nodiscard]] std::uint32_t kernel_version_code(std::string_view release) noexcept;

[[nodiscard]] constexpr std::uint32_t kernel_version(std::uint32_t major, std::uint32_t minor,
                                                     std::uint32_t patch) noexcept {
  return (major << 16U) | (minor << 8U) | patch;
}

[[nodiscard]] constexpr IoBackend active_io_backend() noexcept {
  return IoBackend::batched_syscalls;
}

}
