#include "norr/io_backend.hpp"

#include <charconv>

#if defined(__linux__)
#include <sys/utsname.h>
#include <unistd.h>
#endif

namespace norr {
std::string kernel_release() {
#if defined(__linux__)
  utsname info{};
  if (uname(&info) != 0) return {};
  return info.release;
#else
  return {};
#endif
}

std::uint32_t kernel_version_code(std::string_view release) noexcept {
  std::uint32_t parts[3]{};
  std::size_t index = 0;
  std::size_t offset = 0;

  while (index < 3 && offset < release.size()) {
    const auto begin = release.data() + offset;
    const auto* end = release.data() + release.size();

    std::uint32_t value{};
    const auto result = std::from_chars(begin, end, value);

    if (result.ec != std::errc{}) return 0;

    parts[index++] = value;
    offset = static_cast<std::size_t>(result.ptr - release.data());
    if (offset < release.size() && (release[offset] == '.' || release[offset] == '-')) {
      ++offset;
    } else {
      break;
    }
  }

  return kernel_version(parts[0], parts[1], parts[2]);
}

std::vector<BackendReport> probe_io_backends() {
  std::vector<BackendReport> reports;

  reports.push_back(BackendReport{.backend = IoBackend::batched_syscalls,
                                  .status = BackendStatus::available,
                                  .detail = "recvmmsg/sendmmsg, the measured baseline"});

#if !defined(__linux__)
  for (const auto backend : {IoBackend::io_uring, IoBackend::af_xdp, IoBackend::dpdk}) {
    reports.push_back(BackendReport{
        .backend = backend, .status = BackendStatus::not_compiled_in, .detail = "Linux only"});
  }
  return reports;
#else
  const auto release = kernel_release();
  const auto version = kernel_version_code(release);

  reports.push_back(BackendReport{
      .backend = IoBackend::io_uring,
      .status = version >= kernel_version(5, 19, 0) ? BackendStatus::not_compiled_in
                                                    : BackendStatus::kernel_too_old,
      .detail = version >= kernel_version(5, 19, 0)
                    ? "kernel supports it; no backend written, and none justified yet"
                    : "needs 5.19 or newer for the networking path"});

  const auto privileged = ::geteuid() == 0;
  reports.push_back(BackendReport{
      .backend = IoBackend::af_xdp,
      .status = !privileged ? BackendStatus::insufficient_privilege
                            : BackendStatus::hardware_unsupported,
      .detail = !privileged ? "needs CAP_NET_ADMIN"
                            : "needs a NIC driver with zero-copy XDP support"});

  reports.push_back(BackendReport{.backend = IoBackend::dpdk,
                                  .status = BackendStatus::not_compiled_in,
                                  .detail = "deliberately not a default; needs a bound NIC"});

  return reports;
#endif
}

}
