// I/O backend detection.
//
// Phase 8 is an investigation, so what is tested is that the probe reports
// honestly: no backend may claim to be available when it is not.

#include "check.hpp"
#include <cstdio>

#include "norr/io_backend.hpp"

namespace {

void test_version_parsing() {
  NORR_CHECK(norr::kernel_version_code("6.8.0") == norr::kernel_version(6, 8, 0));
  NORR_CHECK(norr::kernel_version_code("5.19.2-generic") == norr::kernel_version(5, 19, 2));
  NORR_CHECK(norr::kernel_version_code("6.8.0-100-generic") == norr::kernel_version(6, 8, 0));

  // Ordering must hold, since every backend has a minimum version.
  NORR_CHECK(norr::kernel_version_code("6.0.0") > norr::kernel_version_code("5.19.0"));
  NORR_CHECK(norr::kernel_version_code("5.19.0") > norr::kernel_version_code("5.4.0"));

  // An unparseable release reads as zero, so a caller concludes "too old"
  // rather than "new enough".
  NORR_CHECK(norr::kernel_version_code("") == 0);
  NORR_CHECK(norr::kernel_version_code("unknown") == 0);
  NORR_CHECK(norr::kernel_version_code("") < norr::kernel_version(5, 19, 0));

  std::puts("io_backend: kernel version parsing OK");
}

void test_probe_is_honest() {
  const auto reports = norr::probe_io_backends();
  NORR_CHECK(!reports.empty());

  // The baseline must always be present and usable: it is what the datapath
  // actually runs on.
  bool found_baseline = false;
  for (const auto& report : reports) {
    if (report.backend != norr::IoBackend::batched_syscalls) continue;
    found_baseline = true;
    NORR_CHECK(report.status == norr::BackendStatus::available);
  }
  NORR_CHECK(found_baseline);

  // Nothing else may claim availability: none has been written, let alone
  // measured against the baseline.
  for (const auto& report : reports) {
    if (report.backend == norr::IoBackend::batched_syscalls) continue;
    NORR_CHECK(report.status != norr::BackendStatus::available);
    NORR_CHECK(!report.detail.empty());
  }

  // The active backend is the baseline, because promotion requires evidence.
  NORR_CHECK(norr::active_io_backend() == norr::IoBackend::batched_syscalls);

  std::printf("io_backend: kernel %s\n", norr::kernel_release().c_str());
  for (const auto& report : reports) {
    std::printf("  %-18s %-24s %s\n",
                std::string{norr::io_backend_name(report.backend)}.c_str(),
                std::string{norr::backend_status_name(report.status)}.c_str(),
                report.detail.c_str());
  }
}

}  // namespace

int main() {
  test_version_parsing();
  test_probe_is_honest();
  return 0;
}
