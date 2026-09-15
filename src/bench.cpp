#include "norr/bench.hpp"

#include <algorithm>
#include <cmath>
#include <cstdio>

#if defined(__linux__) || defined(__APPLE__)
#include <sys/utsname.h>
#endif

namespace norr {
BenchEnvironment BenchEnvironment::detect() {
  BenchEnvironment environment;

#if defined(__linux__) || defined(__APPLE__)
  utsname info{};
  if (uname(&info) == 0) {
    environment.kernel = std::string{info.sysname} + " " + info.release;
    environment.hardware = info.machine;
  }
#endif

#if defined(__clang__)
  environment.compiler = "clang " + std::to_string(__clang_major__) + "." +
                         std::to_string(__clang_minor__);
#elif defined(__GNUC__)
  environment.compiler = "gcc " + std::to_string(__GNUC__) + "." + std::to_string(__GNUC_MINOR__);
#else
  environment.compiler = "unknown";
#endif

#if defined(NDEBUG)
  environment.build_type = "release";
#else

  environment.build_type = "debug (NOT a performance build)";
#endif

  return environment;
}

void Samples::sort_if_needed() {
  if (sorted_) return;
  std::sort(values_.begin(), values_.end());
  sorted_ = true;
}

double Samples::percentile(double fraction) {
  if (values_.empty()) return 0.0;
  sort_if_needed();
  const auto clamped = std::clamp(fraction, 0.0, 1.0);
  const auto position = clamped * static_cast<double>(values_.size() - 1);
  const auto lower = static_cast<std::size_t>(position);
  const auto upper = std::min(lower + 1, values_.size() - 1);
  const auto weight = position - static_cast<double>(lower);
  return values_[lower] * (1.0 - weight) + values_[upper] * weight;
}

double Samples::min() {
  if (values_.empty()) return 0.0;
  sort_if_needed();
  return values_.front();
}

double Samples::max() {
  if (values_.empty()) return 0.0;
  sort_if_needed();
  return values_.back();
}

double Samples::mean() const {
  if (values_.empty()) return 0.0;
  double total = 0.0;
  for (const auto value : values_) total += value;
  return total / static_cast<double>(values_.size());
}

double Samples::stddev() const {
  if (values_.size() < 2) return 0.0;
  const auto average = mean();
  double sum = 0.0;
  for (const auto value : values_) {
    const auto delta = value - average;
    sum += delta * delta;
  }
  return std::sqrt(sum / static_cast<double>(values_.size()));
}

double BenchResult::operations_per_second() const noexcept {
  if (elapsed.count() <= 0) return 0.0;
  const auto seconds = static_cast<double>(elapsed.count()) / 1e9;
  return static_cast<double>(operations) / seconds;
}

double BenchResult::gigabits_per_second() const noexcept {
  if (bytes_per_operation == 0) return 0.0;
  const auto bits = operations_per_second() * static_cast<double>(bytes_per_operation) * 8.0;
  return bits / 1e9;
}

double BenchResult::nanoseconds_per_operation() const noexcept {
  if (operations == 0) return 0.0;
  return static_cast<double>(elapsed.count()) / static_cast<double>(operations);
}

void print_report(const BenchEnvironment& environment, const std::vector<BenchResult>& results) {
  std::printf("\n=== Norr benchmark report ===\n");
  std::printf("hardware : %s\n", environment.hardware.c_str());
  std::printf("kernel   : %s\n", environment.kernel.c_str());
  std::printf("compiler : %s\n", environment.compiler.c_str());
  std::printf("build    : %s\n", environment.build_type.c_str());
  if (!environment.notes.empty()) std::printf("notes    : %s\n", environment.notes.c_str());

  std::printf("\n%-28s %12s %14s %12s\n", "benchmark", "ops/s", "ns/op", "Gb/s");
  std::printf("%-28s %12s %14s %12s\n", "----------------------------", "------------",
              "--------------", "------------");
  for (const auto& result : results) {
    std::printf("%-28s %12.0f %14.1f", result.name.c_str(), result.operations_per_second(),
                result.nanoseconds_per_operation());
    if (result.bytes_per_operation > 0) {
      std::printf(" %12.3f", result.gigabits_per_second());
    } else {
      std::printf(" %12s", "-");
    }
    std::printf("\n");
  }

  std::printf(
      "\nThese figures describe this machine and this build only. They are not\n"
      "a claim about Norr's speed: see research/performance-research.md.\n");
}

void print_latency_report(std::string_view name, Samples& samples) {
  if (samples.empty()) {
    std::printf("%-28s (no samples)\n", std::string{name}.c_str());
    return;
  }
  std::printf("%-28s n=%zu  p50=%.0f  p95=%.0f  p99=%.0f  max=%.0f  sd=%.0f (ns)\n",
              std::string{name}.c_str(), samples.count(), samples.percentile(0.50),
              samples.percentile(0.95), samples.percentile(0.99), samples.max(),
              samples.stddev());
}

}
