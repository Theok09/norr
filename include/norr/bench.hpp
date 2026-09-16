// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace norr {
struct BenchEnvironment {
  std::string hardware;
  std::string kernel;
  std::string compiler;
  std::string build_type;
  std::string notes;

  [[nodiscard]] static BenchEnvironment detect();
};

class Samples {
 public:
  void reserve(std::size_t count) { values_.reserve(count); }
  void add(double value) { values_.push_back(value); }

  [[nodiscard]] std::size_t count() const noexcept { return values_.size(); }
  [[nodiscard]] bool empty() const noexcept { return values_.empty(); }

  [[nodiscard]] double percentile(double fraction);
  [[nodiscard]] double min();
  [[nodiscard]] double max();
  [[nodiscard]] double mean() const;

  [[nodiscard]] double stddev() const;

 private:
  void sort_if_needed();

  std::vector<double> values_;
  bool sorted_{};
};

struct BenchResult {
  std::string name;
  std::uint64_t operations{};
  std::chrono::nanoseconds elapsed{};
  std::size_t bytes_per_operation{};

  [[nodiscard]] double operations_per_second() const noexcept;
  [[nodiscard]] double gigabits_per_second() const noexcept;
  [[nodiscard]] double nanoseconds_per_operation() const noexcept;

};

template <typename Body>
[[nodiscard]] BenchResult run_benchmark(std::string_view name, std::uint64_t iterations,
                                        std::size_t bytes_per_operation, Body&& body) {
  const auto warmup = std::min<std::uint64_t>(iterations / 10, 10'000);
  for (std::uint64_t index = 0; index < warmup; ++index) body();

  const auto start = std::chrono::steady_clock::now();
  for (std::uint64_t index = 0; index < iterations; ++index) body();
  const auto finish = std::chrono::steady_clock::now();

  return BenchResult{
      .name = std::string{name},
      .operations = iterations,
      .elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(finish - start),
      .bytes_per_operation = bytes_per_operation,
  };
}

void print_report(const BenchEnvironment& environment, const std::vector<BenchResult>& results);

void print_latency_report(std::string_view name, Samples& samples);

struct GateAResult {
  bool packets_intact{true};
  bool replay_rejected{true};
  bool memory_stable{true};
  std::uint64_t packets_checked{};
  std::string failure;

  [[nodiscard]] bool passed() const noexcept {
    return packets_intact && replay_rejected && memory_stable;
  }
};

}
