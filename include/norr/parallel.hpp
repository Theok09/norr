// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#pragma once

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <functional>
#include <mutex>
#include <thread>
#include <vector>

namespace norr {
class ParallelRunner {
 public:
  explicit ParallelRunner(std::size_t helpers = default_helpers());
  ~ParallelRunner();

  ParallelRunner(const ParallelRunner&) = delete;
  ParallelRunner& operator=(const ParallelRunner&) = delete;

  [[nodiscard]] static std::size_t default_helpers() noexcept;

  [[nodiscard]] std::size_t lanes() const noexcept { return helpers_.size() + 1; }

  void run(std::size_t count, const std::function<void(std::size_t)>& task);

 private:
  static constexpr std::size_t kSequentialBelow = 8;

  void helper_loop();
  void drain();

  std::vector<std::thread> helpers_;
  std::mutex mutex_;
  std::condition_variable wake_;
  std::condition_variable done_;
  const std::function<void(std::size_t)>* task_{};
  std::size_t count_{};
  std::atomic<std::size_t> next_{0};
  std::atomic<std::size_t> finished_{0};
  std::atomic<std::uint64_t> generation_{0};
  bool stopping_{};
};
}
