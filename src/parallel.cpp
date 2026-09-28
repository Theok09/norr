// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#include "norr/parallel.hpp"

#include <algorithm>

namespace norr {
namespace {
void relax() noexcept {
#if defined(__x86_64__) || defined(__i386__)
  __builtin_ia32_pause();
#elif defined(__aarch64__)
  asm volatile("yield");
#endif
}
}

std::size_t ParallelRunner::default_helpers() noexcept {
  const auto cores = std::thread::hardware_concurrency();
  if (cores <= 1) return 0;
  return std::min<std::size_t>(cores - 1, 3);
}

ParallelRunner::ParallelRunner(std::size_t helpers) {
  helpers_.reserve(helpers);
  for (std::size_t index = 0; index < helpers; ++index) {
    helpers_.emplace_back([this] { helper_loop(); });
  }
}

ParallelRunner::~ParallelRunner() {
  {
    const std::lock_guard lock{mutex_};
    stopping_ = true;
    generation_.fetch_add(1, std::memory_order_release);
  }
  wake_.notify_all();
  for (auto& helper : helpers_) helper.join();
}

void ParallelRunner::drain() {
  const auto& task = *task_;
  while (true) {
    const auto index = next_.fetch_add(1, std::memory_order_relaxed);
    if (index >= count_) break;
    task(index);
  }
}

void ParallelRunner::helper_loop() {
  std::uint64_t seen = 0;
  while (true) {
    std::uint64_t current = generation_.load(std::memory_order_acquire);
    for (int spin = 0; current == seen && spin < 4000; ++spin) {
      relax();
      current = generation_.load(std::memory_order_acquire);
    }
    if (current == seen) {
      std::unique_lock lock{mutex_};
      wake_.wait(lock, [&] { return generation_.load(std::memory_order_acquire) != seen; });
      current = generation_.load(std::memory_order_acquire);
    }
    seen = current;
    {
      const std::lock_guard lock{mutex_};
      if (stopping_) return;
    }
    drain();
    if (finished_.fetch_add(1, std::memory_order_acq_rel) + 1 == helpers_.size()) {
      const std::lock_guard lock{mutex_};
      done_.notify_one();
    }
  }
}

void ParallelRunner::run(std::size_t count, const std::function<void(std::size_t)>& task) {
  if (count == 0) return;
  if (helpers_.empty() || count < kSequentialBelow) {
    for (std::size_t index = 0; index < count; ++index) task(index);
    return;
  }

  {
    const std::lock_guard lock{mutex_};
    task_ = &task;
    count_ = count;
    next_.store(0, std::memory_order_relaxed);
    finished_.store(0, std::memory_order_relaxed);
    generation_.fetch_add(1, std::memory_order_release);
  }
  wake_.notify_all();

  drain();

  for (int spin = 0; finished_.load(std::memory_order_acquire) < helpers_.size() && spin < 20000;
       ++spin) {
    relax();
  }
  if (finished_.load(std::memory_order_acquire) < helpers_.size()) {
    std::unique_lock lock{mutex_};
    done_.wait(lock, [&] { return finished_.load(std::memory_order_acquire) == helpers_.size(); });
  }
  task_ = nullptr;
}
}
