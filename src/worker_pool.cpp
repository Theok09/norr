#include "norr/worker_pool.hpp"

#include <algorithm>

namespace norr {
std::size_t WorkerPool::default_worker_count() noexcept {
  const auto reported = std::thread::hardware_concurrency();

  if (reported == 0) return 1;
  return static_cast<std::size_t>(reported);
}

WorkerPool::~WorkerPool() {
  stop();
  join();
}

std::expected<std::size_t, TunError> WorkerPool::start(std::string_view tun_name,
                                                       const Endpoint& bind_address,
                                                       RoutingTable& routes,
                                                       SessionTable& sessions,
                                                       std::size_t count) {
  if (count == 0) count = 1;
  slots_.clear();

  for (std::size_t index = 0; index < count; ++index) {
    WorkerSlot slot;
    slot.index = index;

    if (index == 0) {
      slot.tun = std::make_unique<TunDevice>();

      auto opened = slot.tun->open(tun_name, true, count > 1);
      if (!opened && count > 1) {
        slot.tun = std::make_unique<TunDevice>();
        opened = slot.tun->open(tun_name);
        count = 1;
      }
      if (!opened) return std::unexpected(opened.error());
    } else {
      auto queue = TunDevice::open_queue(tun_name);
      if (!queue) break;
      slot.tun = std::make_unique<TunDevice>(std::move(*queue));
    }

    slot.transport = std::make_unique<UdpTransport>();

    const auto started = slot.transport->start(bind_address);
    if (!started) break;

    slot.carrier = std::make_unique<UdpCarrier>(*slot.transport);
    slot.worker = std::make_unique<Worker>(*slot.tun, *slot.carrier, routes, sessions);
    slots_.push_back(std::move(slot));
  }

  if (slots_.empty()) return std::unexpected(TunError::configure_failed);
  return slots_.size();
}

Worker* WorkerPool::worker(std::size_t index) noexcept {
  if (index >= slots_.size()) return nullptr;
  return slots_[index].worker.get();
}

void WorkerPool::run() {
  running_.store(true, std::memory_order_relaxed);
  threads_.clear();
  threads_.reserve(slots_.size());

  for (auto& slot : slots_) {
    threads_.emplace_back([this, &slot] {
      auto* worker = slot.worker.get();
      while (running_.load(std::memory_order_relaxed)) {
        if (worker->poll() == 0) std::this_thread::yield();
      }
    });
  }
}

void WorkerPool::join() {
  for (auto& thread : threads_) {
    if (thread.joinable()) thread.join();
  }
  threads_.clear();
}

WorkerPoolStats WorkerPool::aggregate() const {
  WorkerPoolStats total;
  for (const auto& slot : slots_) {
    if (slot.worker == nullptr) continue;
    const auto& stats = slot.worker->stats();
    total.tun_to_udp += stats.tun_to_udp;
    total.udp_to_tun += stats.udp_to_tun;
    total.drops += stats.drops;
  }
  return total;
}

}
