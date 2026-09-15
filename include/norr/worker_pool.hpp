#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string_view>
#include <thread>
#include <vector>

#include "norr/flow_hash.hpp"
#include "norr/worker.hpp"

namespace norr {
struct WorkerPoolStats {
  std::uint64_t tun_to_udp{};
  std::uint64_t udp_to_tun{};
  std::uint64_t drops{};
  std::uint64_t polls{};
};

struct WorkerSlot {
  std::unique_ptr<TunDevice> tun;
  std::unique_ptr<UdpTransport> transport;
  std::unique_ptr<UdpCarrier> carrier;
  std::unique_ptr<Worker> worker;
  std::size_t index{};
};

class WorkerPool {
 public:

  [[nodiscard]] static std::size_t default_worker_count() noexcept;

  WorkerPool() = default;
  ~WorkerPool();

  WorkerPool(const WorkerPool&) = delete;
  WorkerPool& operator=(const WorkerPool&) = delete;

  [[nodiscard]] std::expected<std::size_t, TunError> start(std::string_view tun_name,
                                                           const Endpoint& bind_address,
                                                           RoutingTable& routes,
                                                           SessionTable& sessions,
                                                           std::size_t count);

  void run();
  void stop() noexcept { running_.store(false, std::memory_order_relaxed); }

  void join();

  [[nodiscard]] std::size_t size() const noexcept { return slots_.size(); }
  [[nodiscard]] Worker* worker(std::size_t index) noexcept;

  [[nodiscard]] std::size_t worker_for_flow(const FlowKey& key) const noexcept {
    return worker_for(key, slots_.size());
  }

  [[nodiscard]] WorkerPoolStats aggregate() const;

 private:
  std::vector<WorkerSlot> slots_;
  std::vector<std::thread> threads_;
  std::atomic<bool> running_{false};
};

}
