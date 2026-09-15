#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>
#include <string_view>
#include <vector>

#include "norr/endpoint.hpp"
#include "norr/flow_hash.hpp"
#include "norr/ip_packet.hpp"
#include "norr/rate_limit.hpp"

namespace norr {
enum class TrafficClass : std::uint8_t { realtime, normal, bulk };

[[nodiscard]] constexpr std::string_view traffic_class_name(TrafficClass value) noexcept {
  switch (value) {
    case TrafficClass::realtime: return "realtime";
    case TrafficClass::normal: return "normal";
    case TrafficClass::bulk: return "bulk";
  }
  return "unknown";
}

inline constexpr std::size_t kTrafficClassCount = 3;

[[nodiscard]] TrafficClass classify(const IpPacketView& packet,
                                    std::span<const std::byte> frame) noexcept;

struct QueueLimits {
  std::array<std::size_t, kTrafficClassCount> capacity{256, 1024, 4096};

  std::size_t total_bytes{16 * 1024 * 1024};
};

struct SchedulerStats {
  std::array<std::uint64_t, kTrafficClassCount> enqueued{};
  std::array<std::uint64_t, kTrafficClassCount> dequeued{};
  std::array<std::uint64_t, kTrafficClassCount> dropped{};
  std::array<std::uint64_t, kTrafficClassCount> queue_delay_samples{};
  std::array<double, kTrafficClassCount> queue_delay_total_us{};
  std::uint64_t shed_for_memory{};

  [[nodiscard]] double mean_delay_us(TrafficClass value) const noexcept {
    const auto index = static_cast<std::size_t>(value);
    const auto samples = queue_delay_samples[index];
    return samples == 0 ? 0.0 : queue_delay_total_us[index] / static_cast<double>(samples);
  }
};

struct QueuedPacket {
  std::vector<std::byte> bytes;
  TrafficClass traffic_class{TrafficClass::normal};
  Instant enqueued_at{};

  Endpoint destination;
};

class Scheduler {
 public:
  explicit Scheduler(QueueLimits limits = {}) : limits_(limits) {}

  [[nodiscard]] bool enqueue(std::vector<std::byte> packet, TrafficClass traffic_class,
                             Instant now, const Endpoint& destination = {});

  [[nodiscard]] std::optional<QueuedPacket> dequeue(Instant now);

  [[nodiscard]] std::size_t depth(TrafficClass value) const noexcept {
    return queues_[static_cast<std::size_t>(value)].size();
  }
  [[nodiscard]] std::size_t total_depth() const noexcept;
  [[nodiscard]] std::size_t queued_bytes() const noexcept { return queued_bytes_; }
  [[nodiscard]] bool empty() const noexcept { return total_depth() == 0; }

  [[nodiscard]] const SchedulerStats& stats() const noexcept { return stats_; }
  [[nodiscard]] const QueueLimits& limits() const noexcept { return limits_; }

 private:
  [[nodiscard]] bool has_room(TrafficClass traffic_class, std::size_t bytes) const noexcept;
  void shed_bulk(std::size_t bytes_needed);

  QueueLimits limits_;
  std::array<std::deque<QueuedPacket>, kTrafficClassCount> queues_;
  std::size_t queued_bytes_{};

  static constexpr std::size_t kNormalWeight = 3;
  static constexpr std::size_t kBulkWeight = 1;
  std::size_t normal_deficit_{};
  std::size_t bulk_deficit_{};

  SchedulerStats stats_{};
};

}
