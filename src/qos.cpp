#include "norr/qos.hpp"

#include <algorithm>
#include <chrono>

namespace norr {
namespace {
constexpr std::uint8_t kDscpExpeditedForwarding = 46;
constexpr std::uint8_t kDscpVoiceAdmit = 44;
constexpr std::uint8_t kDscpClassSelector5 = 40;

[[nodiscard]] std::uint8_t dscp_of(const IpPacketView& packet,
                                   std::span<const std::byte> frame) noexcept {
  const std::size_t offset = packet.family == AddressFamily::ipv4 ? 1 : 0;
  if (frame.size() <= offset + 1) return 0;

  if (packet.family == AddressFamily::ipv4) {
    return static_cast<std::uint8_t>(static_cast<std::uint8_t>(frame[1]) >> 2U);
  }

  const auto high = static_cast<unsigned>(static_cast<std::uint8_t>(frame[0]) & 0x0FU);
  const auto low = static_cast<unsigned>(static_cast<std::uint8_t>(frame[1]) >> 4U);
  return static_cast<std::uint8_t>(((high << 4U) | low) >> 2U);
}

}

TrafficClass classify(const IpPacketView& packet, std::span<const std::byte> frame) noexcept {
  const auto dscp = dscp_of(packet, frame);
  if (dscp == kDscpExpeditedForwarding || dscp == kDscpVoiceAdmit ||
      dscp == kDscpClassSelector5) {
    return TrafficClass::realtime;
  }

  const auto payload = packet.total_length - packet.header_length;
  if (packet.protocol == kProtocolUdp && payload <= 256) return TrafficClass::realtime;

  if (packet.protocol == kProtocolTcp && payload >= 1024) return TrafficClass::bulk;

  return TrafficClass::normal;
}

std::size_t Scheduler::total_depth() const noexcept {
  std::size_t total = 0;
  for (const auto& queue : queues_) total += queue.size();
  return total;
}

bool Scheduler::has_room(TrafficClass traffic_class, std::size_t bytes) const noexcept {
  const auto index = static_cast<std::size_t>(traffic_class);
  if (queues_[index].size() >= limits_.capacity[index]) return false;
  return queued_bytes_ + bytes <= limits_.total_bytes;
}

void Scheduler::shed_bulk(std::size_t bytes_needed) {
  auto& bulk = queues_[static_cast<std::size_t>(TrafficClass::bulk)];
  while (!bulk.empty() && queued_bytes_ + bytes_needed > limits_.total_bytes) {
    queued_bytes_ -= bulk.front().bytes.size();
    bulk.pop_front();
    ++stats_.dropped[static_cast<std::size_t>(TrafficClass::bulk)];
    ++stats_.shed_for_memory;
  }
}

bool Scheduler::enqueue(std::vector<std::byte> packet, TrafficClass traffic_class, Instant now,
                        const Endpoint& destination) {
  const auto index = static_cast<std::size_t>(traffic_class);
  const auto bytes = packet.size();

  if (!has_room(traffic_class, bytes)) {
    if (traffic_class != TrafficClass::bulk && queued_bytes_ + bytes > limits_.total_bytes) {
      shed_bulk(bytes);
    }
    if (!has_room(traffic_class, bytes)) {
      ++stats_.dropped[index];
      return false;
    }
  }

  queues_[index].push_back(QueuedPacket{.bytes = std::move(packet),
                                        .traffic_class = traffic_class,
                                        .enqueued_at = now,
                                        .destination = destination});
  queued_bytes_ += bytes;
  ++stats_.enqueued[index];
  return true;
}

std::optional<QueuedPacket> Scheduler::dequeue(Instant now) {
  const auto take = [&](TrafficClass traffic_class) -> std::optional<QueuedPacket> {
    const auto index = static_cast<std::size_t>(traffic_class);
    auto& queue = queues_[index];
    if (queue.empty()) return std::nullopt;

    auto packet = std::move(queue.front());
    queue.pop_front();
    queued_bytes_ -= packet.bytes.size();
    ++stats_.dequeued[index];

    const auto delay = std::chrono::duration_cast<std::chrono::microseconds>(
                           now - packet.enqueued_at)
                           .count();
    if (delay >= 0) {
      stats_.queue_delay_total_us[index] += static_cast<double>(delay);
      ++stats_.queue_delay_samples[index];
    }
    return packet;
  };

  if (auto packet = take(TrafficClass::realtime)) return packet;

  auto& normal = queues_[static_cast<std::size_t>(TrafficClass::normal)];
  auto& bulk = queues_[static_cast<std::size_t>(TrafficClass::bulk)];

  if (normal.empty() && bulk.empty()) return std::nullopt;

  if (normal.empty()) {
    bulk_deficit_ = 0;
    return take(TrafficClass::bulk);
  }
  if (bulk.empty()) {
    normal_deficit_ = 0;
    return take(TrafficClass::normal);
  }

  if (normal_deficit_ < kNormalWeight) {
    ++normal_deficit_;
    return take(TrafficClass::normal);
  }
  if (bulk_deficit_ < kBulkWeight) {
    ++bulk_deficit_;
    return take(TrafficClass::bulk);
  }

  normal_deficit_ = 1;
  bulk_deficit_ = 0;
  return take(TrafficClass::normal);
}

}
