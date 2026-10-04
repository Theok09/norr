
#include "check.hpp"
#include <chrono>
#include <cstdio>
#include <vector>

#include "norr/qos.hpp"

namespace {
std::vector<std::byte> make_packet(std::uint8_t protocol, std::size_t payload,
                                   std::uint8_t dscp = 0) {
  std::vector<std::byte> packet(norr::kIpv4HeaderSize + payload);
  packet[0] = std::byte{0x45};
  packet[1] = static_cast<std::byte>(dscp << 2U);
  const auto total = static_cast<std::uint16_t>(packet.size());
  packet[2] = static_cast<std::byte>(total >> 8U);
  packet[3] = static_cast<std::byte>(total & 0xFFU);
  packet[8] = std::byte{64};
  packet[9] = static_cast<std::byte>(protocol);
  return packet;
}

norr::TrafficClass class_of(const std::vector<std::byte>& packet) {
  const auto parsed = norr::parse_ip_packet(packet);
  NORR_CHECK(parsed.has_value());
  return norr::classify(*parsed, packet);
}

void test_classification() {
  NORR_CHECK(class_of(make_packet(norr::kProtocolTcp, 2000, 46)) == norr::TrafficClass::realtime);
  NORR_CHECK(class_of(make_packet(norr::kProtocolTcp, 2000, 44)) == norr::TrafficClass::realtime);

  NORR_CHECK(class_of(make_packet(norr::kProtocolUdp, 100)) == norr::TrafficClass::realtime);

  NORR_CHECK(class_of(make_packet(norr::kProtocolTcp, 1400)) == norr::TrafficClass::bulk);

  NORR_CHECK(class_of(make_packet(norr::kProtocolTcp, 500)) == norr::TrafficClass::normal);
  NORR_CHECK(class_of(make_packet(norr::kProtocolUdp, 800)) == norr::TrafficClass::normal);

  std::puts("qos: classification OK");
}

void test_realtime_has_strict_priority() {
  norr::Scheduler scheduler;
  const auto now = norr::Instant{};

  for (int index = 0; index < 50; ++index) {
    NORR_CHECK(scheduler.enqueue(std::vector<std::byte>(100), norr::TrafficClass::bulk, now));
  }
  NORR_CHECK(scheduler.enqueue(std::vector<std::byte>(50), norr::TrafficClass::realtime, now));

  const auto first = scheduler.dequeue(now);
  NORR_CHECK(first.has_value());
  NORR_CHECK(first->traffic_class == norr::TrafficClass::realtime);

  std::puts("qos: realtime has strict priority OK");
}

void test_bulk_is_not_starved() {
  norr::Scheduler scheduler;
  const auto now = norr::Instant{};

  for (int index = 0; index < 100; ++index) {
    NORR_CHECK(scheduler.enqueue(std::vector<std::byte>(100), norr::TrafficClass::normal, now));
    NORR_CHECK(scheduler.enqueue(std::vector<std::byte>(100), norr::TrafficClass::bulk, now));
  }

  std::size_t normal_seen = 0;
  std::size_t bulk_seen = 0;
  for (int index = 0; index < 100; ++index) {
    const auto packet = scheduler.dequeue(now);
    NORR_CHECK(packet.has_value());
    if (packet->traffic_class == norr::TrafficClass::normal) ++normal_seen;
    else ++bulk_seen;
  }

  NORR_CHECK(bulk_seen > 0);
  NORR_CHECK(normal_seen > bulk_seen);

  std::puts("qos: weighted sharing without starvation OK");
}

void test_queues_are_bounded() {
  norr::QueueLimits limits;
  limits.capacity = {4, 8, 16};
  norr::Scheduler scheduler{limits};
  const auto now = norr::Instant{};

  for (std::size_t index = 0; index < limits.capacity[0]; ++index) {
    NORR_CHECK(scheduler.enqueue(std::vector<std::byte>(10), norr::TrafficClass::realtime, now));
  }

  NORR_CHECK(!scheduler.enqueue(std::vector<std::byte>(10), norr::TrafficClass::realtime, now));
  NORR_CHECK(scheduler.stats().dropped[0] == 1);

  NORR_CHECK(scheduler.enqueue(std::vector<std::byte>(10), norr::TrafficClass::normal, now));

  std::puts("qos: per-class queue bounds OK");
}

void test_bulk_shed_under_memory_pressure() {
  norr::QueueLimits limits;
  limits.capacity = {64, 64, 64};
  limits.total_bytes = 10'000;
  norr::Scheduler scheduler{limits};
  const auto now = norr::Instant{};

  while (scheduler.enqueue(std::vector<std::byte>(1000), norr::TrafficClass::bulk, now)) {
  }
  const auto bulk_before = scheduler.depth(norr::TrafficClass::bulk);
  NORR_CHECK(bulk_before > 0);

  NORR_CHECK(scheduler.enqueue(std::vector<std::byte>(1000), norr::TrafficClass::realtime, now));
  NORR_CHECK(scheduler.depth(norr::TrafficClass::bulk) < bulk_before);
  NORR_CHECK(scheduler.stats().shed_for_memory > 0);

  std::puts("qos: bulk shed first under memory pressure OK");
}

void test_queue_delay_is_measured() {
  norr::Scheduler scheduler;
  auto now = norr::Instant{};

  NORR_CHECK(scheduler.enqueue(std::vector<std::byte>(100), norr::TrafficClass::normal, now));
  now += std::chrono::milliseconds{5};

  const auto packet = scheduler.dequeue(now);
  NORR_CHECK(packet.has_value());

  const auto mean = scheduler.stats().mean_delay_us(norr::TrafficClass::normal);
  NORR_CHECK(mean >= 4000.0 && mean <= 6000.0);

  std::puts("qos: queue delay measured OK");
}

void test_empty_scheduler() {
  norr::Scheduler scheduler;
  NORR_CHECK(scheduler.empty());
  NORR_CHECK(!scheduler.dequeue(norr::Instant{}).has_value());
  NORR_CHECK(scheduler.queued_bytes() == 0);

  std::puts("qos: empty scheduler OK");
}
}

void test_restore_keeps_packet_order() {
  norr::Scheduler scheduler;
  const auto now = std::chrono::steady_clock::now();
  for (std::uint8_t value = 1; value <= 3; ++value) {
    NORR_CHECK(scheduler.enqueue(std::vector<std::byte>(8, std::byte{value}),
                                 norr::TrafficClass::normal, now));
  }
  auto first = scheduler.dequeue(now);
  NORR_CHECK(first.has_value() && first->bytes[0] == std::byte{1});
  scheduler.restore(std::move(*first));
  for (std::uint8_t value = 1; value <= 3; ++value) {
    const auto next = scheduler.dequeue(now);
    NORR_CHECK(next.has_value() && next->bytes[0] == std::byte{value});
  }
  NORR_CHECK(scheduler.empty());
  std::puts("qos: a deferred packet keeps its place OK");
}

int main() {
  test_classification();
  test_realtime_has_strict_priority();
  test_bulk_is_not_starved();
  test_queues_are_bounded();
  test_bulk_shed_under_memory_pressure();
  test_queue_delay_is_measured();
  test_empty_scheduler();
  test_restore_keeps_packet_order();
  return 0;
}
