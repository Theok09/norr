// Traffic classes and the scheduler.

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
  // An explicit DSCP marking wins: the sender knows its own intent.
  NORR_CHECK(class_of(make_packet(norr::kProtocolTcp, 2000, 46)) == norr::TrafficClass::realtime);
  NORR_CHECK(class_of(make_packet(norr::kProtocolTcp, 2000, 44)) == norr::TrafficClass::realtime);

  // Without a marking, small UDP looks interactive.
  NORR_CHECK(class_of(make_packet(norr::kProtocolUdp, 100)) == norr::TrafficClass::realtime);
  // Large TCP looks like bulk transfer.
  NORR_CHECK(class_of(make_packet(norr::kProtocolTcp, 1400)) == norr::TrafficClass::bulk);
  // Everything else is normal.
  NORR_CHECK(class_of(make_packet(norr::kProtocolTcp, 500)) == norr::TrafficClass::normal);
  NORR_CHECK(class_of(make_packet(norr::kProtocolUdp, 800)) == norr::TrafficClass::normal);

  std::puts("qos: classification OK");
}

void test_realtime_has_strict_priority() {
  norr::Scheduler scheduler;
  const auto now = norr::Instant{};

  // Fill with bulk first, then add one realtime packet behind it.
  for (int index = 0; index < 50; ++index) {
    NORR_CHECK(scheduler.enqueue(std::vector<std::byte>(100), norr::TrafficClass::bulk, now));
  }
  NORR_CHECK(scheduler.enqueue(std::vector<std::byte>(50), norr::TrafficClass::realtime, now));

  // Realtime must come out first regardless of arrival order: a realtime
  // packet delayed behind bulk has usually already missed its deadline.
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

  // Normal gets the larger share, but bulk must get some: starvation is
  // explicitly forbidden by qos/scheduler.md.
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
  // Every queue is bounded, per runtime/backpressure.md.
  NORR_CHECK(!scheduler.enqueue(std::vector<std::byte>(10), norr::TrafficClass::realtime, now));
  NORR_CHECK(scheduler.stats().dropped[0] == 1);

  // A full realtime queue must not block the others.
  NORR_CHECK(scheduler.enqueue(std::vector<std::byte>(10), norr::TrafficClass::normal, now));

  std::puts("qos: per-class queue bounds OK");
}

void test_bulk_shed_under_memory_pressure() {
  norr::QueueLimits limits;
  limits.capacity = {64, 64, 64};
  limits.total_bytes = 10'000;
  norr::Scheduler scheduler{limits};
  const auto now = norr::Instant{};

  // Fill memory with bulk.
  while (scheduler.enqueue(std::vector<std::byte>(1000), norr::TrafficClass::bulk, now)) {
  }
  const auto bulk_before = scheduler.depth(norr::TrafficClass::bulk);
  NORR_CHECK(bulk_before > 0);

  // A realtime packet arriving under memory pressure must displace bulk
  // rather than being dropped: bulk is shed first.
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

  // qos/scheduler.md insists on measuring queueing delay, not just throughput:
  // throughput hides exactly the behaviour this scheduler controls.
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

}  // namespace

int main() {
  test_classification();
  test_realtime_has_strict_priority();
  test_bulk_is_not_starved();
  test_queues_are_bounded();
  test_bulk_shed_under_memory_pressure();
  test_queue_delay_is_measured();
  test_empty_scheduler();
  return 0;
}
