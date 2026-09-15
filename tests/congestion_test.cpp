// Delay-and-delivery congestion control.

#include "check.hpp"
#include <chrono>
#include <cstdio>

#include "norr/congestion.hpp"

namespace {

norr::DeliverySample sample_of(std::chrono::microseconds rtt, std::uint64_t delivered,
                               std::uint64_t lost = 0) {
  return norr::DeliverySample{.rtt = rtt,
                              .bytes_delivered = delivered,
                              .bytes_lost = lost,
                              .interval = std::chrono::milliseconds{100}};
}

void test_rtt_estimation() {
  norr::CongestionController controller;
  auto now = norr::Instant{};

  controller.observe(sample_of(std::chrono::microseconds{20'000}, 10'000), now);
  // The first sample seeds the estimator directly rather than being averaged
  // against a zero that was never measured.
  NORR_CHECK(controller.smoothed_rtt() == std::chrono::microseconds{20'000});
  NORR_CHECK(controller.minimum_rtt() == std::chrono::microseconds{20'000});

  for (int index = 0; index < 20; ++index) {
    now += std::chrono::milliseconds{100};
    controller.observe(sample_of(std::chrono::microseconds{20'000}, 10'000), now);
  }
  // A steady path keeps the estimate steady and the variance small.
  NORR_CHECK(controller.smoothed_rtt() >= std::chrono::microseconds{19'000});
  NORR_CHECK(controller.smoothed_rtt() <= std::chrono::microseconds{21'000});
  NORR_CHECK(controller.rtt_variance() < std::chrono::microseconds{5'000});

  std::puts("congestion: RTT estimation OK");
}

void test_probes_on_an_idle_path() {
  norr::CongestionController controller;
  auto now = norr::Instant{};
  const auto start = controller.rate_bytes_per_second();

  // A path with no queueing and no loss: the controller should climb.
  for (int index = 0; index < 30; ++index) {
    controller.observe(sample_of(std::chrono::microseconds{20'000}, 100'000), now);
    now += std::chrono::milliseconds{100};
  }

  NORR_CHECK(controller.rate_bytes_per_second() > start);
  NORR_CHECK(controller.stats().probes > 0);

  std::puts("congestion: probes upward on an idle path OK");
}

void test_backs_off_on_queueing_delay() {
  norr::CongestionController controller;
  auto now = norr::Instant{};

  // Establish a baseline.
  for (int index = 0; index < 20; ++index) {
    controller.observe(sample_of(std::chrono::microseconds{20'000}, 100'000), now);
    now += std::chrono::milliseconds{100};
  }
  const auto before = controller.rate_bytes_per_second();

  // RTT climbs while the minimum stays put: a queue is building. The
  // controller must back off before that queue turns into loss.
  for (int index = 0; index < 10; ++index) {
    controller.observe(sample_of(std::chrono::microseconds{80'000}, 100'000), now);
    now += std::chrono::milliseconds{100};
  }

  NORR_CHECK(controller.rate_bytes_per_second() < before);
  NORR_CHECK(controller.stats().delay_backoffs > 0);
  NORR_CHECK(controller.queueing_delay() > std::chrono::microseconds{0});

  std::puts("congestion: backs off on queueing delay OK");
}

void test_ignores_modest_random_loss() {
  norr::CongestionController controller;
  auto now = norr::Instant{};

  for (int index = 0; index < 20; ++index) {
    controller.observe(sample_of(std::chrono::microseconds{20'000}, 100'000), now);
    now += std::chrono::milliseconds{100};
  }
  const auto before = controller.rate_bytes_per_second();

  // 2% loss with no delay growth is a lossy link, not congestion. A
  // loss-based controller would collapse here; this one must not.
  for (int index = 0; index < 10; ++index) {
    controller.observe(sample_of(std::chrono::microseconds{20'000}, 98'000, 2'000), now);
    now += std::chrono::milliseconds{100};
  }

  NORR_CHECK(controller.stats().loss_backoffs == 0);
  NORR_CHECK(controller.rate_bytes_per_second() >= before);

  std::puts("congestion: modest random loss does not collapse the rate OK");
}

void test_backs_off_on_severe_loss() {
  norr::CongestionController controller;
  auto now = norr::Instant{};

  for (int index = 0; index < 20; ++index) {
    controller.observe(sample_of(std::chrono::microseconds{20'000}, 100'000), now);
    now += std::chrono::milliseconds{100};
  }
  const auto before = controller.rate_bytes_per_second();

  // Above the threshold, loss is congestion whatever the delay says.
  for (int index = 0; index < 10; ++index) {
    controller.observe(sample_of(std::chrono::microseconds{20'000}, 70'000, 30'000), now);
    now += std::chrono::milliseconds{100};
  }

  NORR_CHECK(controller.stats().loss_backoffs > 0);
  NORR_CHECK(controller.rate_bytes_per_second() < before);

  std::puts("congestion: severe loss backs the rate off OK");
}

void test_probe_cannot_exceed_measured_delivery() {
  norr::CongestionController controller;
  auto now = norr::Instant{};

  // The path delivers 100 KB per 100 ms, so 1 MB/s. The controller must not
  // probe far above a rate the path has actually demonstrated.
  for (int index = 0; index < 100; ++index) {
    controller.observe(sample_of(std::chrono::microseconds{20'000}, 100'000), now);
    now += std::chrono::milliseconds{100};
  }

  const auto delivery = controller.delivery_rate_bytes_per_second();
  NORR_CHECK(delivery > 0.0);
  NORR_CHECK(controller.rate_bytes_per_second() <= delivery * 1.3);

  std::puts("congestion: probe bounded by measured delivery OK");
}

void test_minimum_rtt_window_expires() {
  norr::CongestionController controller;
  auto now = norr::Instant{};

  controller.observe(sample_of(std::chrono::microseconds{5'000}, 10'000), now);
  NORR_CHECK(controller.minimum_rtt() == std::chrono::microseconds{5'000});

  // After the window passes, an old low sample must stop pinning the minimum,
  // or a route change would look like a permanent standing queue.
  now += std::chrono::seconds{15};
  for (int index = 0; index < 10; ++index) {
    controller.observe(sample_of(std::chrono::microseconds{40'000}, 10'000), now);
    now += std::chrono::milliseconds{100};
  }
  NORR_CHECK(controller.minimum_rtt() > std::chrono::microseconds{5'000});

  std::puts("congestion: minimum RTT window expires OK");
}

void test_rate_stays_within_bounds() {
  norr::CongestionConfig config;
  norr::CongestionController controller{config, config.minimum_rate_bytes};
  auto now = norr::Instant{};

  // Sustained severe congestion must not drive the rate to zero: a tunnel
  // that stops entirely never recovers, because it sends nothing to measure.
  for (int index = 0; index < 200; ++index) {
    controller.observe(sample_of(std::chrono::microseconds{500'000}, 1'000, 9'000), now);
    now += std::chrono::milliseconds{100};
  }
  NORR_CHECK(controller.rate_bytes_per_second() >= config.minimum_rate_bytes);

  std::puts("congestion: rate bounded below OK");
}

}  // namespace

int main() {
  test_rtt_estimation();
  test_probes_on_an_idle_path();
  test_backs_off_on_queueing_delay();
  test_ignores_modest_random_loss();
  test_backs_off_on_severe_loss();
  test_probe_cannot_exceed_measured_delivery();
  test_minimum_rtt_window_expires();
  test_rate_stays_within_bounds();
  return 0;
}
