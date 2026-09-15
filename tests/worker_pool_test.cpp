// Per-core workers with one TUN queue each.
//
// Opening a TUN device needs CAP_NET_ADMIN, so the parts that require it
// report themselves as skipped rather than failing. Flow affinity is pure
// arithmetic and is tested everywhere.

#include "check.hpp"
#include <cstdio>
#include <set>
#include <string_view>
#include <vector>

#include "norr/worker_pool.hpp"

namespace {

norr::Address address_of(std::string_view text) {
  const auto parsed = norr::parse_address(text);
  NORR_CHECK(parsed.has_value());
  return *parsed;
}

norr::FlowKey flow(std::string_view source, std::string_view destination,
                   std::uint16_t source_port, std::uint16_t destination_port) {
  return norr::FlowKey{.source = address_of(source),
                       .destination = address_of(destination),
                       .source_port = source_port,
                       .destination_port = destination_port,
                       .protocol = norr::kProtocolTcp};
}

void test_worker_count_is_sane() {
  const auto count = norr::WorkerPool::default_worker_count();
  // hardware_concurrency may report zero; the floor must hold.
  NORR_CHECK(count >= 1);

  std::puts("pool: default worker count has a floor OK");
}

void test_flow_affinity_is_stable() {
  norr::WorkerPool pool;
  // Affinity is arithmetic over the flow hash, so it can be checked without
  // any device.
  const auto forward = flow("10.1.0.5", "10.2.0.7", 1234, 80);
  const auto reverse = flow("10.2.0.7", "10.1.0.5", 80, 1234);

  for (std::size_t workers : {std::size_t{2}, std::size_t{4}, std::size_t{8}}) {
    const auto a = norr::worker_for(forward, workers);
    const auto b = norr::worker_for(reverse, workers);
    // Both halves of a conversation must land on one worker, or session state
    // would be touched from two threads.
    NORR_CHECK(a == b);
    NORR_CHECK(a < workers);

    // Repeated lookups must agree; an unstable hash would move a live flow
    // between cores.
    NORR_CHECK(norr::worker_for(forward, workers) == a);
  }

  std::puts("pool: flow affinity is stable and bidirectional OK");
}

void test_flows_spread_across_workers() {
  constexpr std::size_t kWorkers = 4;
  std::set<std::size_t> touched;

  for (std::uint16_t port = 1; port < 500; ++port) {
    touched.insert(norr::worker_for(flow("10.1.0.5", "10.2.0.7", port, 80), kWorkers));
  }

  // A hash that sent everything to one worker would silently destroy the
  // parallelism this pool exists for.
  NORR_CHECK(touched.size() == kWorkers);

  std::puts("pool: flows spread across all workers OK");
}

#if defined(__linux__)

void test_pool_start() {
  norr::RoutingTable routes;
  norr::SessionTable sessions;
  const auto prefix = norr::parse_prefix("10.2.0.0/16");
  NORR_CHECK(prefix.has_value());
  NORR_CHECK(routes.add(2, *prefix).has_value());

  norr::WorkerPool pool;
  const auto loopback = address_of("127.0.0.1");
  const auto started = pool.start("norrpool0", norr::Endpoint{loopback, 0}, routes, sessions, 4);

  if (!started) {
    std::printf("pool: TUN unavailable (%s), start skipped\n",
                std::string{norr::tun_error_message(started.error())}.c_str());
    return;
  }

  // The pool reports how many workers it actually built, which may be fewer
  // than requested on a kernel without multiqueue support. A caller must not
  // assume it got what it asked for.
  NORR_CHECK(*started >= 1);
  NORR_CHECK(*started <= 4);
  NORR_CHECK(pool.size() == *started);
  std::printf("pool: started %zu of 4 requested workers\n", *started);

  for (std::size_t index = 0; index < pool.size(); ++index) {
    NORR_CHECK(pool.worker(index) != nullptr);
  }
  // Out-of-range access returns null rather than reading past the end.
  NORR_CHECK(pool.worker(pool.size()) == nullptr);

  const auto stats = pool.aggregate();
  NORR_CHECK(stats.tun_to_udp == 0);
  NORR_CHECK(stats.drops == 0);

  std::puts("pool: start and aggregate OK");
}

void test_run_and_stop() {
  norr::RoutingTable routes;
  norr::SessionTable sessions;

  norr::WorkerPool pool;
  const auto loopback = address_of("127.0.0.1");
  const auto started = pool.start("norrpool1", norr::Endpoint{loopback, 0}, routes, sessions, 2);
  if (!started) {
    std::puts("pool: TUN unavailable, run/stop skipped");
    return;
  }

  // Threads must start and stop cleanly; a hang here would be a deadlock in
  // the poll loop.
  pool.run();
  pool.stop();
  pool.join();

  // Stopping twice and joining twice must be harmless.
  pool.stop();
  pool.join();

  std::puts("pool: run and stop cleanly OK");
}

#endif  // __linux__

}  // namespace

int main() {
  test_worker_count_is_sane();
  test_flow_affinity_is_stable();
  test_flows_spread_across_workers();

#if defined(__linux__)
  test_pool_start();
  test_run_and_stop();
#else
  std::puts("pool: not Linux, device tests skipped");
#endif
  return 0;
}
