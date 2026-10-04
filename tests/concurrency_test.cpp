
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdio>
#include <mutex>
#include <set>
#include <span>
#include <string_view>
#include <thread>
#include <vector>

#include "check.hpp"
#include "norr/routing.hpp"
#include "norr/session.hpp"

namespace {
std::vector<std::byte> as_bytes(std::string_view text) {
  std::vector<std::byte> bytes;
  bytes.reserve(text.size());
  for (const char character : text) {
    bytes.push_back(static_cast<std::byte>(static_cast<unsigned char>(character)));
  }
  return bytes;
}

norr::TrafficKeys make_keys(std::string_view secret_text, norr::KeyDirection direction) {
  const auto secret = as_bytes(secret_text);
  const auto key = norr::derive_traffic_key(secret, norr::kDataLabel, direction, 0);
  NORR_CHECK(key.has_value());
  return norr::TrafficKeys{*key, 0};
}

constexpr std::size_t kThreads = 4;
constexpr std::size_t kPacketsPerThread = 500;

void test_concurrent_seal_issues_unique_counters() {
  if (!norr::crypto_available()) {
    std::puts("concurrency: skipped, no crypto backend");
    return;
  }

  norr::Session session{1, 0x10, 0x20, make_keys("send", norr::KeyDirection::initiator_to_responder),
                        make_keys("recv", norr::KeyDirection::responder_to_initiator)};

  std::mutex collected_guard;
  std::vector<std::uint64_t> counters;
  counters.reserve(kThreads * kPacketsPerThread);

  std::vector<std::thread> threads;
  for (std::size_t thread = 0; thread < kThreads; ++thread) {
    threads.emplace_back([&] {
      std::array<std::byte, 64> plaintext{};
      std::array<std::byte, 256> sealed{};
      std::vector<std::uint64_t> mine;
      mine.reserve(kPacketsPerThread);

      for (std::size_t packet = 0; packet < kPacketsPerThread; ++packet) {
        const auto written = session.seal(norr::FrameType::data, plaintext, sealed);
        if (!written) continue;

        std::uint64_t counter = 0;
        for (std::size_t index = 0; index < 8; ++index) {
          counter = (counter << 8) | static_cast<std::uint64_t>(sealed[6 + index]);
        }
        mine.push_back(counter);
      }

      const std::lock_guard lock{collected_guard};
      counters.insert(counters.end(), mine.begin(), mine.end());
    });
  }
  for (auto& thread : threads) thread.join();

  NORR_CHECK(!counters.empty());
  const std::set<std::uint64_t> unique{counters.begin(), counters.end()};
  NORR_CHECK(unique.size() == counters.size());

  std::printf("concurrency: %zu counters issued across %zu threads, all unique OK\n",
              counters.size(), kThreads);
}

void test_session_survives_erase_while_held() {
  norr::SessionTable table;

  const auto installed = table.install(1, 0x30, 0x40, make_keys("s", norr::KeyDirection::initiator_to_responder),
                                       make_keys("r", norr::KeyDirection::responder_to_initiator));
  NORR_CHECK(installed.has_value());

  auto held = table.find_by_peer(1);
  NORR_CHECK(held != nullptr);

  table.remove(0x30);
  NORR_CHECK(table.find_by_peer(1) == nullptr);

  NORR_CHECK(held->peer() == 1);
  NORR_CHECK(held->local_key_id() == 0x30);

  std::puts("concurrency: a held session outlives its removal from the table OK");
}

void test_concurrent_classify_during_reload() {
  norr::RoutingTable routes;

  const auto local = norr::parse_prefix("10.70.0.1/32");
  NORR_CHECK(local.has_value());
  NORR_CHECK(routes.add_local(*local).has_value());

  for (norr::PeerId peer = 1; peer <= 8; ++peer) {
    const auto prefix = norr::parse_prefix("10.71." + std::to_string(peer) + ".0/24");
    NORR_CHECK(prefix.has_value());
    NORR_CHECK(routes.add(peer, *prefix).has_value());
  }

  std::atomic<bool> stop{false};
  std::atomic<std::uint64_t> classified{0};

  std::vector<std::thread> readers;
  for (std::size_t thread = 0; thread < kThreads; ++thread) {
    readers.emplace_back([&] {
      const auto source = norr::parse_address("10.71.1.5");
      const auto destination = norr::parse_address("10.71.2.5");
      if (!source || !destination) return;

      const norr::IpPacketView packet{.family = norr::AddressFamily::ipv4,
                                      .source = *source,
                                      .destination = *destination,
                                      .protocol = 17,
                                      .hop_limit = 64,
                                      .header_length = 20,
                                      .total_length = 100};
      while (!stop.load(std::memory_order_relaxed)) {
        static_cast<void>(routes.classify(packet, norr::kNoPeer));
        classified.fetch_add(1, std::memory_order_relaxed);
      }
    });
  }

  for (std::size_t round = 0; round < 50; ++round) {
    routes.clear_peer_routes();
    for (norr::PeerId peer = 1; peer <= 8; ++peer) {
      const auto prefix = norr::parse_prefix("10.71." + std::to_string(peer) + ".0/24");
      if (prefix) static_cast<void>(routes.add(peer, *prefix));
    }
  }

  stop.store(true, std::memory_order_relaxed);
  for (auto& thread : readers) thread.join();

  NORR_CHECK(classified.load() > 0);
  std::printf("concurrency: %llu classifications across %zu reloads OK\n",
              static_cast<unsigned long long>(classified.load()), std::size_t{50});
}
}

int main() {
  test_concurrent_seal_issues_unique_counters();
  test_session_survives_erase_while_held();
  test_concurrent_classify_during_reload();
  return 0;
}
