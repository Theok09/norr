#include "check.hpp"
#include <chrono>
#include <cstdio>
#include <set>
#include <vector>

#include "norr/packet.hpp"
#include "norr/spoof_feedback.hpp"

namespace {
std::uint32_t ip(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) {
  return (static_cast<std::uint32_t>(a) << 24U) | (static_cast<std::uint32_t>(b) << 16U) |
         (static_cast<std::uint32_t>(c) << 8U) | static_cast<std::uint32_t>(d);
}

norr::SpoofPool pool_of(std::size_t n) {
  std::vector<std::uint32_t> src;
  for (std::size_t i = 1; i <= n; ++i) src.push_back(ip(10, 0, 0, static_cast<std::uint8_t>(i)));
  return norr::SpoofPool{src, {.death_threshold = 1}};
}

void test_bitmap_roundtrip() {
  const std::vector<std::size_t> received{0, 3, 70, 130};
  const auto bitmap = norr::make_receipt_bitmap(received, 200);
  NORR_CHECK(norr::receipt_bit(bitmap, 0));
  NORR_CHECK(norr::receipt_bit(bitmap, 3));
  NORR_CHECK(norr::receipt_bit(bitmap, 70));
  NORR_CHECK(norr::receipt_bit(bitmap, 130));
  NORR_CHECK(!norr::receipt_bit(bitmap, 1));
  NORR_CHECK(!norr::receipt_bit(bitmap, 500));
  std::puts("spoof_feedback: receipt bitmap roundtrips OK");
}

void test_confirmed_source_stays_healthy() {
  norr::SpoofFeedback fb{pool_of(2), {.miss_windows = 2}};
  norr::Instant now{};
  for (int round = 0; round < 20; ++round) {
    const auto p = fb.pick(0x1234, now);
    NORR_CHECK(p.has_value());
    fb.apply_receipt(norr::make_receipt_bitmap(std::vector<std::size_t>{p->index}, fb.size()), now);
    NORR_CHECK(fb.healthy_count(now) == fb.size());
    now += std::chrono::seconds{1};
  }
  std::puts("spoof_feedback: confirmed source stays healthy forever OK");
}

void test_missing_source_blamed() {
  norr::SpoofFeedback fb{pool_of(2), {.miss_windows = 3}};
  norr::Instant now{};
  const auto empty = norr::make_receipt_bitmap(std::vector<std::size_t>{}, fb.size());
  for (int i = 0; i < 2; ++i) {
    static_cast<void>(fb.pick(0x55, now));
    fb.apply_receipt(empty, now);
    NORR_CHECK(fb.healthy_count(now) == 2);
  }
  static_cast<void>(fb.pick(0x55, now));
  fb.apply_receipt(empty, now);
  NORR_CHECK(fb.healthy_count(now) == 1);
  std::puts("spoof_feedback: source missing from N receipts gets blamed OK");
}

void test_unused_source_not_penalized() {
  norr::SpoofFeedback fb{pool_of(3), {.miss_windows = 1}};
  norr::Instant now{};
  const auto p = fb.pick(0x1, now);
  NORR_CHECK(p.has_value());
  fb.apply_receipt(norr::make_receipt_bitmap(std::vector<std::size_t>{}, 3), now);
  NORR_CHECK(fb.healthy_count(now) == 2);
  std::puts("spoof_feedback: sources never sent-on are not blamed OK");
}

void test_epoch_reroll_migrates_long_flow() {
  norr::SpoofFeedback fb{pool_of(8), {.miss_windows = 10,
                                      .reroll_interval = std::chrono::seconds{10}}};
  norr::Instant now{};
  const auto a = fb.pick(0xCAFEF00D, now);
  NORR_CHECK(a.has_value());
  std::set<std::uint32_t> seen{a->source_be};
  for (int epoch = 1; epoch <= 12; ++epoch) {
    const auto p = fb.pick(0xCAFEF00D, now + std::chrono::seconds{epoch * 10});
    NORR_CHECK(p.has_value());
    seen.insert(p->source_be);
  }
  NORR_CHECK(seen.size() >= 3);
  std::puts("spoof_feedback: epoch re-roll migrates a long flow across sources OK");
}

void test_no_reroll_pins_flow() {
  norr::SpoofFeedback fb{pool_of(8), {.miss_windows = 10}};
  norr::Instant now{};
  const auto first = fb.pick(0xCAFEF00D, now);
  NORR_CHECK(first.has_value());
  for (int s = 1; s <= 100; ++s) {
    const auto p = fb.pick(0xCAFEF00D, now + std::chrono::seconds{s});
    NORR_CHECK(p.has_value());
    NORR_CHECK(p->source_be == first->source_be);
  }
  std::puts("spoof_feedback: with no reroll, a flow stays pinned OK");
}

void test_receipt_frame_roundtrip() {
  const std::vector<std::size_t> received{0, 5, 63, 64, 130};
  const auto bitmap = norr::make_receipt_bitmap(received, 200);
  const auto frame = norr::encode_spoof_receipt(bitmap);
  NORR_CHECK(!frame.empty());
  NORR_CHECK(frame[0] == norr::kSpoofReceipt);
  const auto decoded = norr::decode_spoof_receipt(frame);
  for (const auto idx : received) NORR_CHECK(norr::receipt_bit(decoded, idx));
  NORR_CHECK(!norr::receipt_bit(decoded, 1));
  NORR_CHECK(!norr::receipt_bit(decoded, 129));
  std::puts("spoof_feedback: receipt control frame encodes and decodes OK");
}

void test_receipt_frame_rejects_bad_tag() {
  const std::vector<std::byte> bad{std::byte{0x03}, std::byte{0xFF}};
  NORR_CHECK(norr::decode_spoof_receipt(bad).empty());
  NORR_CHECK(norr::decode_spoof_receipt({}).empty());
  std::puts("spoof_feedback: receipt decode rejects wrong tag and empty OK");
}

void test_receipt_decode_caps_words() {
  std::vector<std::byte> huge(1 + 4096 * 8, std::byte{0xFF});
  huge[0] = norr::kSpoofReceipt;
  const auto decoded = norr::decode_spoof_receipt(huge);
  NORR_CHECK(decoded.size() <= norr::kSpoofReceiptMaxWords);
  std::puts("spoof_feedback: receipt decode caps words against oversized frame OK");
}

void test_randomized_feedback_loop() {
  norr::SpoofFeedback fb{pool_of(12), {.miss_windows = 3,
                                       .reroll_interval = std::chrono::seconds{5}}};
  std::uint64_t state = 0xDEADBEEFCAFEULL;
  auto rng = [&state]() {
    state ^= state << 13U;
    state ^= state >> 7U;
    state ^= state << 17U;
    return state;
  };
  norr::Instant now{};
  for (int round = 0; round < 20000; ++round) {
    std::vector<std::size_t> received;
    for (int f = 0; f < 5; ++f) {
      const auto p = fb.pick(rng(), now);
      NORR_CHECK(p.has_value());
      NORR_CHECK(p->index < fb.size());
      if (rng() % 4 != 0) received.push_back(p->index);
    }
    fb.apply_receipt(norr::make_receipt_bitmap(received, fb.size()), now);
    NORR_CHECK(fb.healthy_count(now) <= fb.size());
    now += std::chrono::milliseconds{static_cast<int>(rng() % 500)};
  }
  std::puts("spoof_feedback: 20k randomized feedback rounds hold invariants OK");
}
}

int main() {
  test_bitmap_roundtrip();
  test_confirmed_source_stays_healthy();
  test_missing_source_blamed();
  test_unused_source_not_penalized();
  test_epoch_reroll_migrates_long_flow();
  test_no_reroll_pins_flow();
  test_receipt_frame_roundtrip();
  test_receipt_frame_rejects_bad_tag();
  test_receipt_decode_caps_words();
  test_randomized_feedback_loop();
  std::puts("spoof_feedback: all tests passed");
  return 0;
}
