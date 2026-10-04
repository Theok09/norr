#include "check.hpp"
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <random>
#include <vector>

#include "norr/fec.hpp"

namespace {

std::vector<std::byte> packet_of(std::size_t length, std::uint8_t seed) {
  std::vector<std::byte> bytes(length);
  for (std::size_t index = 0; index < length; ++index) {
    bytes[index] = static_cast<std::byte>((seed * 131U + index * 7U) & 0xFFU);
  }
  return bytes;
}

struct Block {
  std::vector<std::vector<std::byte>> data;
  std::vector<norr::FecSymbolHeader> headers;
  std::vector<std::vector<std::byte>> parity;
};

Block encode(norr::FecEncoder& encoder, std::size_t count, bool flush) {
  Block block;
  for (std::size_t index = 0; index < count; ++index) {
    auto packet = packet_of(40 + index * 37 % 900, static_cast<std::uint8_t>(index + 1));
    block.headers.push_back(encoder.next_header(packet.size()));
    const auto parity = encoder.add(packet);
    block.data.push_back(std::move(packet));
    if (!parity.empty()) block.parity.assign(parity.begin(), parity.end());
  }
  if (flush && block.parity.empty()) {
    const auto parity = encoder.flush();
    block.parity.assign(parity.begin(), parity.end());
  }
  return block;
}

std::vector<std::vector<std::byte>> deliver(norr::FecDecoder& decoder, const Block& block,
                                            const std::vector<std::size_t>& lost_data,
                                            const std::vector<std::size_t>& lost_parity) {
  const auto now = std::chrono::steady_clock::now();
  std::vector<std::vector<std::byte>> recovered;
  for (std::size_t index = 0; index < block.data.size(); ++index) {
    if (std::ranges::find(lost_data, index) != lost_data.end()) continue;
    auto out = decoder.receive(block.headers[index], block.data[index], now);
    for (auto& packet : out) recovered.push_back(std::move(packet));
  }
  for (std::size_t index = 0; index < block.parity.size(); ++index) {
    if (std::ranges::find(lost_parity, index) != lost_parity.end()) continue;
    const auto header = norr::parse_fec_header(block.parity[index]);
    NORR_CHECK(header.has_value());
    auto out = decoder.receive(*header, std::span{block.parity[index]}.subspan(norr::kFecHeaderSize),
                               now);
    for (auto& packet : out) recovered.push_back(std::move(packet));
  }
  return recovered;
}

void test_field_arithmetic() {
  for (unsigned value = 1; value < 256; ++value) {
    const auto octet = static_cast<std::uint8_t>(value);
    NORR_CHECK(norr::gf256::multiply(octet, norr::gf256::inverse(octet)) == 1);
    NORR_CHECK(norr::gf256::multiply(octet, 1) == octet);
    NORR_CHECK(norr::gf256::multiply(octet, 0) == 0);
  }
  for (std::size_t row = 0; row < norr::kMaximumFecParity; ++row) {
    for (std::size_t column = 0; column < norr::kMaximumFecData; ++column) {
      NORR_CHECK(norr::gf256::cauchy(row, column) != 0);
    }
  }
  std::puts("fec: GF(256) arithmetic OK");
}

void test_modes() {
  NORR_CHECK(norr::parity_needed(32, 0.0, 16) == 16);
  NORR_CHECK(norr::parity_needed(32, 0.01, 16) >= 2 && norr::parity_needed(32, 0.01, 16) <= 4);
  NORR_CHECK(norr::parity_needed(32, 0.05, 16) > norr::parity_needed(32, 0.01, 16));
  NORR_CHECK(norr::parity_needed(1, 0.01, 16) == 1);
  NORR_CHECK(norr::parity_needed(32, 0.45, 16) == 16);

  const auto fast = norr::plan_for_loss(0.01, 100000.0);
  NORR_CHECK(fast.data == 32 && fast.lanes == norr::kMaximumFecLanes && fast.active());
  const auto slow = norr::plan_for_loss(0.01, 1000.0);
  NORR_CHECK(slow.lanes == 1 && slow.data == 5);
  const auto heavy = norr::plan_for_loss(0.1, 100000.0);
  NORR_CHECK(heavy.data == 16 && heavy.parity > fast.parity);
  NORR_CHECK(norr::block_size_for(norr::FecMode::off) == 0);
  NORR_CHECK(norr::parity_count_for(norr::FecMode::aggressive) == 4);

  norr::FecEncoder off{norr::FecMode::off};
  const auto packet = packet_of(100, 1);
  NORR_CHECK(off.add(packet).empty());
  NORR_CHECK(off.flush().empty());
  std::puts("fec: modes OK");
}

void test_header_roundtrip() {
  const norr::FecSymbolHeader header{.block_id = 0xDEADBEEF,
                                     .index = 3,
                                     .block_size = 10,
                                     .parity_count = 4,
                                     .parity = true,
                                     .original_length = 1402};
  std::array<std::byte, norr::kFecHeaderSize> bytes{};
  NORR_CHECK(norr::serialize_fec_header(header, bytes) == norr::kFecHeaderSize);
  const auto parsed = norr::parse_fec_header(bytes);
  NORR_CHECK(parsed.has_value());
  NORR_CHECK(parsed->block_id == header.block_id && parsed->index == 3);
  NORR_CHECK(parsed->block_size == 10 && parsed->parity_count == 4 && parsed->parity);
  NORR_CHECK(parsed->original_length == 1402);

  auto bad = bytes;
  bad[5] = std::byte{4};
  NORR_CHECK(!norr::parse_fec_header(bad).has_value());
  bad = bytes;
  bad[7] = std::byte{0};
  NORR_CHECK(!norr::parse_fec_header(bad).has_value());
  bad = bytes;
  bad[6] = std::byte{65};
  NORR_CHECK(!norr::parse_fec_header(bad).has_value());
  bad = bytes;
  bad[8] = std::byte{2};
  NORR_CHECK(!norr::parse_fec_header(bad).has_value());
  bad = bytes;
  bad[0] = std::byte{0};
  NORR_CHECK(!norr::parse_fec_header(bad).has_value());
  NORR_CHECK(!norr::parse_fec_header(std::span{bytes}.first(5)).has_value());
  std::puts("fec: header round-trip and validation OK");
}

void test_recovers_up_to_parity_count() {
  for (const auto mode : {norr::FecMode::light, norr::FecMode::moderate, norr::FecMode::aggressive}) {
    const auto k = norr::block_size_for(mode);
    const auto m = norr::parity_count_for(mode);
    norr::FecEncoder encoder{mode};
    const auto block = encode(encoder, k, false);
    NORR_CHECK(block.parity.size() == m);

    std::vector<std::size_t> lost;
    for (std::size_t index = 0; index < m; ++index) lost.push_back((index * 3 + 1) % k);
    std::ranges::sort(lost);
    lost.erase(std::unique(lost.begin(), lost.end()), lost.end());

    norr::FecDecoder decoder;
    const auto recovered = deliver(decoder, block, lost, {});
    NORR_CHECK(recovered.size() == lost.size());
    for (const auto index : lost) {
      NORR_CHECK(std::ranges::find(recovered, block.data[index]) != recovered.end());
    }
    NORR_CHECK(decoder.outstanding() == 0);
  }
  std::puts("fec: recovers as many losses as parity symbols OK");
}

void test_mixed_data_and_parity_loss() {
  norr::FecEncoder encoder{norr::FecMode::aggressive};
  const auto block = encode(encoder, 8, false);
  norr::FecDecoder decoder;
  const auto recovered = deliver(decoder, block, {0, 7}, {1, 2});
  NORR_CHECK(recovered.size() == 2);
  NORR_CHECK(std::ranges::find(recovered, block.data[0]) != recovered.end());
  NORR_CHECK(std::ranges::find(recovered, block.data[7]) != recovered.end());
  std::puts("fec: data and parity lost together still recovers OK");
}

void test_too_many_losses() {
  norr::FecEncoder encoder{norr::FecMode::moderate};
  const auto block = encode(encoder, 10, false);
  norr::FecDecoder decoder;
  const auto recovered = deliver(decoder, block, {1, 2, 3, 4}, {});
  NORR_CHECK(recovered.empty());
  std::puts("fec: more losses than parity are not recovered OK");
}

void test_short_flushed_block() {
  norr::FecEncoder encoder{norr::FecMode::moderate};
  const auto block = encode(encoder, 4, true);
  NORR_CHECK(block.parity.size() == 3);
  NORR_CHECK(norr::parse_fec_header(block.parity[0])->block_size == 4);
  norr::FecDecoder decoder;
  const auto recovered = deliver(decoder, block, {0, 3}, {});
  NORR_CHECK(recovered.size() == 2);
  std::puts("fec: short flushed block recovers OK");
}

void test_randomised_recovery() {
  std::mt19937 random{1234};
  for (int round = 0; round < 200; ++round) {
    norr::FecEncoder encoder{norr::FecMode::aggressive};
    const auto block = encode(encoder, 8, false);
    std::vector<std::size_t> symbols(12);
    for (std::size_t index = 0; index < 12; ++index) symbols[index] = index;
    std::ranges::shuffle(symbols, random);
    const auto losses = random() % 5;
    std::vector<std::size_t> lost_data;
    std::vector<std::size_t> lost_parity;
    for (std::size_t index = 0; index < losses; ++index) {
      if (symbols[index] < 8) lost_data.push_back(symbols[index]);
      else lost_parity.push_back(symbols[index] - 8);
    }
    norr::FecDecoder decoder;
    const auto recovered = deliver(decoder, block, lost_data, lost_parity);
    NORR_CHECK(recovered.size() == lost_data.size());
    for (const auto index : lost_data) {
      NORR_CHECK(std::ranges::find(recovered, block.data[index]) != recovered.end());
    }
  }
  std::puts("fec: randomised loss patterns recover exactly OK");
}

void test_duplicates_and_late_symbols() {
  norr::FecEncoder encoder{norr::FecMode::light};
  const auto block = encode(encoder, 16, false);
  norr::FecDecoder decoder;
  const auto now = std::chrono::steady_clock::now();
  NORR_CHECK(decoder.receive(block.headers[0], block.data[0], now).empty());
  NORR_CHECK(decoder.receive(block.headers[0], block.data[0], now).empty());
  const auto recovered = deliver(decoder, block, {0, 5}, {});
  NORR_CHECK(recovered.size() == 1);
  NORR_CHECK(recovered.front() == block.data[5]);
  NORR_CHECK(decoder.receive(block.headers[5], block.data[5], now).empty());
  NORR_CHECK(decoder.outstanding() == 0);
  std::puts("fec: duplicates and late symbols are ignored OK");
}

void test_bounds_and_expiry() {
  norr::FecDecoder decoder;
  const auto now = std::chrono::steady_clock::now();
  const auto packet = packet_of(64, 9);
  for (std::uint32_t id = 0; id < norr::kMaximumOutstandingBlocks + 20; ++id) {
    const norr::FecSymbolHeader header{.block_id = id,
                                       .index = 0,
                                       .block_size = 8,
                                       .parity_count = 4,
                                       .parity = false,
                                       .original_length = 64};
    NORR_CHECK(decoder.receive(header, packet, now).empty());
  }
  NORR_CHECK(decoder.outstanding() <= norr::kMaximumOutstandingBlocks);
  NORR_CHECK(decoder.expire(now + norr::kFecRecoveryDeadline) > 0);
  NORR_CHECK(decoder.outstanding() == 0);
  std::puts("fec: decoder state is bounded and expires OK");
}

void test_forged_parity_cannot_crash() {
  norr::FecEncoder encoder{norr::FecMode::moderate};
  const auto block = encode(encoder, 10, false);
  norr::FecDecoder decoder;
  const auto now = std::chrono::steady_clock::now();
  auto forged = block.parity[0];
  for (std::size_t index = norr::kFecHeaderSize; index < forged.size(); ++index) {
    forged[index] = static_cast<std::byte>(index);
  }
  const auto header = norr::parse_fec_header(forged);
  static_cast<void>(decoder.receive(*header, std::span{forged}.subspan(norr::kFecHeaderSize), now));
  for (std::size_t index = 1; index < 10; ++index) {
    static_cast<void>(decoder.receive(block.headers[index], block.data[index], now));
  }
  std::puts("fec: forged parity yields no crash OK");
}

void test_interleaved_burst() {
  const norr::FecPlan plan{.data = 4, .parity = 2, .lanes = 2, .loss = 0.0};
  norr::FecEncoder encoder{plan};
  Block block;
  for (std::size_t index = 0; index < 8; ++index) {
    auto packet = packet_of(200 + index, static_cast<std::uint8_t>(index + 3));
    block.headers.push_back(encoder.next_header(packet.size()));
    const auto parity = encoder.add(packet);
    block.data.push_back(std::move(packet));
    block.parity.insert(block.parity.end(), parity.begin(), parity.end());
  }
  NORR_CHECK(block.parity.size() == 4);
  NORR_CHECK(block.headers[0].block_id != block.headers[1].block_id);
  NORR_CHECK(block.headers[0].block_id == block.headers[2].block_id);

  norr::FecDecoder decoder;
  const auto recovered = deliver(decoder, block, {2, 3, 4, 5}, {});
  NORR_CHECK(recovered.size() == 4);
  for (const auto index : {2, 3, 4, 5}) {
    NORR_CHECK(std::ranges::find(recovered, block.data[static_cast<std::size_t>(index)]) !=
               recovered.end());
  }
  NORR_CHECK(decoder.outstanding() == 0);
  std::puts("fec: interleaved lanes absorb a burst of four losses OK");
}

void test_partial_flush_trims_parity() {
  norr::FecEncoder encoder{norr::plan_for_loss(0.01, 100000.0)};
  const auto packet = packet_of(300, 5);
  static_cast<void>(encoder.next_header(packet.size()));
  NORR_CHECK(encoder.add(packet).empty());
  NORR_CHECK(encoder.pending() == 1);
  const auto parity = encoder.flush();
  NORR_CHECK(parity.size() == 1);
  NORR_CHECK(encoder.pending() == 0);

  const auto first = encoder.next_header(packet.size());
  std::vector<std::vector<std::byte>> symbol{parity.begin(), parity.end()};
  norr::FecDecoder decoder;
  const auto header = norr::parse_fec_header(symbol[0]);
  NORR_CHECK(header.has_value() && header->block_size == 1);
  const auto recovered = decoder.receive(
      *header, std::span{symbol[0]}.subspan(norr::kFecHeaderSize), std::chrono::steady_clock::now());
  NORR_CHECK(recovered.size() == 1 && recovered.front() == packet);
  NORR_CHECK(first.block_id != header->block_id);
  std::puts("fec: a short block sends only the parity it needs OK");
}

void test_adaptive_controller() {
  const auto start = std::chrono::steady_clock::now();
  const auto report = [](double raw, double residual, bool congested = false) {
    return norr::FecLossReport{.raw = raw, .residual = residual, .packets_per_second = 50000.0,
                               .congested = congested};
  };

  norr::AdaptiveFec controller;
  const norr::FecPlan off{};
  NORR_CHECK(!controller.decide(off, report(0.0, 0.0), start).has_value());
  NORR_CHECK(!controller.decide(off, report(0.02, 0.02), start).has_value());
  NORR_CHECK(!controller.decide(off, report(0.02, 0.02), start).has_value());
  const auto on = controller.decide(off, report(0.02, 0.02), start);
  NORR_CHECK(on.has_value() && on->active());

  NORR_CHECK(!controller.decide(*on, report(0.02, 0.0005), start).has_value());
  bool disabled = false;
  auto current = *on;
  for (std::uint32_t index = 1; index < norr::AdaptiveFec::kCalmBeforeDisable + 8; ++index) {
    const auto next = controller.decide(current, report(0.0, 0.0), start);
    if (!next.has_value()) continue;
    if (!next->active()) {
      disabled = true;
      break;
    }
    NORR_CHECK(next->parity <= current.parity);
    current = *next;
  }
  NORR_CHECK(disabled);

  norr::AdaptiveFec congested;
  for (int index = 0; index < 10; ++index) {
    NORR_CHECK(!congested.decide(off, report(0.05, 0.05, true), start).has_value());
  }

  norr::AdaptiveFec useless;
  const norr::FecPlan plan{.data = 32, .parity = 3, .lanes = 1, .loss = 0.01};
  std::optional<norr::FecPlan> outcome;
  for (int index = 0; index < 3; ++index) outcome = useless.decide(plan, report(0.01, 0.009), start);
  NORR_CHECK(outcome.has_value() && !outcome->active());
  NORR_CHECK(!useless.decide(off, report(0.2, 0.2), start + std::chrono::seconds{10}).has_value());
  static_cast<void>(useless.decide(off, report(0.2, 0.2), start + std::chrono::seconds{31}));
  static_cast<void>(useless.decide(off, report(0.2, 0.2), start + std::chrono::seconds{32}));
  const auto back = useless.decide(off, report(0.2, 0.2), start + std::chrono::seconds{33});
  NORR_CHECK(back.has_value() && back->active());
  for (int index = 0; index < 3; ++index) {
    outcome = useless.decide(*back, report(0.01, 0.009), start + std::chrono::seconds{34});
  }
  NORR_CHECK(outcome.has_value() && !outcome->active());
  for (int index = 0; index < 3; ++index) {
    NORR_CHECK(!useless.decide(off, report(0.2, 0.2), start + std::chrono::seconds{80}).has_value());
  }
  std::puts("fec: controller enables on steady loss, ignores congestion, backs off when useless OK");
}
}

int main() {
  test_field_arithmetic();
  test_modes();
  test_header_roundtrip();
  test_recovers_up_to_parity_count();
  test_mixed_data_and_parity_loss();
  test_too_many_losses();
  test_short_flushed_block();
  test_randomised_recovery();
  test_duplicates_and_late_symbols();
  test_bounds_and_expiry();
  test_forged_parity_cannot_crash();
  test_interleaved_burst();
  test_partial_flush_trims_parity();
  test_adaptive_controller();
  return 0;
}
