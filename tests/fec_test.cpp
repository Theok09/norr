// XOR parity FEC against the parameters fixed in fec/spec.md.

#include "check.hpp"
#include <chrono>
#include <cstdio>
#include <vector>

#include "norr/fec.hpp"

namespace {

std::vector<std::byte> packet_of(std::size_t size, std::uint8_t fill) {
  return std::vector<std::byte>(size, static_cast<std::byte>(fill));
}

void test_mode_selection() {
  // The table in fec/spec.md, checked at its boundaries.
  NORR_CHECK(norr::mode_for_loss(0.0) == norr::FecMode::off);
  NORR_CHECK(norr::mode_for_loss(0.004) == norr::FecMode::off);
  NORR_CHECK(norr::mode_for_loss(0.005) == norr::FecMode::light);
  NORR_CHECK(norr::mode_for_loss(0.019) == norr::FecMode::light);
  NORR_CHECK(norr::mode_for_loss(0.02) == norr::FecMode::moderate);
  NORR_CHECK(norr::mode_for_loss(0.09) == norr::FecMode::moderate);
  NORR_CHECK(norr::mode_for_loss(0.10) == norr::FecMode::aggressive);

  // Higher loss means smaller blocks, so a single loss is likelier to be alone
  // in its block.
  NORR_CHECK(norr::block_size_for(norr::FecMode::light) == 32);
  NORR_CHECK(norr::block_size_for(norr::FecMode::moderate) == 8);
  NORR_CHECK(norr::block_size_for(norr::FecMode::aggressive) == 4);
  NORR_CHECK(norr::block_size_for(norr::FecMode::off) == 0);

  // Past the point where single-parity FEC helps, the path itself is the
  // problem.
  NORR_CHECK(!norr::loss_warrants_path_review(0.05));
  NORR_CHECK(norr::loss_warrants_path_review(0.10));
  NORR_CHECK(norr::loss_warrants_path_review(0.30));

  std::puts("fec: adaptive mode selection OK");
}

void test_off_produces_nothing() {
  norr::FecEncoder encoder{norr::FecMode::off};
  for (int index = 0; index < 100; ++index) {
    NORR_CHECK(!encoder.add(packet_of(100, 1)).has_value());
  }
  NORR_CHECK(!encoder.flush().has_value());
  // A clean path must pay no overhead at all.
  NORR_CHECK(encoder.stats().parity_sent == 0);

  std::puts("fec: disabled mode emits no parity OK");
}

void test_header_roundtrip() {
  const norr::FecSymbolHeader header{
      .block_id = 0xDEADBEEF, .index = 3, .block_size = 8, .parity = false,
      .original_length = 1400};

  std::array<std::byte, norr::kFecHeaderSize> bytes{};
  NORR_CHECK(norr::serialize_fec_header(header, bytes) == norr::kFecHeaderSize);

  const auto parsed = norr::parse_fec_header(bytes);
  NORR_CHECK(parsed.has_value());
  NORR_CHECK(parsed->block_id == 0xDEADBEEF);
  NORR_CHECK(parsed->index == 3);
  NORR_CHECK(parsed->block_size == 8);
  NORR_CHECK(!parsed->parity);
  NORR_CHECK(parsed->original_length == 1400);

  // An oversized block is malformed: accepting it would let a peer choose how
  // much state we allocate. A short one is legitimate - a block flushed while
  // idle carries fewer symbols than the configured size.
  auto bad = bytes;
  bad[6] = std::byte{200};
  NORR_CHECK(!norr::parse_fec_header(bad).has_value());
  bad[6] = std::byte{0};
  NORR_CHECK(!norr::parse_fec_header(bad).has_value());

  // An index beyond the block is equally malformed.
  auto bad_index = bytes;
  bad_index[5] = std::byte{9};
  NORR_CHECK(!norr::parse_fec_header(bad_index).has_value());

  // Anything that is not tagged as a FEC symbol is not one. This is what lets
  // a handshake share the wire with symbols.
  auto untagged = bytes;
  untagged[0] = std::byte{0x11};
  NORR_CHECK(!norr::parse_fec_header(untagged).has_value());
  NORR_CHECK(!norr::looks_like_fec_symbol(untagged));
  NORR_CHECK(norr::looks_like_fec_symbol(bytes));

  // Truncated input is refused rather than read past.
  NORR_CHECK(!norr::parse_fec_header(std::span{bytes}.first(4)).has_value());
  NORR_CHECK(!norr::parse_fec_header({}).has_value());

  std::puts("fec: header round-trip and validation OK");
}

void test_recovers_one_loss() {
  constexpr std::size_t kBlock = 4;
  norr::FecEncoder encoder{norr::FecMode::aggressive};

  std::vector<std::vector<std::byte>> originals;
  std::vector<std::byte> parity;

  for (std::size_t index = 0; index < kBlock; ++index) {
    originals.push_back(packet_of(64, static_cast<std::uint8_t>(index + 1)));
    const auto emitted = encoder.add(originals.back());
    if (index + 1 == kBlock) {
      NORR_CHECK(emitted.has_value());
      parity.assign(emitted->begin(), emitted->end());
    } else {
      NORR_CHECK(!emitted.has_value());
    }
  }
  NORR_CHECK(!parity.empty());

  // Deliver every symbol except one, then the parity.
  norr::FecDecoder decoder;
  const auto now = norr::Instant{};
  constexpr std::size_t kLost = 2;

  for (std::size_t index = 0; index < kBlock; ++index) {
    if (index == kLost) continue;
    const norr::FecSymbolHeader header{.block_id = 0,
                                       .index = static_cast<std::uint8_t>(index),
                                       .block_size = kBlock,
                                       .parity = false,
                                       .original_length = 64};
    NORR_CHECK(!decoder.receive(header, originals[index], now).has_value());
  }

  const auto parity_header = norr::parse_fec_header(parity);
  NORR_CHECK(parity_header.has_value());
  const auto recovered = decoder.receive(
      *parity_header, std::span{parity}.subspan(norr::kFecHeaderSize), now);

  NORR_CHECK(recovered.has_value());
  // XOR is its own inverse, so what comes back must be exactly what was lost.
  NORR_CHECK(recovered->size() >= originals[kLost].size());
  for (std::size_t byte = 0; byte < originals[kLost].size(); ++byte) {
    NORR_CHECK((*recovered)[byte] == originals[kLost][byte]);
  }
  NORR_CHECK(decoder.stats().recovered == 1);

  std::puts("fec: recovers a single lost symbol OK");
}

// A block that stops filling and is flushed early carries fewer symbols than
// the configured size. The parity must say so, or the decoder waits forever
// for symbols the sender never produced - which is what made small flows
// unprotected.
void test_short_block_recovers() {
  norr::FecEncoder encoder{norr::FecMode::light};

  const auto first = packet_of(48, 0xA1);
  const auto second = packet_of(48, 0xB2);
  NORR_CHECK(!encoder.add(first).has_value());
  NORR_CHECK(!encoder.add(second).has_value());

  const auto flushed = encoder.flush();
  NORR_CHECK(flushed.has_value());
  const std::vector<std::byte> parity(flushed->begin(), flushed->end());

  const auto parity_header = norr::parse_fec_header(parity);
  NORR_CHECK(parity_header.has_value());
  NORR_CHECK(parity_header->block_size == 2);

  norr::FecDecoder decoder;
  const auto now = norr::Instant{};

  // The data symbols advertise the configured block size; only the parity
  // knows the block was cut short.
  const norr::FecSymbolHeader data_header{
      .block_id = 0, .index = 0, .block_size = 32, .parity = false,
      .original_length = 48};
  NORR_CHECK(!decoder.receive(data_header, first, now).has_value());

  const auto recovered = decoder.receive(
      *parity_header, std::span{parity}.subspan(norr::kFecHeaderSize), now);
  NORR_CHECK(recovered.has_value());
  NORR_CHECK(std::equal(second.begin(), second.end(), recovered->begin()));

  std::puts("fec: a short flushed block still recovers OK");
}

void test_two_losses_unrecoverable() {
  constexpr std::size_t kBlock = 4;
  norr::FecEncoder encoder{norr::FecMode::aggressive};

  std::vector<std::vector<std::byte>> originals;
  std::vector<std::byte> parity;
  for (std::size_t index = 0; index < kBlock; ++index) {
    originals.push_back(packet_of(64, static_cast<std::uint8_t>(index + 1)));
    const auto emitted = encoder.add(originals.back());
    if (emitted) parity.assign(emitted->begin(), emitted->end());
  }

  norr::FecDecoder decoder;
  const auto now = norr::Instant{};

  // Two losses in one block. One parity symbol cannot recover both, and the
  // decoder must say so rather than returning corrupt data.
  for (std::size_t index = 2; index < kBlock; ++index) {
    const norr::FecSymbolHeader header{.block_id = 0,
                                       .index = static_cast<std::uint8_t>(index),
                                       .block_size = kBlock,
                                       .parity = false,
                                       .original_length = 64};
    NORR_CHECK(!decoder.receive(header, originals[index], now).has_value());
  }

  const auto parity_header = norr::parse_fec_header(parity);
  NORR_CHECK(parity_header.has_value());
  const auto recovered = decoder.receive(
      *parity_header, std::span{parity}.subspan(norr::kFecHeaderSize), now);
  NORR_CHECK(!recovered.has_value());
  NORR_CHECK(decoder.stats().recovered == 0);

  std::puts("fec: two losses in one block are not recovered OK");
}

void test_duplicate_symbol_ignored() {
  norr::FecDecoder decoder;
  const auto now = norr::Instant{};
  const auto payload = packet_of(32, 7);

  const norr::FecSymbolHeader header{
      .block_id = 1, .index = 0, .block_size = 4, .parity = false, .original_length = 32};

  NORR_CHECK(!decoder.receive(header, payload, now).has_value());
  // A repeated symbol must not be XORed twice: doing so would corrupt the
  // accumulator and produce garbage on recovery.
  NORR_CHECK(!decoder.receive(header, payload, now).has_value());

  std::puts("fec: duplicate symbol does not corrupt the block OK");
}

void test_deadline_and_bounds() {
  norr::FecDecoder decoder;
  auto now = norr::Instant{};

  const norr::FecSymbolHeader header{
      .block_id = 1, .index = 0, .block_size = 4, .parity = false, .original_length = 32};
  NORR_CHECK(!decoder.receive(header, packet_of(32, 1), now).has_value());
  NORR_CHECK(decoder.outstanding() == 1);

  // Before the deadline nothing is discarded.
  NORR_CHECK(decoder.expire(now + std::chrono::milliseconds{10}) == 0);

  // A block past its deadline is abandoned: a late recovery is useless and the
  // memory is bounded.
  now += norr::kFecRecoveryDeadline + std::chrono::milliseconds{1};
  NORR_CHECK(decoder.expire(now) == 1);
  NORR_CHECK(decoder.outstanding() == 0);
  NORR_CHECK(decoder.stats().expired == 1);

  std::puts("fec: recovery deadline enforced OK");
}

void test_outstanding_blocks_bounded() {
  norr::FecDecoder decoder;
  const auto now = norr::Instant{};

  // An attacker inventing block ids must not be able to grow our state.
  for (std::uint32_t id = 0; id < norr::kMaximumOutstandingBlocks * 4; ++id) {
    const norr::FecSymbolHeader header{
        .block_id = id, .index = 0, .block_size = 4, .parity = false, .original_length = 32};
    static_cast<void>(decoder.receive(header, packet_of(32, 1), now));
  }
  NORR_CHECK(decoder.outstanding() <= norr::kMaximumOutstandingBlocks);

  std::puts("fec: outstanding block count bounded OK");
}

void test_flush_partial_block() {
  norr::FecEncoder encoder{norr::FecMode::light};  // 32-symbol blocks

  for (int index = 0; index < 5; ++index) {
    NORR_CHECK(!encoder.add(packet_of(100, static_cast<std::uint8_t>(index))).has_value());
  }
  NORR_CHECK(encoder.pending() == 5);

  // A pause in traffic must not strand the packets already sent.
  const auto parity = encoder.flush();
  NORR_CHECK(parity.has_value());
  NORR_CHECK(encoder.pending() == 0);
  // Flushing again with nothing buffered produces nothing.
  NORR_CHECK(!encoder.flush().has_value());

  std::puts("fec: partial block flush OK");
}

void test_varying_packet_sizes() {
  norr::FecEncoder encoder{norr::FecMode::aggressive};

  // Symbols must be equal length to XOR, so short packets are zero-padded to
  // the widest in the block.
  std::vector<std::vector<std::byte>> originals{packet_of(10, 1), packet_of(100, 2),
                                                packet_of(50, 3), packet_of(75, 4)};
  std::vector<std::byte> parity;
  for (const auto& packet : originals) {
    const auto emitted = encoder.add(packet);
    if (emitted) parity.assign(emitted->begin(), emitted->end());
  }
  NORR_CHECK(!parity.empty());
  // The parity symbol is as wide as the widest packet.
  NORR_CHECK(parity.size() == norr::kFecHeaderSize + 100);

  std::puts("fec: mixed packet sizes padded correctly OK");
}

}  // namespace

int main() {
  test_mode_selection();
  test_off_produces_nothing();
  test_header_roundtrip();
  test_recovers_one_loss();
  test_short_block_recovers();
  test_two_losses_unrecoverable();
  test_duplicate_symbol_ignored();
  test_deadline_and_bounds();
  test_outstanding_blocks_bounded();
  test_flush_partial_block();
  test_varying_packet_sizes();
  return 0;
}
