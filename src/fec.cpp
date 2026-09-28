// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#include "norr/fec.hpp"

#include <algorithm>
#include <cmath>
#include <cstring>

#if defined(__x86_64__) || defined(__i386__)
#include <immintrin.h>
#define NORR_FEC_X86 1
#elif defined(__aarch64__)
#include <arm_neon.h>
#define NORR_FEC_NEON 1
#endif

namespace norr {
namespace {
struct Tables {
  std::array<std::uint8_t, 512> exp{};
  std::array<std::uint8_t, 256> log{};
  std::array<std::array<std::uint8_t, 256>, 256> product{};
  std::array<std::array<std::uint8_t, 32>, 256> nibbles{};

  Tables() noexcept {
    unsigned value = 1;
    for (std::size_t index = 0; index < 255; ++index) {
      exp[index] = static_cast<std::uint8_t>(value);
      log[value] = static_cast<std::uint8_t>(index);
      value <<= 1U;
      if ((value & 0x100U) != 0U) value ^= 0x11DU;
    }
    for (std::size_t index = 255; index < exp.size(); ++index) exp[index] = exp[index - 255];
    for (std::size_t left = 1; left < 256; ++left) {
      for (std::size_t right = 1; right < 256; ++right) {
        product[left][right] = exp[static_cast<std::size_t>(log[left]) + log[right]];
      }
    }
    for (std::size_t coefficient = 0; coefficient < 256; ++coefficient) {
      for (std::size_t nibble = 0; nibble < 16; ++nibble) {
        nibbles[coefficient][nibble] = product[coefficient][nibble];
        nibbles[coefficient][16 + nibble] = product[coefficient][nibble << 4U];
      }
    }
  }
};

const Tables& tables() noexcept {
  static const Tables instance;
  return instance;
}

constexpr void write_u32(std::span<std::byte> out, std::size_t offset,
                         std::uint32_t value) noexcept {
  out[offset] = static_cast<std::byte>((value >> 24U) & 0xFFU);
  out[offset + 1] = static_cast<std::byte>((value >> 16U) & 0xFFU);
  out[offset + 2] = static_cast<std::byte>((value >> 8U) & 0xFFU);
  out[offset + 3] = static_cast<std::byte>(value & 0xFFU);
}

[[nodiscard]] constexpr std::uint32_t read_u32(std::span<const std::byte> bytes,
                                               std::size_t offset) noexcept {
  return (static_cast<std::uint32_t>(bytes[offset]) << 24U) |
         (static_cast<std::uint32_t>(bytes[offset + 1]) << 16U) |
         (static_cast<std::uint32_t>(bytes[offset + 2]) << 8U) |
         static_cast<std::uint32_t>(bytes[offset + 3]);
}

#if defined(NORR_FEC_X86)
__attribute__((target("avx2"))) std::size_t multiply_add_avx2(std::byte* accumulator,
                                                              const std::byte* source,
                                                              std::size_t length,
                                                              const std::uint8_t* table) noexcept {
  const auto low_table = _mm256_broadcastsi128_si256(
      _mm_loadu_si128(reinterpret_cast<const __m128i*>(table)));
  const auto high_table = _mm256_broadcastsi128_si256(
      _mm_loadu_si128(reinterpret_cast<const __m128i*>(table + 16)));
  const auto mask = _mm256_set1_epi8(0x0F);
  std::size_t index = 0;
  for (; index + 32 <= length; index += 32) {
    const auto input = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(source + index));
    const auto low = _mm256_shuffle_epi8(low_table, _mm256_and_si256(input, mask));
    const auto high =
        _mm256_shuffle_epi8(high_table, _mm256_and_si256(_mm256_srli_epi64(input, 4), mask));
    auto* target = reinterpret_cast<__m256i*>(accumulator + index);
    _mm256_storeu_si256(target, _mm256_xor_si256(_mm256_loadu_si256(target),
                                                 _mm256_xor_si256(low, high)));
  }
  return index;
}

[[nodiscard]] bool has_avx2() noexcept {
  static const bool supported = __builtin_cpu_supports("avx2");
  return supported;
}
#endif

#if defined(NORR_FEC_NEON)
std::size_t multiply_add_neon(std::byte* accumulator, const std::byte* source, std::size_t length,
                              const std::uint8_t* table) noexcept {
  const auto low_table = vld1q_u8(table);
  const auto high_table = vld1q_u8(table + 16);
  const auto mask = vdupq_n_u8(0x0F);
  std::size_t index = 0;
  for (; index + 16 <= length; index += 16) {
    auto* target = reinterpret_cast<std::uint8_t*>(accumulator + index);
    const auto input = vld1q_u8(reinterpret_cast<const std::uint8_t*>(source + index));
    const auto low = vqtbl1q_u8(low_table, vandq_u8(input, mask));
    const auto high = vqtbl1q_u8(high_table, vshrq_n_u8(input, 4));
    vst1q_u8(target, veorq_u8(vld1q_u8(target), veorq_u8(low, high)));
  }
  return index;
}
#endif

void scale(std::span<std::byte> row, std::uint8_t coefficient) noexcept {
  const auto& table = tables().product[coefficient];
  for (auto& octet : row) octet = static_cast<std::byte>(table[static_cast<std::uint8_t>(octet)]);
}
}

namespace gf256 {
std::uint8_t multiply(std::uint8_t left, std::uint8_t right) noexcept {
  return tables().product[left][right];
}

std::uint8_t inverse(std::uint8_t value) noexcept {
  if (value == 0) return 0;
  const auto& table = tables();
  return table.exp[255U - table.log[value]];
}

std::uint8_t cauchy(std::size_t parity_row, std::size_t data_column) noexcept {
  const auto x = static_cast<std::uint8_t>(kMaximumFecData + parity_row);
  const auto y = static_cast<std::uint8_t>(data_column);
  return inverse(static_cast<std::uint8_t>(x ^ y));
}

void multiply_add(std::span<std::byte> accumulator, std::span<const std::byte> source,
                  std::uint8_t coefficient) noexcept {
  const auto length = std::min(accumulator.size(), source.size());
  if (coefficient == 0) return;
  if (coefficient == 1) {
    for (std::size_t index = 0; index < length; ++index) accumulator[index] ^= source[index];
    return;
  }
  std::size_t index = 0;
#if defined(NORR_FEC_X86)
  if (has_avx2()) {
    index = multiply_add_avx2(accumulator.data(), source.data(), length,
                              tables().nibbles[coefficient].data());
  }
#elif defined(NORR_FEC_NEON)
  index = multiply_add_neon(accumulator.data(), source.data(), length,
                            tables().nibbles[coefficient].data());
#endif
  const auto& table = tables().product[coefficient];
  for (; index < length; ++index) {
    accumulator[index] ^= static_cast<std::byte>(table[static_cast<std::uint8_t>(source[index])]);
  }
}
}

std::size_t parity_needed(std::size_t data, double loss, std::size_t limit) noexcept {
  if (data == 0 || limit == 0) return 0;
  const auto p = std::clamp(loss, 0.0, 0.5);
  if (p <= 0.0) return limit;
  const auto odds = p / (1.0 - p);
  for (std::size_t rows = 1; rows < limit; ++rows) {
    const auto total = data + rows;
    auto term = std::pow(1.0 - p, static_cast<double>(total));
    auto covered = term;
    for (std::size_t lost = 0; lost < rows; ++lost) {
      term *= static_cast<double>(total - lost) / static_cast<double>(lost + 1) * odds;
      covered += term;
    }
    if (1.0 - covered <= kFecTargetBlockFailure) return rows;
  }
  return limit;
}

FecPlan plan_for_loss(double loss, double packets_per_second) noexcept {
  const auto design = std::min(0.4, loss * 1.5 + 0.002);
  const auto per_flush = std::max(0.0, packets_per_second) *
                         std::chrono::duration<double>(kFecFlushInterval).count();
  std::size_t data = 32;
  std::size_t lanes = 1;
  if (per_flush >= 64.0) {
    lanes = std::clamp<std::size_t>(static_cast<std::size_t>(per_flush / 32.0), 1, kMaximumFecLanes);
  } else {
    data = std::clamp<std::size_t>(static_cast<std::size_t>(per_flush), 4, 32);
  }
  if (design >= 0.08) data = std::min<std::size_t>(data, 16);
  return FecPlan{.data = data,
                 .parity = parity_needed(data, design, kMaximumFecParity),
                 .lanes = lanes,
                 .loss = design};
}

std::optional<FecPlan> AdaptiveFec::decide(const FecPlan& current, const FecLossReport& report,
                                           Instant now) noexcept {
  if (report.congested) {
    lossy_reports_ = 0;
    return std::nullopt;
  }

  const auto raw = std::clamp(report.raw, 0.0, 1.0);
  smoothed_ = raw >= smoothed_ ? raw : 0.6 * smoothed_ + 0.4 * raw;

  if (now < suppressed_until_) {
    lossy_reports_ = 0;
    if (current.active()) return FecPlan{};
    return std::nullopt;
  }

  if (!current.active()) {
    calm_reports_ = 0;
    ineffective_reports_ = 0;
    if (smoothed_ < kEnableLoss) {
      lossy_reports_ = 0;
      return std::nullopt;
    }
    if (++lossy_reports_ < kReportsBeforeEnable) return std::nullopt;
    lossy_reports_ = 0;
    return plan_for_loss(smoothed_, report.packets_per_second);
  }

  if (raw >= 0.002) {
    const auto recovered_share = (raw - std::clamp(report.residual, 0.0, raw)) / raw;
    if (recovered_share < kMinimumRecoveredShare) {
      if (++ineffective_reports_ >= kIneffectiveBeforeSuppress) {
        ineffective_reports_ = 0;
        calm_reports_ = 0;
        suppressed_until_ = now + suppression_;
        suppression_ = std::min<Duration>(suppression_ * 2, kMaximumSuppression);
        return FecPlan{};
      }
    } else {
      ineffective_reports_ = 0;
      suppression_ = kSuppression;
    }
  }

  if (smoothed_ < kDisableLoss) {
    if (++calm_reports_ < kCalmBeforeDisable) return std::nullopt;
    calm_reports_ = 0;
    return FecPlan{};
  }
  calm_reports_ = 0;

  const auto wanted = plan_for_loss(smoothed_, report.packets_per_second);
  const auto distance = [](std::size_t left, std::size_t right) {
    return left > right ? left - right : right - left;
  };
  const bool settled = wanted.lanes == current.lanes && distance(wanted.parity, current.parity) < 2 &&
                       distance(wanted.data, current.data) * 4 <= current.data;
  if (settled) return std::nullopt;
  return wanted;
}

std::size_t serialize_fec_header(const FecSymbolHeader& header, std::span<std::byte> out) noexcept {
  if (out.size() < kFecHeaderSize) return 0;
  out[0] = kFecTag;
  write_u32(out, 1, header.block_id);
  out[5] = static_cast<std::byte>(header.index);
  out[6] = static_cast<std::byte>(header.block_size);
  out[7] = static_cast<std::byte>(header.parity_count);
  out[8] = static_cast<std::byte>(header.parity ? 1 : 0);
  out[9] = static_cast<std::byte>((header.original_length >> 8U) & 0xFFU);
  out[10] = static_cast<std::byte>(header.original_length & 0xFFU);
  return kFecHeaderSize;
}

std::optional<FecSymbolHeader> parse_fec_header(std::span<const std::byte> bytes) noexcept {
  if (bytes.size() < kFecHeaderSize) return std::nullopt;
  if (bytes[0] != kFecTag) return std::nullopt;

  const auto flags = static_cast<std::uint8_t>(bytes[8]);
  if ((flags & ~1U) != 0U) return std::nullopt;

  FecSymbolHeader header{};
  header.block_id = read_u32(bytes, 1);
  header.index = static_cast<std::uint8_t>(bytes[5]);
  header.block_size = static_cast<std::uint8_t>(bytes[6]);
  header.parity_count = static_cast<std::uint8_t>(bytes[7]);
  header.parity = (flags & 1U) != 0U;
  header.original_length = static_cast<std::uint16_t>(
      (static_cast<unsigned>(bytes[9]) << 8U) | static_cast<unsigned>(bytes[10]));

  if (header.block_size == 0 || header.block_size > kMaximumFecData) return std::nullopt;
  if (header.parity_count == 0 || header.parity_count > kMaximumFecParity) return std::nullopt;
  if (header.parity ? header.index >= header.parity_count : header.index >= header.block_size) {
    return std::nullopt;
  }
  return header;
}

void FecEncoder::configure(const FecPlan& plan) {
  plan_ = plan;
  plan_.data = std::min(plan_.data, kMaximumFecData);
  plan_.parity = std::min(plan_.parity, kMaximumFecParity);
  plan_.lanes = std::clamp<std::size_t>(plan_.lanes, 1, kMaximumFecLanes);
  if (!plan_.active()) plan_ = FecPlan{};
  cursor_ = 0;
  output_count_ = 0;
  for (auto& lane : lanes_) {
    lane.index = 0;
    lane.width = 0;
    lane.parity.resize(plan_.parity);
    for (auto& row : lane.parity) row.clear();
    lane.block_id = next_block_++;
  }
}

void FecEncoder::resume_at(std::uint32_t block_id) noexcept {
  next_block_ = block_id;
  for (auto& lane : lanes_) {
    if (lane.index == 0) lane.block_id = next_block_++;
  }
}

std::size_t FecEncoder::pending() const noexcept {
  std::size_t total = 0;
  for (std::size_t index = 0; index < plan_.lanes; ++index) total += lanes_[index].index;
  return total;
}

FecSymbolHeader FecEncoder::next_header(std::size_t sealed_length) const noexcept {
  const auto& lane = lanes_[cursor_];
  return FecSymbolHeader{.block_id = lane.block_id,
                         .index = static_cast<std::uint8_t>(lane.index),
                         .block_size = static_cast<std::uint8_t>(plan_.data),
                         .parity_count = static_cast<std::uint8_t>(plan_.parity),
                         .parity = false,
                         .original_length = static_cast<std::uint16_t>(sealed_length)};
}

std::span<const std::vector<std::byte>> FecEncoder::add(std::span<const std::byte> packet) {
  output_count_ = 0;
  if (!plan_.active() || packet.size() > 0xFFFFU) return {};

  auto& lane = lanes_[cursor_];
  cursor_ = (cursor_ + 1) % plan_.lanes;

  const auto length = kFecLengthPrefix + packet.size();
  if (length > lane.width) {
    lane.width = length;
    for (auto& row : lane.parity) row.resize(lane.width, std::byte{0});
  }
  symbol_.resize(length);
  symbol_[0] = static_cast<std::byte>((packet.size() >> 8U) & 0xFFU);
  symbol_[1] = static_cast<std::byte>(packet.size() & 0xFFU);
  std::copy(packet.begin(), packet.end(), symbol_.begin() + kFecLengthPrefix);
  for (std::size_t row = 0; row < plan_.parity; ++row) {
    gf256::multiply_add(lane.parity[row], symbol_, gf256::cauchy(row, lane.index));
  }

  ++lane.index;
  if (lane.index >= plan_.data) emit(lane, plan_.parity);
  return std::span{output_}.first(output_count_);
}

std::span<const std::vector<std::byte>> FecEncoder::flush() {
  output_count_ = 0;
  if (!plan_.active()) return {};
  for (std::size_t index = 0; index < plan_.lanes; ++index) {
    auto& lane = lanes_[index];
    if (lane.index == 0) continue;
    const auto rows = plan_.loss > 0.0 ? parity_needed(lane.index, plan_.loss, plan_.parity)
                                       : plan_.parity;
    emit(lane, rows);
  }
  cursor_ = 0;
  return std::span{output_}.first(output_count_);
}

void FecEncoder::emit(Lane& lane, std::size_t rows) {
  if (output_.size() < output_count_ + rows) output_.resize(output_count_ + rows);
  for (std::size_t row = 0; row < rows; ++row) {
    const FecSymbolHeader header{.block_id = lane.block_id,
                                 .index = static_cast<std::uint8_t>(row),
                                 .block_size = static_cast<std::uint8_t>(lane.index),
                                 .parity_count = static_cast<std::uint8_t>(plan_.parity),
                                 .parity = true,
                                 .original_length = static_cast<std::uint16_t>(lane.width)};
    auto& symbol = output_[output_count_++];
    symbol.resize(kFecHeaderSize + lane.width);
    static_cast<void>(serialize_fec_header(header, symbol));
    std::copy(lane.parity[row].begin(), lane.parity[row].end(),
              symbol.begin() + static_cast<std::ptrdiff_t>(kFecHeaderSize));
  }
  for (auto& row : lane.parity) row.clear();
  lane.block_id = next_block_++;
  lane.index = 0;
  lane.width = 0;
  ++stats_.blocks_encoded;
  stats_.parity_sent += rows;
}

bool FecDecoder::recently_finished(std::uint32_t id) const noexcept {
  return std::ranges::find(finished_, id) != finished_.end();
}

std::vector<std::byte> FecDecoder::take_buffer() {
  if (spare_.empty()) return {};
  auto buffer = std::move(spare_.back());
  spare_.pop_back();
  buffer.clear();
  return buffer;
}

void FecDecoder::recycle(Block& block) {
  const auto keep = [&](std::vector<std::byte>& buffer) {
    if (buffer.capacity() == 0 || spare_.size() >= kMaximumFecData * 8) return;
    spare_.push_back(std::move(buffer));
  };
  for (auto& buffer : block.data) keep(buffer);
  for (auto& buffer : block.parity) keep(buffer);
}

void FecDecoder::finish(std::uint32_t id) {
  for (auto& block : blocks_) {
    if (block.id == id) recycle(block);
  }
  std::erase_if(blocks_, [id](const Block& block) { return block.id == id; });
  finished_.push_back(id);
  while (finished_.size() > kMaximumOutstandingBlocks * 2) finished_.pop_front();
}

FecDecoder::Block* FecDecoder::find_or_create(const FecSymbolHeader& header, Instant now) {
  for (auto& block : blocks_) {
    if (block.id == header.block_id) return &block;
  }

  if (blocks_.size() >= kMaximumOutstandingBlocks) {
    ++stats_.unrecoverable;
    recycle(blocks_.front());
    blocks_.pop_front();
  }

  Block block{};
  block.id = header.block_id;
  block.data_count = header.block_size;
  block.parity_count = header.parity_count;
  block.data.resize(header.block_size);
  block.parity.resize(header.parity_count);
  block.created = now;
  blocks_.push_back(std::move(block));
  return &blocks_.back();
}

std::vector<std::vector<std::byte>> FecDecoder::receive(const FecSymbolHeader& header,
                                                        std::span<const std::byte> payload,
                                                        Instant now) {
  ++stats_.symbols_received;
  if (recently_finished(header.block_id)) return {};

  auto* block = find_or_create(header, now);
  if (block->parity_count != header.parity_count) return {};

  if (header.parity) {
    if (header.block_size < block->data_count) {
      for (std::size_t index = header.block_size; index < block->data_count; ++index) {
        if (!block->data[index].empty()) --block->data_received;
      }
      block->data_count = header.block_size;
      block->data.resize(header.block_size);
    }
    auto& slot = block->parity[header.index];
    if (!slot.empty()) return {};
    slot = take_buffer();
    slot.assign(payload.begin(), payload.end());
  } else {
    if (header.index >= block->data_count) return {};
    auto& slot = block->data[header.index];
    if (!slot.empty()) return {};
    slot = take_buffer();
    slot.resize(kFecLengthPrefix + payload.size());
    slot[0] = static_cast<std::byte>((payload.size() >> 8U) & 0xFFU);
    slot[1] = static_cast<std::byte>(payload.size() & 0xFFU);
    std::copy(payload.begin(), payload.end(), slot.begin() + kFecLengthPrefix);
    ++block->data_received;
  }

  if (block->data_received == block->data_count) {
    finish(block->id);
    return {};
  }
  return try_recover(*block);
}

std::vector<std::vector<std::byte>> FecDecoder::try_recover(Block& block) {
  std::vector<std::size_t> missing;
  for (std::size_t index = 0; index < block.data_count; ++index) {
    if (block.data[index].empty()) missing.push_back(index);
  }
  std::vector<std::size_t> rows;
  for (std::size_t index = 0; index < block.parity_count; ++index) {
    if (!block.parity[index].empty()) rows.push_back(index);
  }
  if (missing.empty() || rows.size() < missing.size()) return {};
  rows.resize(missing.size());

  const auto width = block.parity[rows.front()].size();
  for (const auto row : rows) {
    if (block.parity[row].size() != width) return {};
  }
  for (const auto& symbol : block.data) {
    if (symbol.size() > width) return {};
  }

  const auto count = missing.size();
  std::vector<std::vector<std::byte>> syndrome(count);
  if (count > kMaximumFecParity) return {};
  std::array<std::array<std::uint8_t, kMaximumFecParity>, kMaximumFecParity> matrix{};
  for (std::size_t r = 0; r < count; ++r) {
    syndrome[r] = block.parity[rows[r]];
    for (std::size_t index = 0; index < block.data_count; ++index) {
      if (block.data[index].empty()) continue;
      gf256::multiply_add(syndrome[r], block.data[index], gf256::cauchy(rows[r], index));
    }
    for (std::size_t c = 0; c < count; ++c) matrix[r][c] = gf256::cauchy(rows[r], missing[c]);
  }

  for (std::size_t column = 0; column < count; ++column) {
    std::size_t pivot = column;
    while (pivot < count && matrix[pivot][column] == 0) ++pivot;
    if (pivot == count) return {};
    std::swap(matrix[pivot], matrix[column]);
    std::swap(syndrome[pivot], syndrome[column]);

    const auto factor = gf256::inverse(matrix[column][column]);
    for (auto& value : matrix[column]) value = gf256::multiply(value, factor);
    scale(syndrome[column], factor);

    for (std::size_t r = 0; r < count; ++r) {
      if (r == column || matrix[r][column] == 0) continue;
      const auto coefficient = matrix[r][column];
      for (std::size_t c = 0; c < count; ++c) {
        matrix[r][c] ^= gf256::multiply(coefficient, matrix[column][c]);
      }
      gf256::multiply_add(syndrome[r], syndrome[column], coefficient);
    }
  }

  std::vector<std::vector<std::byte>> recovered;
  recovered.reserve(count);
  for (std::size_t c = 0; c < count; ++c) {
    const auto& symbol = syndrome[c];
    if (symbol.size() < kFecLengthPrefix) continue;
    const auto length = (static_cast<std::size_t>(symbol[0]) << 8U) |
                        static_cast<std::size_t>(symbol[1]);
    if (length == 0 || kFecLengthPrefix + length > symbol.size()) {
      ++stats_.unrecoverable;
      continue;
    }
    recovered.emplace_back(symbol.begin() + static_cast<std::ptrdiff_t>(kFecLengthPrefix),
                           symbol.begin() + static_cast<std::ptrdiff_t>(kFecLengthPrefix + length));
    ++stats_.recovered;
  }

  finish(block.id);
  return recovered;
}

std::size_t FecDecoder::expire(Instant now) {
  std::size_t removed = 0;
  while (!blocks_.empty() && now - blocks_.front().created >= kFecRecoveryDeadline) {
    finished_.push_back(blocks_.front().id);
    recycle(blocks_.front());
    blocks_.pop_front();
    ++removed;
    ++stats_.expired;
  }
  while (finished_.size() > kMaximumOutstandingBlocks * 2) finished_.pop_front();
  return removed;
}
}
