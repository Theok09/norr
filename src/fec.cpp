// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#include "norr/fec.hpp"

#include <algorithm>
#include <cstring>

namespace norr {
namespace {
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

void xor_into(std::span<std::byte> accumulator, std::span<const std::byte> symbol) noexcept {
  const auto length = std::min(accumulator.size(), symbol.size());
  for (std::size_t index = 0; index < length; ++index) {
    accumulator[index] ^= symbol[index];
  }
}

}

FecMode mode_for_loss(double loss_fraction) noexcept {
  if (loss_fraction < 0.005) return FecMode::off;
  if (loss_fraction < 0.02) return FecMode::light;
  if (loss_fraction < 0.10) return FecMode::moderate;
  return FecMode::aggressive;
}

bool loss_warrants_path_review(double loss_fraction) noexcept {
  return loss_fraction >= 0.10;
}

std::size_t serialize_fec_header(const FecSymbolHeader& header, std::span<std::byte> out) noexcept {
  if (out.size() < kFecHeaderSize) return 0;
  out[0] = kFecTag;
  write_u32(out, 1, header.block_id);
  out[5] = static_cast<std::byte>(header.index);
  out[6] = static_cast<std::byte>(header.block_size);
  out[7] = static_cast<std::byte>(header.parity ? 1 : 0);
  out[8] = static_cast<std::byte>((header.original_length >> 8U) & 0xFFU);
  out[9] = static_cast<std::byte>(header.original_length & 0xFFU);
  return kFecHeaderSize;
}

std::optional<FecSymbolHeader> parse_fec_header(std::span<const std::byte> bytes) noexcept {
  if (bytes.size() < kFecHeaderSize) return std::nullopt;
  if (bytes[0] != kFecTag) return std::nullopt;

  FecSymbolHeader header{};
  header.block_id = read_u32(bytes, 1);
  header.index = static_cast<std::uint8_t>(bytes[5]);
  header.block_size = static_cast<std::uint8_t>(bytes[6]);
  header.parity = bytes[7] != std::byte{0};
  header.original_length = static_cast<std::uint16_t>(
      (static_cast<unsigned>(bytes[8]) << 8U) | static_cast<unsigned>(bytes[9]));

  if (header.block_size == 0 || header.block_size > kMaximumFecBlock) return std::nullopt;
  if (!header.parity && header.index >= header.block_size) return std::nullopt;
  return header;
}

void FecEncoder::set_mode(FecMode mode) noexcept {
  mode_ = mode;
  block_size_ = block_size_for(mode);

  index_ = 0;
  widest_ = 0;
  parity_.clear();
}

std::optional<std::span<const std::byte>> FecEncoder::add(std::span<const std::byte> packet) {
  if (mode_ == FecMode::off || block_size_ == 0) return std::nullopt;

  if (packet.size() > widest_) {
    widest_ = packet.size();
    parity_.resize(widest_, std::byte{0});
  }
  xor_into(parity_, packet);
  ++index_;

  if (index_ < block_size_) return std::nullopt;
  return flush();
}

std::optional<std::span<const std::byte>> FecEncoder::flush() {
  if (mode_ == FecMode::off || index_ == 0) return std::nullopt;

  FecSymbolHeader header{};
  header.block_id = block_id_;
  header.index = static_cast<std::uint8_t>(index_);

  // The true symbol count, not the configured block size: a block flushed
  // early is short, and a decoder told otherwise waits for symbols that were
  // never sent.
  header.block_size = static_cast<std::uint8_t>(index_);
  header.parity = true;
  header.original_length = static_cast<std::uint16_t>(widest_);

  output_.assign(kFecHeaderSize + widest_, std::byte{0});
  static_cast<void>(serialize_fec_header(header, output_));
  std::copy(parity_.begin(), parity_.end(),
            output_.begin() + static_cast<std::ptrdiff_t>(kFecHeaderSize));

  ++block_id_;
  index_ = 0;
  widest_ = 0;
  parity_.clear();
  ++stats_.blocks_encoded;
  ++stats_.parity_sent;
  return std::span<const std::byte>{output_};
}

FecDecoder::Block* FecDecoder::find_or_create(const FecSymbolHeader& header,
                                              std::size_t symbol_size, Instant now) {
  for (auto& block : blocks_) {
    if (block.id == header.block_id) return &block;
  }

  if (blocks_.size() >= kMaximumOutstandingBlocks) {
    ++stats_.unrecoverable;
    blocks_.pop_front();
  }

  Block block{};
  block.id = header.block_id;
  block.size = header.block_size;
  block.accumulator.assign(symbol_size, std::byte{0});
  block.present.assign(header.block_size, false);
  block.lengths.assign(header.block_size, 0);
  block.created = now;
  blocks_.push_back(std::move(block));
  return &blocks_.back();
}

std::optional<std::vector<std::byte>> FecDecoder::receive(const FecSymbolHeader& header,
                                                          std::span<const std::byte> payload,
                                                          Instant now) {
  ++stats_.symbols_received;

  auto* block = find_or_create(header, std::max(payload.size(), std::size_t{1}), now);
  if (block == nullptr) return std::nullopt;

  if (block->accumulator.size() < payload.size()) {
    block->accumulator.resize(payload.size(), std::byte{0});
  }

  if (header.parity) {
    if (block->have_parity) return std::nullopt;
    block->have_parity = true;
    // Parity is authoritative on how many symbols the block actually holds:
    // a block flushed early is shorter than the configured size the data
    // symbols advertised.
    if (header.block_size < block->size) {
      block->size = header.block_size;
      block->present.resize(header.block_size);
      block->lengths.resize(header.block_size);
    }
  } else {
    if (header.index >= block->present.size()) return std::nullopt;

    if (block->present[header.index]) return std::nullopt;
    block->present[header.index] = true;
    block->lengths[header.index] = header.original_length;
    ++block->received;
  }

  xor_into(block->accumulator, payload);

  if (!block->have_parity) return std::nullopt;
  if (block->received + 1 != block->size) return std::nullopt;

  std::size_t missing = block->size;
  for (std::size_t index = 0; index < block->present.size(); ++index) {
    if (!block->present[index]) {
      missing = index;
      break;
    }
  }
  if (missing >= block->size) return std::nullopt;

  std::vector<std::byte> recovered = block->accumulator;

  const auto id = block->id;
  std::erase_if(blocks_, [id](const Block& candidate) { return candidate.id == id; });

  ++stats_.recovered;
  return recovered;
}

std::size_t FecDecoder::expire(Instant now) {
  std::size_t removed = 0;

  while (!blocks_.empty() && now - blocks_.front().created >= kFecRecoveryDeadline) {
    blocks_.pop_front();
    ++removed;
    ++stats_.expired;
  }
  return removed;
}

}
