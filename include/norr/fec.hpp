// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include "norr/packet.hpp"
#include "norr/rate_limit.hpp"

namespace norr {
inline constexpr std::size_t kMinimumFecBlock = 4;
inline constexpr std::size_t kMaximumFecBlock = 32;
inline constexpr std::size_t kMaximumOutstandingBlocks = 64;
inline constexpr auto kFecRecoveryDeadline = std::chrono::milliseconds{50};

enum class FecMode : std::uint8_t { off, light, moderate, aggressive };

[[nodiscard]] constexpr std::string_view fec_mode_name(FecMode mode) noexcept {
  switch (mode) {
    case FecMode::off: return "off";
    case FecMode::light: return "light";
    case FecMode::moderate: return "moderate";
    case FecMode::aggressive: return "aggressive";
  }
  return "unknown";
}

[[nodiscard]] constexpr std::size_t block_size_for(FecMode mode) noexcept {
  switch (mode) {
    case FecMode::off: return 0;
    case FecMode::light: return 32;
    case FecMode::moderate: return 8;
    case FecMode::aggressive: return kMinimumFecBlock;
  }
  return 0;
}

[[nodiscard]] FecMode mode_for_loss(double loss_fraction) noexcept;

[[nodiscard]] bool loss_warrants_path_review(double loss_fraction) noexcept;

struct FecStats {
  std::uint64_t blocks_encoded{};
  std::uint64_t parity_sent{};
  std::uint64_t symbols_received{};
  std::uint64_t recovered{};
  std::uint64_t unrecoverable{};
  std::uint64_t expired{};
};

struct FecSymbolHeader {
  std::uint32_t block_id{};
  std::uint8_t index{};
  std::uint8_t block_size{};
  bool parity{};
  std::uint16_t original_length{};
};

// A FEC symbol is a Norr packet whose first byte says so: version in the high
// nibble, FrameType::fec in the low one. Anything else on the wire - a
// handshake, a data packet from a peer with FEC off - parses as itself and is
// never mistaken for a symbol.
inline constexpr std::size_t kFecHeaderSize = 10;

inline constexpr std::byte kFecTag{static_cast<std::uint8_t>(
    (kProtocolVersion << 4U) | static_cast<std::uint8_t>(FrameType::fec))};

[[nodiscard]] constexpr bool looks_like_fec_symbol(std::span<const std::byte> bytes) noexcept {
  return !bytes.empty() && bytes[0] == kFecTag;
}

[[nodiscard]] std::size_t serialize_fec_header(const FecSymbolHeader& header,
                                               std::span<std::byte> out) noexcept;
[[nodiscard]] std::optional<FecSymbolHeader> parse_fec_header(
    std::span<const std::byte> bytes) noexcept;

class FecEncoder {
 public:
  explicit FecEncoder(FecMode mode = FecMode::off) noexcept { set_mode(mode); }

  void set_mode(FecMode mode) noexcept;
  [[nodiscard]] FecMode mode() const noexcept { return mode_; }

  [[nodiscard]] std::optional<std::span<const std::byte>> add(std::span<const std::byte> packet);

  [[nodiscard]] std::optional<std::span<const std::byte>> flush();

  [[nodiscard]] std::uint32_t current_block() const noexcept { return block_id_; }
  [[nodiscard]] std::size_t pending() const noexcept { return index_; }
  [[nodiscard]] const FecStats& stats() const noexcept { return stats_; }

 private:
  FecMode mode_{FecMode::off};
  std::size_t block_size_{};
  std::uint32_t block_id_{};
  std::size_t index_{};
  std::size_t widest_{};
  std::vector<std::byte> parity_;
  std::vector<std::byte> output_;
  FecStats stats_{};
};

class FecDecoder {
 public:
  FecDecoder() = default;

  [[nodiscard]] std::optional<std::vector<std::byte>> receive(const FecSymbolHeader& header,
                                                              std::span<const std::byte> payload,
                                                              Instant now);

  std::size_t expire(Instant now);

  [[nodiscard]] std::size_t outstanding() const noexcept { return blocks_.size(); }
  [[nodiscard]] const FecStats& stats() const noexcept { return stats_; }

 private:
  struct Block {
    std::uint32_t id{};
    std::size_t size{};
    std::size_t received{};
    bool have_parity{};
    std::vector<std::byte> accumulator;
    std::vector<bool> present;
    std::vector<std::uint16_t> lengths;
    Instant created{};
  };

  [[nodiscard]] Block* find_or_create(const FecSymbolHeader& header, std::size_t symbol_size,
                                      Instant now);

  std::deque<Block> blocks_;
  FecStats stats_{};
};

}
