// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#pragma once

#include <array>
#include <chrono>
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
inline constexpr std::size_t kMaximumFecData = 64;
inline constexpr std::size_t kMaximumFecParity = 16;
inline constexpr std::size_t kMaximumOutstandingBlocks = 128;
inline constexpr std::size_t kFecLengthPrefix = 2;
inline constexpr auto kFecRecoveryDeadline = std::chrono::milliseconds{250};
inline constexpr auto kFecFlushInterval = std::chrono::milliseconds{5};

enum class FecMode : std::uint8_t { off, light, moderate, aggressive, automatic };

[[nodiscard]] constexpr std::string_view fec_mode_name(FecMode mode) noexcept {
  switch (mode) {
    case FecMode::off: return "off";
    case FecMode::light: return "light";
    case FecMode::moderate: return "moderate";
    case FecMode::aggressive: return "aggressive";
    case FecMode::automatic: return "auto";
  }
  return "unknown";
}

[[nodiscard]] constexpr std::size_t block_size_for(FecMode mode) noexcept {
  switch (mode) {
    case FecMode::off: return 0;
    case FecMode::light: return 16;
    case FecMode::moderate: return 10;
    case FecMode::aggressive: return 8;
    case FecMode::automatic: return 0;
  }
  return 0;
}

[[nodiscard]] constexpr std::size_t parity_count_for(FecMode mode) noexcept {
  switch (mode) {
    case FecMode::off: return 0;
    case FecMode::light: return 2;
    case FecMode::moderate: return 3;
    case FecMode::aggressive: return 4;
    case FecMode::automatic: return 0;
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
  std::uint8_t parity_count{};
  bool parity{};
  std::uint16_t original_length{};
};

inline constexpr std::size_t kFecHeaderSize = 11;

inline constexpr std::byte kFecTag{static_cast<std::uint8_t>(
    (kProtocolVersion << 4U) | static_cast<std::uint8_t>(FrameType::fec))};

[[nodiscard]] constexpr bool looks_like_fec_symbol(std::span<const std::byte> bytes) noexcept {
  return !bytes.empty() && bytes[0] == kFecTag;
}

[[nodiscard]] std::size_t serialize_fec_header(const FecSymbolHeader& header,
                                               std::span<std::byte> out) noexcept;
[[nodiscard]] std::optional<FecSymbolHeader> parse_fec_header(
    std::span<const std::byte> bytes) noexcept;

namespace gf256 {
[[nodiscard]] std::uint8_t multiply(std::uint8_t left, std::uint8_t right) noexcept;
[[nodiscard]] std::uint8_t inverse(std::uint8_t value) noexcept;
[[nodiscard]] std::uint8_t cauchy(std::size_t parity_row, std::size_t data_column) noexcept;
void multiply_add(std::span<std::byte> accumulator, std::span<const std::byte> source,
                  std::uint8_t coefficient) noexcept;
}

class FecEncoder {
 public:
  explicit FecEncoder(FecMode mode = FecMode::off) { set_mode(mode); }

  void set_mode(FecMode mode);
  [[nodiscard]] FecMode mode() const noexcept { return mode_; }
  [[nodiscard]] std::size_t data_count() const noexcept { return data_count_; }
  [[nodiscard]] std::size_t parity_count() const noexcept { return parity_count_; }

  [[nodiscard]] FecSymbolHeader next_header(std::size_t sealed_length) const noexcept;

  [[nodiscard]] const std::vector<std::vector<std::byte>>& add(std::span<const std::byte> packet);

  [[nodiscard]] const std::vector<std::vector<std::byte>>& flush();

  [[nodiscard]] std::uint32_t current_block() const noexcept { return block_id_; }
  void resume_at(std::uint32_t block_id) noexcept { block_id_ = block_id; }
  [[nodiscard]] std::size_t pending() const noexcept { return index_; }
  [[nodiscard]] const FecStats& stats() const noexcept { return stats_; }

 private:
  FecMode mode_{FecMode::off};
  std::size_t data_count_{};
  std::size_t parity_count_{};
  std::uint32_t block_id_{};
  std::size_t index_{};
  std::size_t width_{};
  std::vector<std::vector<std::byte>> parity_;
  std::vector<std::byte> symbol_;
  std::vector<std::vector<std::byte>> output_;
  FecStats stats_{};
};

class AdaptiveFec {
 public:
  static constexpr double kMinimumRecoveredShare = 0.3;
  static constexpr std::uint32_t kIneffectiveBeforeSuppress = 3;
  static constexpr std::uint32_t kCalmBeforeDowngrade = 10;
  static constexpr auto kSuppression = std::chrono::seconds{30};

  [[nodiscard]] std::optional<FecMode> decide(FecMode current, double raw_loss,
                                              double residual_loss, Instant now) noexcept;

 private:
  std::uint32_t calm_reports_{};
  std::uint32_t ineffective_reports_{};
  Instant suppressed_until_{};
};

class FecDecoder {
 public:
  FecDecoder() = default;

  [[nodiscard]] std::vector<std::vector<std::byte>> receive(const FecSymbolHeader& header,
                                                            std::span<const std::byte> payload,
                                                            Instant now);

  std::size_t expire(Instant now);

  [[nodiscard]] std::size_t outstanding() const noexcept { return blocks_.size(); }
  [[nodiscard]] const FecStats& stats() const noexcept { return stats_; }

 private:
  struct Block {
    std::uint32_t id{};
    std::size_t data_count{};
    std::size_t parity_count{};
    std::size_t data_received{};
    std::vector<std::vector<std::byte>> data;
    std::vector<std::vector<std::byte>> parity;
    Instant created{};
  };

  [[nodiscard]] Block* find_or_create(const FecSymbolHeader& header, Instant now);
  [[nodiscard]] std::vector<std::vector<std::byte>> try_recover(Block& block);
  [[nodiscard]] bool recently_finished(std::uint32_t id) const noexcept;
  void finish(std::uint32_t id);

  std::deque<Block> blocks_;
  std::deque<std::uint32_t> finished_;
  FecStats stats_{};
};
}
