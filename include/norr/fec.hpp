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
    case FecMode::light: return 16;
    case FecMode::moderate: return 10;
    case FecMode::aggressive: return 8;
    default: return 0;
  }
}

[[nodiscard]] constexpr std::size_t parity_count_for(FecMode mode) noexcept {
  switch (mode) {
    case FecMode::light: return 2;
    case FecMode::moderate: return 3;
    case FecMode::aggressive: return 4;
    default: return 0;
  }
}

inline constexpr std::size_t kMaximumFecLanes = 4;
inline constexpr double kFecTargetBlockFailure = 1e-3;

struct FecPlan {
  std::size_t data{};
  std::size_t parity{};
  std::size_t lanes{1};
  double loss{};

  [[nodiscard]] constexpr bool active() const noexcept { return data > 0 && parity > 0; }
  [[nodiscard]] constexpr bool same_shape(const FecPlan& other) const noexcept {
    return data == other.data && parity == other.parity && lanes == other.lanes;
  }
};

[[nodiscard]] constexpr FecPlan plan_for_mode(FecMode mode) noexcept {
  return FecPlan{.data = block_size_for(mode), .parity = parity_count_for(mode), .lanes = 1,
                 .loss = 0.0};
}

[[nodiscard]] std::size_t parity_needed(std::size_t data, double loss, std::size_t limit) noexcept;

[[nodiscard]] FecPlan plan_for_loss(double loss, double packets_per_second) noexcept;

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
  explicit FecEncoder(FecMode mode = FecMode::off) { configure(plan_for_mode(mode)); }
  explicit FecEncoder(const FecPlan& plan) { configure(plan); }

  void configure(const FecPlan& plan);
  [[nodiscard]] const FecPlan& plan() const noexcept { return plan_; }
  [[nodiscard]] bool active() const noexcept { return plan_.active(); }
  [[nodiscard]] std::size_t data_count() const noexcept { return plan_.data; }
  [[nodiscard]] std::size_t parity_count() const noexcept { return plan_.parity; }

  [[nodiscard]] FecSymbolHeader next_header(std::size_t sealed_length) const noexcept;

  [[nodiscard]] std::span<const std::vector<std::byte>> add(std::span<const std::byte> packet);

  [[nodiscard]] std::span<const std::vector<std::byte>> flush();

  [[nodiscard]] std::uint32_t current_block() const noexcept { return next_block_; }
  void resume_at(std::uint32_t block_id) noexcept;
  [[nodiscard]] std::size_t pending() const noexcept;
  [[nodiscard]] const FecStats& stats() const noexcept { return stats_; }

 private:
  struct Lane {
    std::uint32_t block_id{};
    std::size_t index{};
    std::size_t width{};
    std::vector<std::vector<std::byte>> parity;
  };

  void emit(Lane& lane, std::size_t rows);

  FecPlan plan_{};
  std::array<Lane, kMaximumFecLanes> lanes_{};
  std::size_t cursor_{};
  std::uint32_t next_block_{};
  std::vector<std::byte> symbol_;
  std::vector<std::vector<std::byte>> output_;
  std::size_t output_count_{};
  FecStats stats_{};
};

struct FecLossReport {
  double raw{};
  double residual{};
  double packets_per_second{};
  bool congested{};
};

class AdaptiveFec {
 public:
  static constexpr double kEnableLoss = 0.003;
  static constexpr double kDisableLoss = 0.001;
  static constexpr std::uint32_t kReportsBeforeEnable = 3;
  static constexpr std::uint32_t kCalmBeforeDisable = 5;
  static constexpr double kMinimumRecoveredShare = 0.3;
  static constexpr std::uint32_t kIneffectiveBeforeSuppress = 3;
  static constexpr auto kSuppression = std::chrono::seconds{30};
  static constexpr auto kMaximumSuppression = std::chrono::seconds{300};

  [[nodiscard]] std::optional<FecPlan> decide(const FecPlan& current, const FecLossReport& report,
                                              Instant now) noexcept;

  [[nodiscard]] double smoothed_loss() const noexcept { return smoothed_; }

 private:
  double smoothed_{};
  std::uint32_t lossy_reports_{};
  std::uint32_t calm_reports_{};
  std::uint32_t ineffective_reports_{};
  Instant suppressed_until_{};
  Duration suppression_{kSuppression};
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
  void recycle(Block& block);
  [[nodiscard]] std::vector<std::byte> take_buffer();

  std::deque<Block> blocks_;
  std::vector<std::vector<std::byte>> spare_;
  std::deque<std::uint32_t> finished_;
  FecStats stats_{};
};
}
