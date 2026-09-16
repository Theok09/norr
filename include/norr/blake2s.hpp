// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace norr {
class Blake2s {
 public:
  static constexpr std::size_t kBlockSize = 64;
  static constexpr std::size_t kMaximumDigestSize = 32;
  static constexpr std::size_t kMaximumKeySize = 32;

  using Digest = std::array<std::byte, kMaximumDigestSize>;

  explicit Blake2s(std::size_t digest_size = kMaximumDigestSize,
                   std::span<const std::byte> key = {}) noexcept;

  void update(std::span<const std::byte> input) noexcept;

  void finish(std::span<std::byte> out) noexcept;

  [[nodiscard]] std::size_t digest_size() const noexcept { return digest_size_; }

  [[nodiscard]] static Digest hash(std::span<const std::byte> input,
                                   std::span<const std::byte> key = {}) noexcept;

 private:
  void compress(bool last) noexcept;

  std::array<std::uint32_t, 8> state_{};
  std::array<std::byte, kBlockSize> buffer_{};
  std::size_t buffered_{};
  std::uint64_t counter_{};
  std::size_t digest_size_{kMaximumDigestSize};
  bool finished_{};
};

using HmacKey = std::array<std::byte, Blake2s::kMaximumDigestSize>;

[[nodiscard]] Blake2s::Digest hmac_blake2s(std::span<const std::byte> key,
                                           std::span<const std::byte> message) noexcept;

[[nodiscard]] Blake2s::Digest hkdf_extract(std::span<const std::byte> salt,
                                           std::span<const std::byte> input) noexcept;

[[nodiscard]] bool hkdf_expand(std::span<const std::byte> pseudorandom_key,
                               std::span<const std::byte> info,
                               std::span<std::byte> out) noexcept;

}
