// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>

#include "norr/crypto.hpp"

namespace norr {
inline constexpr std::size_t kRealityShortIdSize = 8;
inline constexpr std::size_t kRealityCipherSize = 16;
inline constexpr std::size_t kRealityMacSize = 16;
inline constexpr std::size_t kRealitySessionIdSize = kRealityCipherSize + kRealityMacSize;

using RealityShortId = std::array<std::byte, kRealityShortIdSize>;
using RealitySessionId = std::array<std::byte, kRealitySessionIdSize>;

struct RealityClientHello {
  KeyPair ephemeral{};
  RealitySessionId session_id{};
};

[[nodiscard]] std::expected<RealityClientHello, CryptoError> reality_client_hello(
    const PublicKey& server_public, const RealityShortId& short_id,
    std::uint64_t unix_time) noexcept;

struct RealityServerResult {
  bool authenticated{};
  RealityShortId short_id{};
  std::uint64_t timestamp{};
};

[[nodiscard]] RealityServerResult reality_server_verify(
    const PrivateKey& server_private, const PublicKey& client_key_share,
    std::span<const std::byte> session_id, std::uint64_t now,
    std::uint64_t window_seconds) noexcept;
}
