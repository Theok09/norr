// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#include "norr/reality.hpp"

#include <algorithm>
#include <array>
#include <string_view>

#include "norr/blake2s.hpp"

namespace norr {
namespace {
constexpr std::string_view kRealityDomain = "norr-reality-v1";
constexpr std::size_t kRealityNonceSize = 8;
constexpr std::size_t kRealityPlainSize = 16;

[[nodiscard]] std::array<std::byte, 32> derive_key(const SharedSecret& secret) noexcept {
  const auto salt = std::as_bytes(std::span{kRealityDomain});
  const auto digest = hkdf_extract(salt, secret);
  std::array<std::byte, 32> key{};
  std::copy(digest.begin(), digest.begin() + 32, key.begin());
  return key;
}

void put_u64(std::span<std::byte> out, std::uint64_t value) noexcept {
  for (std::size_t index = 0; index < 8; ++index) {
    out[index] = static_cast<std::byte>((value >> (8U * (7U - index))) & 0xFFU);
  }
}

[[nodiscard]] std::uint64_t get_u64(std::span<const std::byte> in) noexcept {
  std::uint64_t value = 0;
  for (std::size_t index = 0; index < 8; ++index) {
    value = (value << 8U) | static_cast<std::uint64_t>(static_cast<std::uint8_t>(in[index]));
  }
  return value;
}
}

std::expected<RealityClientHello, CryptoError> reality_client_hello(
    const PublicKey& server_public, const RealityShortId& short_id,
    std::uint64_t unix_time) noexcept {
  auto ephemeral = generate_keypair();
  if (!ephemeral) return std::unexpected(ephemeral.error());

  auto secret = x25519(ephemeral->private_key, server_public);
  if (!secret) return std::unexpected(secret.error());
  const auto key = derive_key(*secret);

  std::array<std::byte, kRealityPlainSize> plain{};
  put_u64(std::span{plain}.first(8), unix_time);
  std::copy(short_id.begin(), short_id.end(), plain.begin() + 8);

  const auto nonce = std::span{ephemeral->public_key}.first(kRealityNonceSize);
  if (!keystream_xor(key, nonce, plain)) {
    return std::unexpected(CryptoError::initialisation_failed);
  }

  std::array<std::byte, kPublicKeySize + kRealityCipherSize> mac_input{};
  std::copy(ephemeral->public_key.begin(), ephemeral->public_key.end(), mac_input.begin());
  std::copy(plain.begin(), plain.end(), mac_input.begin() + kPublicKeySize);
  const auto mac = hmac_blake2s(key, mac_input);

  RealityClientHello result{};
  result.ephemeral = *ephemeral;
  std::copy(plain.begin(), plain.end(), result.session_id.begin());
  std::copy(mac.begin(), mac.begin() + kRealityMacSize,
            result.session_id.begin() + kRealityCipherSize);
  return result;
}

RealityServerResult reality_server_verify(
    const PrivateKey& server_private, const PublicKey& client_key_share,
    std::span<const std::byte> session_id, std::uint64_t now,
    std::uint64_t window_seconds) noexcept {
  RealityServerResult result{};
  if (session_id.size() != kRealitySessionIdSize) return result;

  auto secret = x25519(server_private, client_key_share);
  if (!secret) return result;
  const auto key = derive_key(*secret);

  const auto cipher = session_id.first(kRealityCipherSize);
  const auto mac = session_id.subspan(kRealityCipherSize, kRealityMacSize);

  std::array<std::byte, kPublicKeySize + kRealityCipherSize> mac_input{};
  std::copy(client_key_share.begin(), client_key_share.end(), mac_input.begin());
  std::copy(cipher.begin(), cipher.end(), mac_input.begin() + kPublicKeySize);
  const auto expected = hmac_blake2s(key, mac_input);
  if (!constant_time_equal(mac, std::span{expected}.first(kRealityMacSize))) return result;

  std::array<std::byte, kRealityPlainSize> plain{};
  std::copy(cipher.begin(), cipher.end(), plain.begin());
  const auto nonce = std::span{client_key_share}.first(kRealityNonceSize);
  if (!keystream_xor(key, nonce, plain)) return result;

  const auto timestamp = get_u64(std::span{plain}.first(8));
  const auto delta = now > timestamp ? now - timestamp : timestamp - now;
  if (delta > window_seconds) return result;

  result.authenticated = true;
  result.timestamp = timestamp;
  std::copy(plain.begin() + 8, plain.end(), result.short_id.begin());
  return result;
}
}
