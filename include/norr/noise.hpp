// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string_view>
#include <vector>

#include "norr/blake2s.hpp"
#include "norr/crypto.hpp"

namespace norr {
inline constexpr std::string_view kNoiseProtocolName =
    "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";

inline constexpr std::size_t kNoiseHashLength = 32;
inline constexpr std::size_t kNoiseDhLength = 32;
inline constexpr std::size_t kNoiseKeyLength = 32;
inline constexpr std::size_t kPresharedKeyLength = 32;

inline constexpr std::size_t kNoiseMessage1Overhead = 32 + 32 + 16 + 16;

inline constexpr std::size_t kNoiseMessage2Overhead = 32 + 16;

using PresharedKey = std::array<std::byte, kPresharedKeyLength>;
using ChainingKey = std::array<std::byte, kNoiseHashLength>;
using TranscriptHash = std::array<std::byte, kNoiseHashLength>;

enum class NoiseError {
  unsupported_platform,
  invalid_state,
  decryption_failed,
  message_too_short,
  message_too_large,
  buffer_too_small,
  bad_public_key,
  missing_static_key,
  missing_remote_static,
};

[[nodiscard]] constexpr std::string_view noise_error_message(NoiseError error) noexcept {
  switch (error) {
    case NoiseError::unsupported_platform: return "crypto backend not available";
    case NoiseError::invalid_state: return "handshake step out of order";
    case NoiseError::decryption_failed: return "handshake message failed authentication";
    case NoiseError::message_too_short: return "handshake message too short";
    case NoiseError::message_too_large: return "handshake message too large";
    case NoiseError::buffer_too_small: return "output buffer too small";
    case NoiseError::bad_public_key: return "invalid public key";
    case NoiseError::missing_static_key: return "local static key not set";
    case NoiseError::missing_remote_static: return "responder static key required by IK";
  }
  return "unknown noise error";
}

class CipherState {
 public:
  void initialize(std::span<const std::byte> key) noexcept;
  [[nodiscard]] bool has_key() const noexcept { return has_key_; }

  [[nodiscard]] std::expected<std::size_t, NoiseError> encrypt_with_ad(
      std::span<const std::byte> associated_data, std::span<const std::byte> plaintext,
      std::span<std::byte> out) noexcept;

  [[nodiscard]] std::expected<std::size_t, NoiseError> decrypt_with_ad(
      std::span<const std::byte> associated_data, std::span<const std::byte> ciphertext,
      std::span<std::byte> out) noexcept;

  [[nodiscard]] TrafficKey key() const noexcept { return key_; }

  ~CipherState();

 private:
  TrafficKey key_{};
  std::uint64_t nonce_{};
  bool has_key_{};
};

class SymmetricState {
 public:
  void initialize(std::string_view protocol_name) noexcept;

  void mix_hash(std::span<const std::byte> data) noexcept;
  void mix_key(std::span<const std::byte> input_key_material) noexcept;
  void mix_key_and_hash(std::span<const std::byte> input_key_material) noexcept;

  [[nodiscard]] std::expected<std::size_t, NoiseError> encrypt_and_hash(
      std::span<const std::byte> plaintext, std::span<std::byte> out) noexcept;

  [[nodiscard]] std::expected<std::size_t, NoiseError> decrypt_and_hash(
      std::span<const std::byte> ciphertext, std::span<std::byte> out) noexcept;

  [[nodiscard]] std::pair<TrafficKey, TrafficKey> split() const noexcept;

  [[nodiscard]] const TranscriptHash& handshake_hash() const noexcept { return hash_; }
  [[nodiscard]] const ChainingKey& chaining_key() const noexcept { return chaining_key_; }

  ~SymmetricState();

 private:
  ChainingKey chaining_key_{};
  TranscriptHash hash_{};
  CipherState cipher_;
};

struct NoiseResult {
  TrafficKey send{};
  TrafficKey receive{};

  TranscriptHash handshake_hash{};

  PublicKey remote_static{};
};

class NoiseHandshake {
 public:

  [[nodiscard]] static std::expected<NoiseHandshake, NoiseError> create(
      HandshakeRole role, const KeyPair& local_static, const PublicKey& remote_static,
      const PresharedKey& preshared, std::span<const std::byte> prologue = {});

  NoiseHandshake(const NoiseHandshake&) = delete;
  NoiseHandshake& operator=(const NoiseHandshake&) = delete;
  NoiseHandshake(NoiseHandshake&&) noexcept = default;
  NoiseHandshake& operator=(NoiseHandshake&&) noexcept = default;

  [[nodiscard]] std::expected<std::size_t, NoiseError> write_message_1(
      std::span<const std::byte> payload, std::span<std::byte> out);

  [[nodiscard]] std::expected<std::size_t, NoiseError> read_message_1(
      std::span<const std::byte> message, std::span<std::byte> payload_out);

  [[nodiscard]] std::expected<std::size_t, NoiseError> write_message_2(
      std::span<const std::byte> payload, std::span<std::byte> out);

  [[nodiscard]] std::expected<std::size_t, NoiseError> read_message_2(
      std::span<const std::byte> message, std::span<std::byte> payload_out);

  [[nodiscard]] bool finished() const noexcept { return finished_; }

  [[nodiscard]] const PublicKey& learned_remote_static() const noexcept { return remote_static_; }

  [[nodiscard]] std::expected<NoiseResult, NoiseError> result() const;

 private:
  NoiseHandshake() = default;

  HandshakeRole role_{HandshakeRole::initiator};
  SymmetricState symmetric_;
  KeyPair local_static_{};
  KeyPair local_ephemeral_{};
  PublicKey remote_static_{};
  PublicKey remote_ephemeral_{};
  PresharedKey preshared_{};
  bool has_remote_static_{};
  bool sent_message_1_{};
  bool read_message_1_{};
  bool finished_{};
};

}
