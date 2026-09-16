// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#include "norr/noise.hpp"

#include <algorithm>
#include <cstring>

namespace norr {
namespace {
struct HkdfOutputs {
  std::array<std::byte, kNoiseHashLength> output1{};
  std::array<std::byte, kNoiseHashLength> output2{};
  std::array<std::byte, kNoiseHashLength> output3{};
};

[[nodiscard]] HkdfOutputs noise_hkdf(std::span<const std::byte> chaining_key,
                                     std::span<const std::byte> input_key_material,
                                     unsigned outputs) noexcept {
  HkdfOutputs result{};
  const auto temp_key = hmac_blake2s(chaining_key, input_key_material);

  const std::array<std::byte, 1> one{std::byte{0x01}};
  const auto first = hmac_blake2s(temp_key, one);
  std::copy(first.begin(), first.end(), result.output1.begin());
  if (outputs == 1) return result;

  std::array<std::byte, kNoiseHashLength + 1> second_input{};
  std::copy(first.begin(), first.end(), second_input.begin());
  second_input[kNoiseHashLength] = std::byte{0x02};
  const auto second = hmac_blake2s(temp_key, second_input);
  std::copy(second.begin(), second.end(), result.output2.begin());
  if (outputs == 2) return result;

  std::array<std::byte, kNoiseHashLength + 1> third_input{};
  std::copy(second.begin(), second.end(), third_input.begin());
  third_input[kNoiseHashLength] = std::byte{0x03};
  const auto third = hmac_blake2s(temp_key, third_input);
  std::copy(third.begin(), third.end(), result.output3.begin());
  return result;
}

}

CipherState::~CipherState() { secure_zero(key_); }

void CipherState::initialize(std::span<const std::byte> key) noexcept {
  std::copy_n(key.begin(), std::min(key.size(), key_.size()), key_.begin());

  nonce_ = 0;
  has_key_ = true;
}

std::expected<std::size_t, NoiseError> CipherState::encrypt_with_ad(
    std::span<const std::byte> associated_data, std::span<const std::byte> plaintext,
    std::span<std::byte> out) noexcept {
  if (!has_key_) {
    if (out.size() < plaintext.size()) return std::unexpected(NoiseError::buffer_too_small);
    std::copy(plaintext.begin(), plaintext.end(), out.begin());
    return plaintext.size();
  }

  const TrafficKeys keys{key_, 0};
  const auto sealed = keys.seal(nonce_, associated_data, plaintext, out);
  if (!sealed) {
    return std::unexpected(sealed.error() == CryptoError::buffer_too_small
                               ? NoiseError::buffer_too_small
                               : NoiseError::unsupported_platform);
  }
  ++nonce_;
  return *sealed;
}

std::expected<std::size_t, NoiseError> CipherState::decrypt_with_ad(
    std::span<const std::byte> associated_data, std::span<const std::byte> ciphertext,
    std::span<std::byte> out) noexcept {
  if (!has_key_) {
    if (out.size() < ciphertext.size()) return std::unexpected(NoiseError::buffer_too_small);
    std::copy(ciphertext.begin(), ciphertext.end(), out.begin());
    return ciphertext.size();
  }

  const TrafficKeys keys{key_, 0};
  const auto opened = keys.open(nonce_, associated_data, ciphertext, out);
  if (!opened) {
    return std::unexpected(opened.error() == CryptoError::buffer_too_small
                               ? NoiseError::buffer_too_small
                               : NoiseError::decryption_failed);
  }
  ++nonce_;
  return *opened;
}

SymmetricState::~SymmetricState() {
  secure_zero(chaining_key_);
  secure_zero(hash_);
}

void SymmetricState::initialize(std::string_view protocol_name) noexcept {
  if (protocol_name.size() <= kNoiseHashLength) {
    std::fill(hash_.begin(), hash_.end(), std::byte{0});
    for (std::size_t index = 0; index < protocol_name.size(); ++index) {
      hash_[index] = static_cast<std::byte>(static_cast<unsigned char>(protocol_name[index]));
    }
  } else {
    std::vector<std::byte> name;
    name.reserve(protocol_name.size());
    for (const char character : protocol_name) {
      name.push_back(static_cast<std::byte>(static_cast<unsigned char>(character)));
    }
    const auto digest = Blake2s::hash(name);
    std::copy(digest.begin(), digest.end(), hash_.begin());
  }
  std::copy(hash_.begin(), hash_.end(), chaining_key_.begin());
}

void SymmetricState::mix_hash(std::span<const std::byte> data) noexcept {
  Blake2s state;
  state.update(hash_);
  state.update(data);
  Blake2s::Digest digest{};
  state.finish(digest);
  std::copy(digest.begin(), digest.end(), hash_.begin());
}

void SymmetricState::mix_key(std::span<const std::byte> input_key_material) noexcept {
  const auto outputs = noise_hkdf(chaining_key_, input_key_material, 2);
  std::copy(outputs.output1.begin(), outputs.output1.end(), chaining_key_.begin());
  cipher_.initialize(outputs.output2);
}

void SymmetricState::mix_key_and_hash(std::span<const std::byte> input_key_material) noexcept {
  const auto outputs = noise_hkdf(chaining_key_, input_key_material, 3);
  std::copy(outputs.output1.begin(), outputs.output1.end(), chaining_key_.begin());
  mix_hash(outputs.output2);
  cipher_.initialize(outputs.output3);
}

std::expected<std::size_t, NoiseError> SymmetricState::encrypt_and_hash(
    std::span<const std::byte> plaintext, std::span<std::byte> out) noexcept {
  const auto written = cipher_.encrypt_with_ad(hash_, plaintext, out);
  if (!written) return std::unexpected(written.error());

  mix_hash(out.first(*written));
  return *written;
}

std::expected<std::size_t, NoiseError> SymmetricState::decrypt_and_hash(
    std::span<const std::byte> ciphertext, std::span<std::byte> out) noexcept {
  std::vector<std::byte> received(ciphertext.begin(), ciphertext.end());
  const auto written = cipher_.decrypt_with_ad(hash_, ciphertext, out);
  if (!written) return std::unexpected(written.error());
  mix_hash(received);
  return *written;
}

std::pair<TrafficKey, TrafficKey> SymmetricState::split() const noexcept {
  const auto outputs = noise_hkdf(chaining_key_, {}, 2);
  TrafficKey first{};
  TrafficKey second{};
  std::copy(outputs.output1.begin(), outputs.output1.end(), first.begin());
  std::copy(outputs.output2.begin(), outputs.output2.end(), second.begin());
  return {first, second};
}

std::expected<NoiseHandshake, NoiseError> NoiseHandshake::create(
    HandshakeRole role, const KeyPair& local_static, const PublicKey& remote_static,
    const PresharedKey& preshared, std::span<const std::byte> prologue) {
  if (!crypto_available()) return std::unexpected(NoiseError::unsupported_platform);

  NoiseHandshake handshake;
  handshake.role_ = role;
  handshake.local_static_ = local_static;
  handshake.preshared_ = preshared;

  handshake.symmetric_.initialize(kNoiseProtocolName);
  handshake.symmetric_.mix_hash(prologue);

  if (role == HandshakeRole::initiator) {
    const auto empty = std::ranges::all_of(remote_static,
                                           [](std::byte octet) { return octet == std::byte{0}; });
    if (empty) return std::unexpected(NoiseError::missing_remote_static);
    handshake.remote_static_ = remote_static;
    handshake.has_remote_static_ = true;
    handshake.symmetric_.mix_hash(remote_static);
  } else {
    handshake.symmetric_.mix_hash(local_static.public_key);
  }

  return handshake;
}

std::expected<std::size_t, NoiseError> NoiseHandshake::write_message_1(
    std::span<const std::byte> payload, std::span<std::byte> out) {
  if (role_ != HandshakeRole::initiator || sent_message_1_ || finished_) {
    return std::unexpected(NoiseError::invalid_state);
  }
  if (!has_remote_static_) return std::unexpected(NoiseError::missing_remote_static);
  if (out.size() < kNoiseMessage1Overhead + payload.size()) {
    return std::unexpected(NoiseError::buffer_too_small);
  }

  const auto ephemeral = generate_keypair();
  if (!ephemeral) return std::unexpected(NoiseError::unsupported_platform);
  local_ephemeral_ = *ephemeral;

  std::size_t offset = 0;

  std::copy(local_ephemeral_.public_key.begin(), local_ephemeral_.public_key.end(),
            out.begin() + static_cast<std::ptrdiff_t>(offset));
  symmetric_.mix_hash(local_ephemeral_.public_key);
  offset += kNoiseDhLength;

  {
    const auto shared = x25519(local_ephemeral_.private_key, remote_static_);
    if (!shared) return std::unexpected(NoiseError::bad_public_key);
    symmetric_.mix_key(*shared);
  }

  {
    const auto written =
        symmetric_.encrypt_and_hash(local_static_.public_key, out.subspan(offset));
    if (!written) return std::unexpected(written.error());
    offset += *written;
  }

  {
    const auto shared = x25519(local_static_.private_key, remote_static_);
    if (!shared) return std::unexpected(NoiseError::bad_public_key);
    symmetric_.mix_key(*shared);
  }

  const auto written = symmetric_.encrypt_and_hash(payload, out.subspan(offset));
  if (!written) return std::unexpected(written.error());
  offset += *written;

  sent_message_1_ = true;
  return offset;
}

std::expected<std::size_t, NoiseError> NoiseHandshake::read_message_1(
    std::span<const std::byte> message, std::span<std::byte> payload_out) {
  if (role_ != HandshakeRole::responder || read_message_1_ || finished_) {
    return std::unexpected(NoiseError::invalid_state);
  }
  if (message.size() < kNoiseMessage1Overhead) {
    return std::unexpected(NoiseError::message_too_short);
  }

  std::size_t offset = 0;

  std::copy_n(message.begin(), kNoiseDhLength, remote_ephemeral_.begin());
  symmetric_.mix_hash(remote_ephemeral_);
  offset += kNoiseDhLength;

  {
    const auto shared = x25519(local_static_.private_key, remote_ephemeral_);
    if (!shared) return std::unexpected(NoiseError::bad_public_key);
    symmetric_.mix_key(*shared);
  }

  {
    constexpr std::size_t kEncryptedStaticSize = kNoiseDhLength + kAeadTagSize;
    PublicKey initiator_static{};
    const auto written = symmetric_.decrypt_and_hash(
        message.subspan(offset, kEncryptedStaticSize), initiator_static);
    if (!written) return std::unexpected(written.error());
    remote_static_ = initiator_static;
    has_remote_static_ = true;
    offset += kEncryptedStaticSize;
  }

  {
    const auto shared = x25519(local_static_.private_key, remote_static_);
    if (!shared) return std::unexpected(NoiseError::bad_public_key);
    symmetric_.mix_key(*shared);
  }

  const auto remaining = message.subspan(offset);
  if (remaining.size() < kAeadTagSize) return std::unexpected(NoiseError::message_too_short);
  if (payload_out.size() < remaining.size() - kAeadTagSize) {
    return std::unexpected(NoiseError::buffer_too_small);
  }
  const auto written = symmetric_.decrypt_and_hash(remaining, payload_out);
  if (!written) return std::unexpected(written.error());

  read_message_1_ = true;
  return *written;
}

std::expected<std::size_t, NoiseError> NoiseHandshake::write_message_2(
    std::span<const std::byte> payload, std::span<std::byte> out) {
  if (role_ != HandshakeRole::responder || !read_message_1_ || finished_) {
    return std::unexpected(NoiseError::invalid_state);
  }
  if (out.size() < kNoiseMessage2Overhead + payload.size()) {
    return std::unexpected(NoiseError::buffer_too_small);
  }

  const auto ephemeral = generate_keypair();
  if (!ephemeral) return std::unexpected(NoiseError::unsupported_platform);
  local_ephemeral_ = *ephemeral;

  std::size_t offset = 0;

  std::copy(local_ephemeral_.public_key.begin(), local_ephemeral_.public_key.end(),
            out.begin() + static_cast<std::ptrdiff_t>(offset));
  symmetric_.mix_hash(local_ephemeral_.public_key);
  offset += kNoiseDhLength;

  {
    const auto shared = x25519(local_ephemeral_.private_key, remote_ephemeral_);
    if (!shared) return std::unexpected(NoiseError::bad_public_key);
    symmetric_.mix_key(*shared);
  }

  {
    const auto shared = x25519(local_ephemeral_.private_key, remote_static_);
    if (!shared) return std::unexpected(NoiseError::bad_public_key);
    symmetric_.mix_key(*shared);
  }

  symmetric_.mix_key_and_hash(preshared_);

  const auto written = symmetric_.encrypt_and_hash(payload, out.subspan(offset));
  if (!written) return std::unexpected(written.error());
  offset += *written;

  finished_ = true;
  return offset;
}

std::expected<std::size_t, NoiseError> NoiseHandshake::read_message_2(
    std::span<const std::byte> message, std::span<std::byte> payload_out) {
  if (role_ != HandshakeRole::initiator || !sent_message_1_ || finished_) {
    return std::unexpected(NoiseError::invalid_state);
  }
  if (message.size() < kNoiseMessage2Overhead) {
    return std::unexpected(NoiseError::message_too_short);
  }

  std::size_t offset = 0;

  std::copy_n(message.begin(), kNoiseDhLength, remote_ephemeral_.begin());
  symmetric_.mix_hash(remote_ephemeral_);
  offset += kNoiseDhLength;

  {
    const auto shared = x25519(local_ephemeral_.private_key, remote_ephemeral_);
    if (!shared) return std::unexpected(NoiseError::bad_public_key);
    symmetric_.mix_key(*shared);
  }

  {
    const auto shared = x25519(local_static_.private_key, remote_ephemeral_);
    if (!shared) return std::unexpected(NoiseError::bad_public_key);
    symmetric_.mix_key(*shared);
  }

  symmetric_.mix_key_and_hash(preshared_);

  const auto remaining = message.subspan(offset);
  if (remaining.size() < kAeadTagSize) return std::unexpected(NoiseError::message_too_short);
  if (payload_out.size() < remaining.size() - kAeadTagSize) {
    return std::unexpected(NoiseError::buffer_too_small);
  }
  const auto written = symmetric_.decrypt_and_hash(remaining, payload_out);
  if (!written) return std::unexpected(written.error());

  finished_ = true;
  return *written;
}

std::expected<NoiseResult, NoiseError> NoiseHandshake::result() const {
  if (!finished_) return std::unexpected(NoiseError::invalid_state);

  const auto [first, second] = symmetric_.split();
  NoiseResult result{};

  if (role_ == HandshakeRole::initiator) {
    result.send = first;
    result.receive = second;
  } else {
    result.send = second;
    result.receive = first;
  }
  result.handshake_hash = symmetric_.handshake_hash();
  result.remote_static = remote_static_;
  return result;
}

}
