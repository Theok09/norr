// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#include "norr/blake2s.hpp"

#include <algorithm>
#include <cstring>

namespace norr {
namespace {
constexpr std::array<std::uint32_t, 8> kInitialisationVector{
    0x6A09E667U, 0xBB67AE85U, 0x3C6EF372U, 0xA54FF53AU,
    0x510E527FU, 0x9B05688CU, 0x1F83D9ABU, 0x5BE0CD19U,
};

constexpr std::array<std::array<std::uint8_t, 16>, 10> kSigma{{
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
}};

[[nodiscard]] constexpr std::uint32_t rotate_right(std::uint32_t value, unsigned bits) noexcept {
  return (value >> bits) | (value << (32U - bits));
}

[[nodiscard]] constexpr std::uint32_t load_le32(const std::byte* bytes) noexcept {
  return static_cast<std::uint32_t>(bytes[0]) |
         (static_cast<std::uint32_t>(bytes[1]) << 8U) |
         (static_cast<std::uint32_t>(bytes[2]) << 16U) |
         (static_cast<std::uint32_t>(bytes[3]) << 24U);
}

constexpr void store_le32(std::byte* bytes, std::uint32_t value) noexcept {
  bytes[0] = static_cast<std::byte>(value & 0xFFU);
  bytes[1] = static_cast<std::byte>((value >> 8U) & 0xFFU);
  bytes[2] = static_cast<std::byte>((value >> 16U) & 0xFFU);
  bytes[3] = static_cast<std::byte>((value >> 24U) & 0xFFU);
}

constexpr void mix(std::array<std::uint32_t, 16>& v, std::size_t a, std::size_t b, std::size_t c,
                   std::size_t d, std::uint32_t x, std::uint32_t y) noexcept {
  v[a] = v[a] + v[b] + x;
  v[d] = rotate_right(v[d] ^ v[a], 16);
  v[c] = v[c] + v[d];
  v[b] = rotate_right(v[b] ^ v[c], 12);
  v[a] = v[a] + v[b] + y;
  v[d] = rotate_right(v[d] ^ v[a], 8);
  v[c] = v[c] + v[d];
  v[b] = rotate_right(v[b] ^ v[c], 7);
}

}

Blake2s::Blake2s(std::size_t digest_size, std::span<const std::byte> key) noexcept {
  digest_size_ = std::clamp(digest_size, std::size_t{1}, kMaximumDigestSize);
  const auto key_length = std::min(key.size(), kMaximumKeySize);

  state_ = kInitialisationVector;

  state_[0] ^= 0x0101'0000U | (static_cast<std::uint32_t>(key_length) << 8U) |
               static_cast<std::uint32_t>(digest_size_);

  if (key_length > 0) {
    std::array<std::byte, kBlockSize> block{};
    std::copy_n(key.begin(), key_length, block.begin());
    update(block);
  }
}

void Blake2s::compress(bool last) noexcept {
  std::array<std::uint32_t, 16> message{};
  for (std::size_t index = 0; index < 16; ++index) {
    message[index] = load_le32(buffer_.data() + index * 4);
  }

  std::array<std::uint32_t, 16> v{};
  std::copy(state_.begin(), state_.end(), v.begin());
  std::copy(kInitialisationVector.begin(), kInitialisationVector.end(), v.begin() + 8);

  v[12] ^= static_cast<std::uint32_t>(counter_ & 0xFFFF'FFFFU);
  v[13] ^= static_cast<std::uint32_t>(counter_ >> 32U);
  if (last) v[14] = ~v[14];

  for (std::size_t round = 0; round < 10; ++round) {
    const auto& s = kSigma[round];
    mix(v, 0, 4, 8, 12, message[s[0]], message[s[1]]);
    mix(v, 1, 5, 9, 13, message[s[2]], message[s[3]]);
    mix(v, 2, 6, 10, 14, message[s[4]], message[s[5]]);
    mix(v, 3, 7, 11, 15, message[s[6]], message[s[7]]);
    mix(v, 0, 5, 10, 15, message[s[8]], message[s[9]]);
    mix(v, 1, 6, 11, 12, message[s[10]], message[s[11]]);
    mix(v, 2, 7, 8, 13, message[s[12]], message[s[13]]);
    mix(v, 3, 4, 9, 14, message[s[14]], message[s[15]]);
  }

  for (std::size_t index = 0; index < 8; ++index) {
    state_[index] ^= v[index] ^ v[index + 8];
  }
}

void Blake2s::update(std::span<const std::byte> input) noexcept {
  if (finished_) return;

  std::size_t offset = 0;
  while (offset < input.size()) {
    if (buffered_ == kBlockSize) {
      counter_ += kBlockSize;
      compress(false);
      buffered_ = 0;
    }

    const auto take = std::min(kBlockSize - buffered_, input.size() - offset);
    std::copy_n(input.begin() + static_cast<std::ptrdiff_t>(offset), take,
                buffer_.begin() + static_cast<std::ptrdiff_t>(buffered_));
    buffered_ += take;
    offset += take;
  }
}

void Blake2s::finish(std::span<std::byte> out) noexcept {
  if (finished_) return;
  finished_ = true;

  counter_ += buffered_;

  std::fill(buffer_.begin() + static_cast<std::ptrdiff_t>(buffered_), buffer_.end(), std::byte{0});
  compress(true);

  std::array<std::byte, kMaximumDigestSize> digest{};
  for (std::size_t index = 0; index < 8; ++index) {
    store_le32(digest.data() + index * 4, state_[index]);
  }

  const auto length = std::min(out.size(), digest_size_);
  std::copy_n(digest.begin(), length, out.begin());
}

Blake2s::Digest Blake2s::hash(std::span<const std::byte> input,
                              std::span<const std::byte> key) noexcept {
  Blake2s state{kMaximumDigestSize, key};
  state.update(input);
  Digest digest{};
  state.finish(digest);
  return digest;
}

Blake2s::Digest hmac_blake2s(std::span<const std::byte> key,
                             std::span<const std::byte> message) noexcept {
  std::array<std::byte, Blake2s::kBlockSize> padded{};
  if (key.size() > Blake2s::kBlockSize) {
    const auto digest = Blake2s::hash(key);
    std::copy(digest.begin(), digest.end(), padded.begin());
  } else {
    std::copy(key.begin(), key.end(), padded.begin());
  }

  std::array<std::byte, Blake2s::kBlockSize> inner_pad{};
  std::array<std::byte, Blake2s::kBlockSize> outer_pad{};
  for (std::size_t index = 0; index < Blake2s::kBlockSize; ++index) {
    inner_pad[index] = padded[index] ^ std::byte{0x36};
    outer_pad[index] = padded[index] ^ std::byte{0x5C};
  }

  Blake2s inner;
  inner.update(inner_pad);
  inner.update(message);
  Blake2s::Digest inner_digest{};
  inner.finish(inner_digest);

  Blake2s outer;
  outer.update(outer_pad);
  outer.update(inner_digest);
  Blake2s::Digest result{};
  outer.finish(result);
  return result;
}

Blake2s::Digest hkdf_extract(std::span<const std::byte> salt,
                             std::span<const std::byte> input) noexcept {
  return hmac_blake2s(salt, input);
}

bool hkdf_expand(std::span<const std::byte> pseudorandom_key, std::span<const std::byte> info,
                 std::span<std::byte> out) noexcept {
  constexpr std::size_t kHashLength = Blake2s::kMaximumDigestSize;

  if (out.size() > 255U * kHashLength) return false;

  Blake2s::Digest previous{};
  std::size_t produced = 0;
  std::uint8_t counter = 1;

  while (produced < out.size()) {
    Blake2s inner;
    std::array<std::byte, Blake2s::kBlockSize> inner_pad{};
    std::array<std::byte, Blake2s::kBlockSize> outer_pad{};
    {
      std::array<std::byte, Blake2s::kBlockSize> padded{};
      if (pseudorandom_key.size() > Blake2s::kBlockSize) {
        const auto digest = Blake2s::hash(pseudorandom_key);
        std::copy(digest.begin(), digest.end(), padded.begin());
      } else {
        std::copy(pseudorandom_key.begin(), pseudorandom_key.end(), padded.begin());
      }
      for (std::size_t index = 0; index < Blake2s::kBlockSize; ++index) {
        inner_pad[index] = padded[index] ^ std::byte{0x36};
        outer_pad[index] = padded[index] ^ std::byte{0x5C};
      }
    }

    inner.update(inner_pad);

    if (counter > 1) inner.update(previous);
    inner.update(info);
    const std::array<std::byte, 1> counter_byte{static_cast<std::byte>(counter)};
    inner.update(counter_byte);

    Blake2s::Digest inner_digest{};
    inner.finish(inner_digest);

    Blake2s outer;
    outer.update(outer_pad);
    outer.update(inner_digest);
    outer.finish(previous);

    const auto take = std::min(kHashLength, out.size() - produced);
    std::copy_n(previous.begin(), take, out.begin() + static_cast<std::ptrdiff_t>(produced));
    produced += take;
    ++counter;
  }
  return true;
}

}
