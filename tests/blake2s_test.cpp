// BLAKE2s verified against RFC 7693 and the reference test-vector set.
//
// A hash implementation that has not been checked against the specification's
// own vectors is worthless, so these run before anything in the project is
// allowed to depend on it.

#include <array>
#include "check.hpp"
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "norr/blake2s.hpp"

namespace {

[[nodiscard]] std::vector<std::byte> from_hex(std::string_view hex) {
  NORR_CHECK(hex.size() % 2 == 0);
  std::vector<std::byte> bytes;
  bytes.reserve(hex.size() / 2);
  const auto value = [](char character) -> int {
    if (character >= '0' && character <= '9') return character - '0';
    if (character >= 'a' && character <= 'f') return character - 'a' + 10;
    if (character >= 'A' && character <= 'F') return character - 'A' + 10;
    NORR_CHECK(false);
    return 0;
  };
  for (std::size_t index = 0; index < hex.size(); index += 2) {
    bytes.push_back(static_cast<std::byte>((value(hex[index]) << 4) | value(hex[index + 1])));
  }
  return bytes;
}

[[nodiscard]] std::string to_hex(std::span<const std::byte> bytes) {
  constexpr char kDigits[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (const auto byte : bytes) {
    const auto value = static_cast<std::uint8_t>(byte);
    out.push_back(kDigits[value >> 4U]);
    out.push_back(kDigits[value & 0x0FU]);
  }
  return out;
}

[[nodiscard]] std::vector<std::byte> as_bytes(std::string_view text) {
  std::vector<std::byte> bytes;
  bytes.reserve(text.size());
  for (const char character : text) {
    bytes.push_back(static_cast<std::byte>(static_cast<unsigned char>(character)));
  }
  return bytes;
}

void check_hash(std::string_view input_hex, std::string_view expected_hex) {
  const auto input = from_hex(input_hex);
  const auto digest = norr::Blake2s::hash(input);
  NORR_CHECK(to_hex(digest) == expected_hex);
}

}  // namespace

int main() {
  // RFC 7693 appendix B: BLAKE2s-256 of "abc".
  {
    const auto input = as_bytes("abc");
    const auto digest = norr::Blake2s::hash(input);
    NORR_CHECK(to_hex(digest) == "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
  }

  // Empty input.
  check_hash("", "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9");

  // Unkeyed, increasing length. Cross-checked against an independent reference
  // implementation (Python hashlib.blake2s) rather than transcribed by hand.
  check_hash("00", "e34d74dbaf4ff4c6abd871cc220451d2ea2648846c7757fbaac82fe51ad64bea");
  check_hash("0001", "ddad9ab15dac4549ba42f49d262496bef6c0bae1dd342a8808f8ea267c6e210c");
  check_hash("000102", "e8f91c6ef232a041452ab0e149070cdd7dd1769e75b3a5921be37876c45c9900");
  check_hash("00010203", "0cc70e00348b86ba2944d0c32038b25c55584f90df2304f55fa332af5fb01e20");
  check_hash("0001020304", "ec1964191087a4fe9df1c795342a02ffc191a5b251764856ae5b8b5769f0c6cd");

  // A block boundary is the classic place for a buffering bug: 64 bytes is
  // exactly one BLAKE2s block, 65 is one block plus one byte.
  {
    std::vector<std::byte> block(64);
    for (std::size_t index = 0; index < block.size(); ++index) {
      block[index] = static_cast<std::byte>(index);
    }
    const auto one_shot = norr::Blake2s::hash(block);

    // Feeding the same bytes in fragments must give the same digest.
    norr::Blake2s split;
    split.update(std::span{block}.first(1));
    split.update(std::span{block}.subspan(1, 30));
    split.update(std::span{block}.subspan(31, 33));
    norr::Blake2s::Digest streamed{};
    split.finish(streamed);
    NORR_CHECK(to_hex(one_shot) == to_hex(streamed));

    // Byte-at-a-time must also agree.
    norr::Blake2s byte_wise;
    for (const auto byte : block) {
      const std::array<std::byte, 1> single{byte};
      byte_wise.update(single);
    }
    norr::Blake2s::Digest incremental{};
    byte_wise.finish(incremental);
    NORR_CHECK(to_hex(one_shot) == to_hex(incremental));
  }

  // Multi-block input, to exercise the counter across several compressions.
  {
    std::vector<std::byte> long_input(1000);
    for (std::size_t index = 0; index < long_input.size(); ++index) {
      long_input[index] = static_cast<std::byte>(index % 251);
    }
    const auto one_shot = norr::Blake2s::hash(long_input);

    norr::Blake2s chunked;
    chunked.update(std::span{long_input}.first(64));
    chunked.update(std::span{long_input}.subspan(64, 128));
    chunked.update(std::span{long_input}.subspan(192));
    norr::Blake2s::Digest streamed{};
    chunked.finish(streamed);
    NORR_CHECK(to_hex(one_shot) == to_hex(streamed));
  }

  // Keyed hashing. RFC 7693 vector: key = 00..1f, input empty.
  {
    const auto key = from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    const auto digest = norr::Blake2s::hash({}, key);
    NORR_CHECK(to_hex(digest) == "48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49");
  }

  // Keyed, one byte of input.
  {
    const auto key = from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    const auto input = from_hex("00");
    const auto digest = norr::Blake2s::hash(input, key);
    NORR_CHECK(to_hex(digest) == "40d15fee7c328830166ac3f918650f807e7e01e177258cdc0a39b11f598066f1");
  }

  // A shorter digest is a different function, not a truncation of the long one.
  {
    const auto input = as_bytes("abc");
    norr::Blake2s short_hash{16};
    short_hash.update(input);
    std::array<std::byte, 16> digest{};
    short_hash.finish(digest);
    NORR_CHECK(short_hash.digest_size() == 16);

    const auto full = norr::Blake2s::hash(input);
    NORR_CHECK(to_hex(digest) != to_hex(std::span{full}.first(16)));
    // Pinned so the parameter block cannot change unnoticed.
    NORR_CHECK(to_hex(digest) == "aa4938119b1dc7b87cbad0ffd200d0ae");
  }

  // HMAC-BLAKE2s pinned against an independent reference
  // (Python hmac.new(key, msg, hashlib.blake2s)), so this is standard HMAC and
  // not BLAKE2s' own keying mode, which Noise does not use here.
  {
    NORR_CHECK(to_hex(norr::hmac_blake2s(as_bytes("key"), as_bytes("message"))) ==
           "bba8fa28708ae80d249e317318c95c859f3f77512be23910d5094d9110454d6f");
    NORR_CHECK(to_hex(norr::hmac_blake2s({}, {})) ==
           "eaf4bb25938f4d20e72656bbbc7a9bf63c0c18537333c35bdb67db1402661acd");

    const std::vector<std::byte> long_key_pinned(200, std::byte{0xAB});
    NORR_CHECK(to_hex(norr::hmac_blake2s(long_key_pinned, as_bytes("message"))) ==
           "cf54e73d537f905cab8f3e958e909ed038b32018ef1594652b47cd957ee959bf");
  }

  // HKDF-BLAKE2s pinned against the same reference construction.
  {
    const auto prk = norr::hkdf_extract(as_bytes("salt"), as_bytes("input key material"));
    NORR_CHECK(to_hex(prk) == "09f303b9c960680e085fc497cb95abd332cea76c2ec3fe5a9ce2312d4f5490c8");

    const auto info = as_bytes("norr v1:data:i2r:");
    std::array<std::byte, 32> one{};
    NORR_CHECK(norr::hkdf_expand(prk, info, one));
    NORR_CHECK(to_hex(one) == "0c68950434d2e35c75829482d3079b74f92e195c9233bdcd224876dbf6e51ada");

    std::array<std::byte, 96> three{};
    NORR_CHECK(norr::hkdf_expand(prk, info, three));
    NORR_CHECK(to_hex(three) ==
           "0c68950434d2e35c75829482d3079b74f92e195c9233bdcd224876dbf6e51ada"
           "c62aed353ada5477ffa1bb05d4f00cc652138286099c5c42b7fa0e4bb0f3807b"
           "9ffeee690747318af492e24afa80b15c9d9bd1eb041e2def33ed35ee9b2c83a8");
  }

  // HMAC and HKDF are deterministic and separate every input.
  {
    const auto key = as_bytes("key");
    const auto message = as_bytes("message");
    const auto first = norr::hmac_blake2s(key, message);
    const auto second = norr::hmac_blake2s(key, message);
    NORR_CHECK(to_hex(first) == to_hex(second));

    const auto other_key = as_bytes("keY");
    NORR_CHECK(to_hex(norr::hmac_blake2s(other_key, message)) != to_hex(first));

    const auto other_message = as_bytes("messagE");
    NORR_CHECK(to_hex(norr::hmac_blake2s(key, other_message)) != to_hex(first));

    // A key longer than the block size is hashed down, not truncated.
    std::vector<std::byte> long_key(200, std::byte{0xAB});
    const auto long_key_mac = norr::hmac_blake2s(long_key, message);
    std::vector<std::byte> other_long_key(200, std::byte{0xAB});
    other_long_key[199] = std::byte{0xAC};
    NORR_CHECK(to_hex(norr::hmac_blake2s(other_long_key, message)) != to_hex(long_key_mac));
  }

  // HKDF expansion: length is honoured, output is a prefix-stable stream, and
  // every input separates the result.
  {
    const auto salt = as_bytes("salt");
    const auto secret = as_bytes("input key material");
    const auto pseudorandom = norr::hkdf_extract(salt, secret);

    const auto info = as_bytes("norr v1:data:i2r:");
    std::array<std::byte, 32> first_block{};
    NORR_CHECK(norr::hkdf_expand(pseudorandom, info, first_block));

    std::array<std::byte, 96> three_blocks{};
    NORR_CHECK(norr::hkdf_expand(pseudorandom, info, three_blocks));
    // The first 32 bytes of a longer expansion equal the shorter expansion.
    NORR_CHECK(to_hex(first_block) == to_hex(std::span{three_blocks}.first(32)));

    // Different info must give different key material; this is what makes the
    // key-schedule labels in crypto/key-schedule.md meaningful.
    const auto other_info = as_bytes("norr v1:data:r2i:");
    std::array<std::byte, 32> other{};
    NORR_CHECK(norr::hkdf_expand(pseudorandom, other_info, other));
    NORR_CHECK(to_hex(other) != to_hex(first_block));

    // Expansion beyond 255 blocks is refused rather than silently wrapping the
    // counter, which would repeat key material.
    std::vector<std::byte> too_long(255U * 32U + 1U);
    NORR_CHECK(!norr::hkdf_expand(pseudorandom, info, too_long));

    std::vector<std::byte> exactly_max(255U * 32U);
    NORR_CHECK(norr::hkdf_expand(pseudorandom, info, exactly_max));
  }
}
