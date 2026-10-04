#include <array>
#include <algorithm>
#include "check.hpp"
#include <cstddef>
#include <cstdio>
#include <span>
#include <vector>

#include "norr/crypto.hpp"
#include "norr/obfuscation.hpp"
#include "norr/packet.hpp"

namespace {
norr::PresharedKey make_psk(std::byte fill) {
  norr::PresharedKey psk{};
  std::fill(psk.begin(), psk.end(), fill);
  return psk;
}

std::vector<std::byte> sample_data_packet() {
  std::vector<std::byte> plaintext(64);
  plaintext[0] = static_cast<std::byte>((norr::kProtocolVersion << 4U) |
                                        static_cast<std::uint8_t>(norr::FrameType::data));
  plaintext[1] = std::byte{0x00};
  plaintext[4] = std::byte{0x00};
  plaintext[5] = std::byte{0x10};
  for (std::size_t index = 6; index < plaintext.size(); ++index) {
    plaintext[index] = static_cast<std::byte>(index);
  }
  return plaintext;
}

void test_full_roundtrip() {
  const auto psk = make_psk(std::byte{0xAB});
  norr::Obfuscator sender;
  norr::Obfuscator receiver;
  norr::ObfuscationConfig config{
      .mode = norr::ObfuscationMode::full, .junk_padding = true, .priming = false, .junk_max = 96};
  sender.configure(config, psk);
  receiver.configure(config, psk);

  const auto plaintext = sample_data_packet();
  for (int trial = 0; trial < 64; ++trial) {
    std::vector<std::byte> wire(plaintext.size() + sender.max_overhead());
    const auto wrapped = sender.wrap(plaintext, wire);
    NORR_CHECK(wrapped.has_value());
    NORR_CHECK(*wrapped >= plaintext.size() + norr::kObfuscationNonceSize);

    std::vector<std::byte> out(*wrapped);
    const auto unwrapped = receiver.unwrap(std::span{wire}.first(*wrapped), out);
    NORR_CHECK(unwrapped.has_value());
    NORR_CHECK(*unwrapped == plaintext.size());
    NORR_CHECK(std::equal(plaintext.begin(), plaintext.end(), out.begin()));
  }
  std::puts("obfuscation: full mode round-trips with random junk OK");
}

void test_header_mask_roundtrip() {
  const auto psk = make_psk(std::byte{0x11});
  norr::Obfuscator sender;
  norr::Obfuscator receiver;
  norr::ObfuscationConfig config{.mode = norr::ObfuscationMode::header_mask};
  sender.configure(config, psk);
  receiver.configure(config, psk);

  const auto plaintext = sample_data_packet();
  std::vector<std::byte> wire(plaintext.size() + sender.max_overhead());
  const auto wrapped = sender.wrap(plaintext, wire);
  NORR_CHECK(wrapped.has_value());
  NORR_CHECK(*wrapped == plaintext.size() + norr::kObfuscationNonceSize);

  const auto masked = std::span{wire}.subspan(norr::kObfuscationNonceSize);
  NORR_CHECK(masked[0] != plaintext[0]);
  NORR_CHECK(masked[1] != plaintext[1]);
  NORR_CHECK(masked[5] != plaintext[5]);
  NORR_CHECK(masked[16] == plaintext[16]);

  std::vector<std::byte> out(*wrapped);
  const auto unwrapped = receiver.unwrap(std::span{wire}.first(*wrapped), out);
  NORR_CHECK(unwrapped.has_value());
  NORR_CHECK(*unwrapped == plaintext.size());
  NORR_CHECK(std::equal(plaintext.begin(), plaintext.end(), out.begin()));
  std::puts("obfuscation: header-mask hides the header, preserves body OK");
}

void test_wrong_key_does_not_recover() {
  norr::Obfuscator sender;
  norr::Obfuscator receiver;
  const norr::ObfuscationConfig config{.mode = norr::ObfuscationMode::full,
                                       .junk_padding = true,
                                       .priming = false,
                                       .junk_max = 32};
  sender.configure(config, make_psk(std::byte{0x01}));
  receiver.configure(config, make_psk(std::byte{0x02}));

  const auto plaintext = sample_data_packet();
  std::vector<std::byte> wire(plaintext.size() + sender.max_overhead());
  const auto wrapped = sender.wrap(plaintext, wire);
  NORR_CHECK(wrapped.has_value());

  std::vector<std::byte> out(*wrapped);
  const auto unwrapped = receiver.unwrap(std::span{wire}.first(*wrapped), out);
  const bool rejected_or_wrong =
      !unwrapped.has_value() ||
      *unwrapped != plaintext.size() ||
      !std::equal(plaintext.begin(), plaintext.end(), out.begin());
  NORR_CHECK(rejected_or_wrong);
  std::puts("obfuscation: mismatched key does not reconstruct the packet OK");
}

void test_priming_is_random_sized() {
  norr::Obfuscator obf;
  obf.configure({.mode = norr::ObfuscationMode::full}, make_psk(std::byte{0x55}));
  std::array<std::byte, norr::kPrimingMaxSize> buffer{};
  for (int trial = 0; trial < 16; ++trial) {
    const auto size = obf.generate_priming(buffer);
    NORR_CHECK(size.has_value());
    NORR_CHECK(*size >= norr::kPrimingMinSize);
    NORR_CHECK(*size <= norr::kPrimingMaxSize);
  }
  std::puts("obfuscation: priming packets sit within the configured size band OK");
}

void test_nonce_varies() {
  norr::Obfuscator obf;
  obf.configure({.mode = norr::ObfuscationMode::full}, make_psk(std::byte{0x77}));
  const auto plaintext = sample_data_packet();
  std::vector<std::byte> first(plaintext.size() + obf.max_overhead());
  std::vector<std::byte> second(plaintext.size() + obf.max_overhead());
  const auto a = obf.wrap(plaintext, first);
  const auto b = obf.wrap(plaintext, second);
  NORR_CHECK(a.has_value() && b.has_value());
  NORR_CHECK(!std::equal(first.begin(), first.begin() + norr::kObfuscationNonceSize,
                         second.begin()));
  std::puts("obfuscation: each wrap draws a fresh nonce OK");
}
}

int main() {
  if (!norr::crypto_available()) {
    std::puts("obfuscation: crypto backend absent, skipped");
    return 0;
  }
  NORR_CHECK(norr::crypto_init().has_value());

  test_full_roundtrip();
  test_header_mask_roundtrip();
  test_wrong_key_does_not_recover();
  test_priming_is_random_sized();
  test_nonce_varies();

  std::puts("obfuscation: all checks passed");
  return 0;
}
