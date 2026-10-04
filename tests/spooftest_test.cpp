// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#include <array>
#include <cstdio>
#include <span>
#include <string_view>
#include <vector>

#include "check.hpp"
#include "norr/spooftest.hpp"

namespace {
std::vector<std::byte> secret_of(std::string_view s) {
  std::vector<std::byte> v;
  for (char c : s) v.push_back(static_cast<std::byte>(static_cast<unsigned char>(c)));
  return v;
}

std::uint32_t ip(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) {
  return (static_cast<std::uint32_t>(a) << 24U) | (static_cast<std::uint32_t>(b) << 16U) |
         (static_cast<std::uint32_t>(c) << 8U) | d;
}

void test_probe_roundtrip() {
  const auto s = secret_of("shared-token");
  const auto src = ip(1, 2, 3, 4), dst = ip(5, 6, 7, 8);
  const auto p = norr::spoof_probe(s, src, dst, 7);
  NORR_CHECK(norr::spoof_probe_sequence(p) == 7);
  NORR_CHECK(norr::spoof_probe_valid(s, p, src, dst));
  std::puts("spooftest: a probe validates against its own source and token OK");
}

void test_wrong_source_rejected() {
  const auto s = secret_of("shared-token");
  const auto p = norr::spoof_probe(s, ip(1, 2, 3, 4), ip(5, 6, 7, 8), 1);
  NORR_CHECK(!norr::spoof_probe_valid(s, p, ip(9, 9, 9, 9), ip(5, 6, 7, 8)));
  NORR_CHECK(!norr::spoof_probe_valid(secret_of("other"), p, ip(1, 2, 3, 4), ip(5, 6, 7, 8)));
  std::puts("spooftest: a probe bound to one forged source is rejected for another OK");
}

void test_packet_checksums() {
  std::array<std::byte, 64> out{};
  std::array<std::byte, 4> payload{std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
  const auto n = norr::build_spoofed_udp(ip(10, 0, 0, 1), ip(10, 0, 0, 2), 4000, 5000, payload, out);
  NORR_CHECK(n == 20 + 8 + 4);
  NORR_CHECK(static_cast<unsigned>(out[0]) == 0x45);
  NORR_CHECK(static_cast<unsigned>(out[9]) == 17);
  NORR_CHECK(norr::ip_checksum(std::span{out}.first(20)) == 0);
  std::puts("spooftest: the forged IP header carries a valid checksum OK");
}
}

int main() {
  NORR_CHECK(norr::crypto_init().has_value());
  test_probe_roundtrip();
  test_wrong_source_rejected();
  test_packet_checksums();
  std::puts("all spooftest-core tests passed");
  return 0;
}
