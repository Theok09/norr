#include <array>
#include <algorithm>
#include "check.hpp"
#include <cstddef>
#include <cstdio>
#include <span>
#include <vector>

#include "norr/icmp_transport.hpp"

namespace {
void test_checksum_zero_when_valid() {
  std::array<std::byte, 40> pkt{};
  std::vector<std::byte> pay(32);
  for (std::size_t i = 0; i < pay.size(); ++i) pay[i] = static_cast<std::byte>(i);
  const auto n = norr::build_icmp_echo(norr::kIcmpEchoRequest, norr::kNorrIcmpId, 7, pay, pkt);
  NORR_CHECK(n == norr::kIcmpHeaderSize + pay.size());
  NORR_CHECK(norr::icmp_checksum(std::span{pkt}.first(n)) == 0);
  std::puts("icmp: checksum verifies to zero over a valid echo OK");
}

void test_build_parse_roundtrip() {
  std::vector<std::byte> pay(100);
  for (std::size_t i = 0; i < pay.size(); ++i) pay[i] = static_cast<std::byte>(i * 3);
  std::array<std::byte, 200> pkt{};
  const auto n = norr::build_icmp_echo(norr::kIcmpEchoReply, norr::kNorrIcmpId, 42, pay, pkt);
  const auto v = norr::parse_icmp_echo(std::span{pkt}.first(n), false);
  NORR_CHECK(v.has_value());
  NORR_CHECK(v->type == norr::kIcmpEchoReply);
  NORR_CHECK(v->identifier == norr::kNorrIcmpId);
  NORR_CHECK(v->sequence == 42);
  NORR_CHECK(v->payload.size() == pay.size());
  NORR_CHECK(std::equal(pay.begin(), pay.end(), v->payload.begin()));
  std::puts("icmp: build/parse echo round-trips payload OK");
}

void test_parse_skips_ip_header() {
  std::vector<std::byte> pay(20, std::byte{0xAB});
  std::array<std::byte, 64> icmp{};
  const auto n = norr::build_icmp_echo(norr::kIcmpEchoRequest, norr::kNorrIcmpId, 1, pay, icmp);
  std::vector<std::byte> wire;
  wire.push_back(std::byte{0x45});
  wire.resize(20, std::byte{0});
  wire.insert(wire.end(), icmp.begin(), icmp.begin() + static_cast<std::ptrdiff_t>(n));
  const auto v = norr::parse_icmp_echo(wire, true);
  NORR_CHECK(v.has_value());
  NORR_CHECK(v->payload.size() == pay.size());
  NORR_CHECK(v->identifier == norr::kNorrIcmpId);
  std::puts("icmp: parse skips the 20-byte IPv4 header OK");
}

void test_short_datagram_rejected() {
  std::array<std::byte, 4> tiny{};
  NORR_CHECK(!norr::parse_icmp_echo(tiny, false).has_value());
  std::puts("icmp: too-short datagram rejected OK");
}
}

int main() {
  test_checksum_zero_when_valid();
  test_build_parse_roundtrip();
  test_parse_skips_ip_header();
  test_short_datagram_rejected();
  std::puts("icmp: all checks passed");
  return 0;
}
