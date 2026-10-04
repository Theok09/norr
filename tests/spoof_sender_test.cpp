#include "check.hpp"
#include <cstdio>
#include <vector>

#include "norr/spoof_sender.hpp"
#include "norr/spooftest.hpp"

namespace {
std::uint32_t ip(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) {
  return (static_cast<std::uint32_t>(a) << 24U) | (static_cast<std::uint32_t>(b) << 16U) |
         (static_cast<std::uint32_t>(c) << 8U) | static_cast<std::uint32_t>(d);
}

void test_build_into_matches_builder() {
  norr::SpoofSender sender;
  const std::vector<std::byte> payload(32, std::byte{0xAB});
  const norr::SpoofDatagram datagram{.source_be = ip(94, 183, 218, 150),
                                     .destination_be = ip(45, 135, 195, 61),
                                     .source_port = 40000,
                                     .destination_port = 443,
                                     .payload = payload};
  std::array<std::byte, 20 + 8 + 32> a{};
  std::array<std::byte, 20 + 8 + 32> b{};
  const auto na = sender.build_into(datagram, a);
  const auto nb = norr::build_spoofed_udp(datagram.source_be, datagram.destination_be,
                                          datagram.source_port, datagram.destination_port,
                                          payload, b);
  NORR_CHECK(na == nb);
  NORR_CHECK(na == 20 + 8 + 32);
  for (std::size_t i = 0; i < a.size(); ++i) {
    if (i == 4 || i == 5 || i == 10 || i == 11) continue;
    NORR_CHECK(a[i] == b[i]);
  }
  std::puts("spoof_sender: build_into matches build_spoofed_udp (ex IP-ID/checksum) OK");

  std::array<std::byte, 20 + 8 + 32> c{};
  std::array<std::byte, 20 + 8 + 32> d{};
  static_cast<void>(norr::build_spoofed_udp(datagram.source_be, datagram.destination_be,
                                            datagram.source_port, datagram.destination_port,
                                            payload, c));
  static_cast<void>(norr::build_spoofed_udp(datagram.source_be, datagram.destination_be,
                                            datagram.source_port, datagram.destination_port,
                                            payload, d));
  NORR_CHECK(!(c[4] == d[4] && c[5] == d[5]));
  std::puts("spoof_sender: IP-ID varies between packets of the same flow OK");
}

void test_built_header_fields() {
  norr::SpoofSender sender;
  const std::vector<std::byte> payload(16, std::byte{0x11});
  const auto src = ip(62, 60, 164, 120);
  const auto dst = ip(45, 135, 195, 61);
  const norr::SpoofDatagram datagram{.source_be = src,
                                     .destination_be = dst,
                                     .source_port = 1234,
                                     .destination_port = 5678,
                                     .payload = payload};
  std::array<std::byte, 20 + 8 + 16> packet{};
  const auto n = sender.build_into(datagram, packet);
  NORR_CHECK(n == packet.size());

  const auto be32 = [&](std::size_t off) {
    return (static_cast<std::uint32_t>(packet[off]) << 24U) |
           (static_cast<std::uint32_t>(packet[off + 1]) << 16U) |
           (static_cast<std::uint32_t>(packet[off + 2]) << 8U) |
           static_cast<std::uint32_t>(packet[off + 3]);
  };
  NORR_CHECK(static_cast<std::uint8_t>(packet[0]) == 0x45);
  NORR_CHECK(static_cast<std::uint8_t>(packet[9]) == 17);
  NORR_CHECK(be32(12) == src);
  NORR_CHECK(be32(16) == dst);
  std::puts("spoof_sender: built packet carries the spoofed source in the IP header OK");
}

void test_platform_gate() {
  norr::SpoofSender sender;
  if (!norr::SpoofSender::supported()) {
    const auto opened = sender.open();
    NORR_CHECK(!opened.has_value());
    NORR_CHECK(opened.error() == norr::SpoofSendError::unsupported_platform);
    std::puts("spoof_sender: non-Linux reports unsupported_platform OK");
  } else {
    std::puts("spoof_sender: Linux platform, raw socket path compiled OK");
  }
}

void test_send_without_open_fails() {
  norr::SpoofSender sender;
  const std::vector<std::byte> payload(8, std::byte{0});
  const norr::SpoofDatagram datagram{.source_be = ip(1, 2, 3, 4),
                                     .destination_be = ip(5, 6, 7, 8),
                                     .source_port = 1,
                                     .destination_port = 2,
                                     .payload = payload};
  const std::vector<norr::SpoofDatagram> batch{datagram};
  const auto result = sender.send_batch(batch);
  NORR_CHECK(!result.has_value());
  std::puts("spoof_sender: send before open is rejected OK");
}
}

int main() {
  test_build_into_matches_builder();
  test_built_header_fields();
  test_platform_gate();
  test_send_without_open_fails();
  std::puts("spoof_sender: all tests passed");
  return 0;
}
