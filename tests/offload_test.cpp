#include "check.hpp"
#include <algorithm>
#include <cstdio>
#include <vector>

#include "norr/offload.hpp"

namespace {

std::vector<std::byte> tcp_super_packet(bool ipv4, std::size_t payload, std::uint8_t flags) {
  const std::size_t ip = ipv4 ? 20 : 40;
  const std::size_t tcp = 32;
  std::vector<std::byte> packet(ip + tcp + payload);
  if (ipv4) {
    packet[0] = std::byte{0x45};
    packet[4] = std::byte{0x12};
    packet[5] = std::byte{0x34};
    packet[6] = std::byte{0x40};
    packet[8] = std::byte{64};
    packet[9] = std::byte{6};
    const std::uint8_t addresses[8] = {10, 99, 0, 2, 10, 99, 0, 1};
    for (int i = 0; i < 8; ++i) packet[12 + i] = static_cast<std::byte>(addresses[i]);
  } else {
    packet[0] = std::byte{0x60};
    packet[6] = std::byte{6};
    packet[7] = std::byte{64};
    for (int i = 0; i < 32; ++i) packet[8 + i] = static_cast<std::byte>(i % 2 == 0 ? 0xFD : i);
  }
  auto* t = packet.data() + ip;
  t[0] = std::byte{0xC0};
  t[1] = std::byte{0x01};
  t[2] = std::byte{0x14};
  t[3] = std::byte{0x51};
  t[4] = std::byte{0x10};
  t[5] = std::byte{0x20};
  t[6] = std::byte{0x30};
  t[7] = std::byte{0x40};
  t[11] = std::byte{0x77};
  t[12] = std::byte{0x80};
  t[13] = static_cast<std::byte>(flags);
  t[14] = std::byte{0x01};
  t[15] = std::byte{0xF5};
  t[20] = std::byte{0x01};
  t[21] = std::byte{0x01};
  t[22] = std::byte{0x08};
  t[23] = std::byte{0x0A};
  for (std::size_t i = 0; i < payload; ++i) {
    packet[ip + tcp + i] = static_cast<std::byte>((i * 31U + 7U) & 0xFFU);
  }
  return packet;
}

std::vector<std::vector<std::byte>> segment(bool ipv4, std::size_t payload, std::uint16_t mss,
                                            std::uint8_t flags) {
  auto super = tcp_super_packet(ipv4, payload, flags);
  const norr::VirtioHeader header{.flags = norr::kVirtioNeedsChecksum,
                                  .gso_type = ipv4 ? norr::kGsoTcpV4 : norr::kGsoTcpV6,
                                  .header_length = static_cast<std::uint16_t>((ipv4 ? 20 : 40) + 32),
                                  .gso_size = mss,
                                  .checksum_start = static_cast<std::uint16_t>(ipv4 ? 20 : 40),
                                  .checksum_offset = 16};
  std::vector<std::byte> scratch;
  std::vector<std::vector<std::byte>> out;
  NORR_CHECK(norr::expand_offloaded(header, super, scratch, [&](std::span<const std::byte> seg) {
    out.emplace_back(seg.begin(), seg.end());
  }));
  return out;
}

void test_segmentation() {
  for (const bool ipv4 : {true, false}) {
    const auto segments = segment(ipv4, 10000, 1368, 0x18);
    NORR_CHECK(segments.size() == 8);
    const std::size_t ip = ipv4 ? 20 : 40;
    std::uint32_t expected_sequence = 0x10203040;
    std::size_t total = 0;
    for (std::size_t index = 0; index < segments.size(); ++index) {
      const auto& packet = segments[index];
      NORR_CHECK(norr::transport_checksum_valid(packet));
      if (ipv4) {
        NORR_CHECK(norr::fold_checksum(norr::checksum_add(std::span{packet}.first(20))) == 0xFFFF);
        NORR_CHECK(((static_cast<unsigned>(packet[2]) << 8U) | static_cast<unsigned>(packet[3])) ==
                   packet.size());
      }
      const auto* t = packet.data() + ip;
      const auto sequence = (static_cast<std::uint32_t>(t[4]) << 24U) |
                            (static_cast<std::uint32_t>(t[5]) << 16U) |
                            (static_cast<std::uint32_t>(t[6]) << 8U) | static_cast<std::uint32_t>(t[7]);
      NORR_CHECK(sequence == expected_sequence);
      const auto flags = static_cast<std::uint8_t>(t[13]);
      NORR_CHECK(((flags & 0x08) != 0) == (index + 1 == segments.size()));
      const auto payload = packet.size() - ip - 32;
      expected_sequence += static_cast<std::uint32_t>(payload);
      total += payload;
    }
    NORR_CHECK(total == 10000);
  }
  std::puts("offload: TSO segmentation yields valid, ordered segments OK");
}

void test_coalesce_round_trip() {
  for (const bool ipv4 : {true, false}) {
    const auto segments = segment(ipv4, 20000, 1368, 0x18);
    norr::TcpCoalescer coalescer;
    for (const auto& packet : segments) coalescer.add(packet, true);

    std::vector<std::pair<std::vector<std::byte>, std::vector<std::byte>>> writes;
    NORR_CHECK(coalescer.flush([&](std::span<const std::byte> header, std::span<const std::byte> head,
                                   std::span<const std::span<const std::byte>> payloads) {
      std::vector<std::byte> packet(head.begin(), head.end());
      for (const auto piece : payloads) packet.insert(packet.end(), piece.begin(), piece.end());
      writes.emplace_back(std::vector<std::byte>(header.begin(), header.end()), std::move(packet));
    }) == 1);
    NORR_CHECK(coalescer.coalesced() == segments.size() - 1);

    const auto header = norr::parse_virtio_header(writes[0].first);
    NORR_CHECK(header.gso_size == 1368);
    NORR_CHECK(header.gso_type == (ipv4 ? norr::kGsoTcpV4 : norr::kGsoTcpV6));

    std::vector<std::byte> scratch;
    std::vector<std::vector<std::byte>> again;
    auto packet = writes[0].second;
    NORR_CHECK(norr::expand_offloaded(header, packet, scratch, [&](std::span<const std::byte> seg) {
      again.emplace_back(seg.begin(), seg.end());
    }));
    NORR_CHECK(again == segments);
  }
  std::puts("offload: coalesced super-packet re-segments byte-identically OK");
}

void test_coalescer_respects_boundaries() {
  auto segments = segment(true, 6000, 1368, 0x10);
  std::swap(segments[1], segments[2]);
  norr::TcpCoalescer coalescer;
  for (const auto& packet : segments) coalescer.add(packet);
  std::size_t writes = 0;
  coalescer.flush([&](std::span<const std::byte>, std::span<const std::byte>,
                      std::span<const std::span<const std::byte>>) { ++writes; });
  NORR_CHECK(writes > 1);

  norr::TcpCoalescer passthrough;
  std::vector<std::byte> udp(28);
  udp[0] = std::byte{0x45};
  udp[3] = std::byte{28};
  udp[9] = std::byte{17};
  passthrough.add(udp);
  std::vector<std::byte> seen;
  passthrough.flush([&](std::span<const std::byte> header, std::span<const std::byte> head,
                        std::span<const std::span<const std::byte>> payloads) {
    NORR_CHECK(std::ranges::all_of(header, [](std::byte b) { return b == std::byte{0}; }));
    seen.assign(head.begin(), head.end());
    for (const auto piece : payloads) seen.insert(seen.end(), piece.begin(), piece.end());
  });
  NORR_CHECK(seen == udp);
  std::puts("offload: out-of-order and non-TCP packets are not merged OK");
}

void test_partial_checksum_completion() {
  auto packet = segment(true, 500, 1368, 0x18).front();
  const auto correct = packet;
  const auto partial = norr::fold_checksum(norr::pseudo_header_sum(packet, 6, packet.size() - 20));
  packet[36] = static_cast<std::byte>(partial >> 8U);
  packet[37] = static_cast<std::byte>(partial & 0xFFU);
  const norr::VirtioHeader header{.flags = norr::kVirtioNeedsChecksum,
                                  .gso_type = norr::kGsoNone,
                                  .header_length = 0,
                                  .gso_size = 0,
                                  .checksum_start = 20,
                                  .checksum_offset = 16};
  std::vector<std::byte> scratch;
  std::vector<std::byte> out;
  NORR_CHECK(norr::expand_offloaded(header, packet, scratch, [&](std::span<const std::byte> seg) {
    out.assign(seg.begin(), seg.end());
  }));
  NORR_CHECK(out == correct);
  std::puts("offload: partial checksum is completed exactly OK");
}
}

int main() {
  test_segmentation();
  test_coalesce_round_trip();
  test_coalescer_respects_boundaries();
  test_partial_checksum_completion();
  return 0;
}
