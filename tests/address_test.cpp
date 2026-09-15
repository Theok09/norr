#include <array>
#include "check.hpp"
#include <cstddef>
#include <string_view>

#include "norr/address.hpp"
#include "norr/ip_packet.hpp"

namespace {

norr::Address address_of(std::string_view text) {
  const auto parsed = norr::parse_address(text);
  NORR_CHECK(parsed.has_value());
  return *parsed;
}

norr::Prefix prefix_of(std::string_view text) {
  const auto parsed = norr::parse_prefix(text);
  NORR_CHECK(parsed.has_value());
  return *parsed;
}

bool address_rejected(std::string_view text) { return !norr::parse_address(text).has_value(); }
bool prefix_rejected(std::string_view text) { return !norr::parse_prefix(text).has_value(); }

// Builds a minimal well-formed IPv4 header with the given addresses.
std::array<std::byte, 20> make_ipv4(std::uint8_t ttl, std::array<std::uint8_t, 4> source,
                                    std::array<std::uint8_t, 4> destination) {
  std::array<std::byte, 20> packet{};
  packet[0] = std::byte{0x45};
  packet[2] = std::byte{0};
  packet[3] = std::byte{20};
  packet[8] = static_cast<std::byte>(ttl);
  packet[9] = std::byte{6};
  for (std::size_t index = 0; index < 4; ++index) {
    packet[12 + index] = static_cast<std::byte>(source[index]);
    packet[16 + index] = static_cast<std::byte>(destination[index]);
  }
  return packet;
}

}  // namespace

int main() {
  // IPv4 parsing.
  NORR_CHECK(address_of("10.0.0.1").family() == norr::AddressFamily::ipv4);
  NORR_CHECK(address_of("0.0.0.0") == address_of("0.0.0.0"));
  NORR_CHECK(address_of("255.255.255.255").to_string() == "255.255.255.255");
  NORR_CHECK(address_of("192.168.1.10").to_string() == "192.168.1.10");

  NORR_CHECK(address_rejected("10.0.0"));
  NORR_CHECK(address_rejected("10.0.0.1.2"));
  NORR_CHECK(address_rejected("256.0.0.1"));
  NORR_CHECK(address_rejected("10.0.0."));
  NORR_CHECK(address_rejected(""));
  // Leading zeros are ambiguous between decimal and octal readings.
  NORR_CHECK(address_rejected("010.0.0.1"));

  // IPv6 parsing, including compression.
  NORR_CHECK(address_of("::1").family() == norr::AddressFamily::ipv6);
  NORR_CHECK(address_of("::1").to_string() == "0000:0000:0000:0000:0000:0000:0000:0001");
  NORR_CHECK(address_of("2001:db8::1") == address_of("2001:0db8:0000:0000:0000:0000:0000:0001"));
  NORR_CHECK(address_of("fe80::") == address_of("fe80:0000:0000:0000:0000:0000:0000:0000"));
  NORR_CHECK(address_of("::") == address_of("0:0:0:0:0:0:0:0"));

  NORR_CHECK(address_rejected("2001:db8::1::2"));
  NORR_CHECK(address_rejected("2001:db8:0:0:0:0:0:0:1"));
  NORR_CHECK(address_rejected("2001:db8"));
  NORR_CHECK(address_rejected("12345::1"));
  // "::" must stand for at least one zero hextet.
  NORR_CHECK(address_rejected("1:2:3:4:5:6:7::8"));

  // Prefixes are canonicalised, so a host bit set below the prefix length is
  // cleared rather than silently making a narrower route.
  NORR_CHECK(prefix_of("10.1.2.3/8") == prefix_of("10.0.0.0/8"));
  NORR_CHECK(prefix_of("2001:db8::ffff/32") == prefix_of("2001:db8::/32"));
  NORR_CHECK(prefix_of("10.0.0.0/8").to_string() == "10.0.0.0/8");

  NORR_CHECK(prefix_rejected("10.0.0.0/33"));
  NORR_CHECK(prefix_rejected("2001:db8::/129"));
  NORR_CHECK(prefix_rejected("10.0.0.0"));
  NORR_CHECK(prefix_rejected("10.0.0.0/"));
  NORR_CHECK(prefix_rejected("10.0.0.0/08"));

  // Containment, including the boundaries of a prefix that is not octet-aligned.
  NORR_CHECK(prefix_of("10.0.0.0/8").contains(address_of("10.255.255.255")));
  NORR_CHECK(!prefix_of("10.0.0.0/8").contains(address_of("11.0.0.0")));
  NORR_CHECK(prefix_of("10.0.0.0/0").contains(address_of("1.2.3.4")));
  NORR_CHECK(prefix_of("192.168.0.0/23").contains(address_of("192.168.1.255")));
  NORR_CHECK(!prefix_of("192.168.0.0/23").contains(address_of("192.168.2.0")));
  NORR_CHECK(prefix_of("10.0.0.5/32").contains(address_of("10.0.0.5")));
  NORR_CHECK(!prefix_of("10.0.0.5/32").contains(address_of("10.0.0.6")));

  // A prefix never matches across address families.
  NORR_CHECK(!prefix_of("10.0.0.0/8").contains(address_of("::1")));
  NORR_CHECK(!prefix_of("2001:db8::/32").contains(address_of("10.0.0.1")));

  // Address classification.
  NORR_CHECK(norr::is_multicast(address_of("224.0.0.1")));
  NORR_CHECK(norr::is_multicast(address_of("239.255.255.255")));
  NORR_CHECK(!norr::is_multicast(address_of("223.255.255.255")));
  NORR_CHECK(norr::is_multicast(address_of("ff02::1")));
  NORR_CHECK(!norr::is_multicast(address_of("2001:db8::1")));
  NORR_CHECK(norr::is_unspecified(address_of("0.0.0.0")));
  NORR_CHECK(norr::is_unspecified(address_of("::")));
  NORR_CHECK(!norr::is_unspecified(address_of("0.0.0.1")));
  NORR_CHECK(norr::is_loopback(address_of("127.0.0.1")));
  NORR_CHECK(norr::is_loopback(address_of("::1")));
  NORR_CHECK(!norr::is_loopback(address_of("128.0.0.1")));

  // IPv4 packet parsing.
  {
    const auto packet = make_ipv4(64, {10, 0, 0, 1}, {10, 0, 0, 2});
    const auto parsed = norr::parse_ip_packet(packet);
    NORR_CHECK(parsed.has_value());
    NORR_CHECK(parsed->family == norr::AddressFamily::ipv4);
    NORR_CHECK(parsed->source == address_of("10.0.0.1"));
    NORR_CHECK(parsed->destination == address_of("10.0.0.2"));
    NORR_CHECK(parsed->hop_limit == 64);
    NORR_CHECK(parsed->protocol == 6);
    NORR_CHECK(parsed->header_length == norr::kIpv4HeaderSize);
    NORR_CHECK(parsed->total_length == packet.size());
  }

  // A declared total length that does not match the bytes present is refused.
  {
    auto packet = make_ipv4(64, {10, 0, 0, 1}, {10, 0, 0, 2});
    packet[3] = std::byte{40};
    const auto parsed = norr::parse_ip_packet(packet);
    NORR_CHECK(!parsed.has_value() && parsed.error() == norr::Error::payload_length_mismatch);
  }

  // IHL below five would place the header inside its own fixed fields.
  {
    auto packet = make_ipv4(64, {10, 0, 0, 1}, {10, 0, 0, 2});
    packet[0] = std::byte{0x44};
    NORR_CHECK(!norr::parse_ip_packet(packet).has_value());
  }

  // Truncated and empty input.
  {
    constexpr std::array<std::byte, 8> truncated{std::byte{0x45}};
    NORR_CHECK(!norr::parse_ip_packet(truncated).has_value());
    NORR_CHECK(!norr::parse_ip_packet(std::span<const std::byte>{}).has_value());
  }

  // An unknown IP version is rejected rather than guessed at.
  {
    auto packet = make_ipv4(64, {10, 0, 0, 1}, {10, 0, 0, 2});
    packet[0] = std::byte{0x55};
    const auto parsed = norr::parse_ip_packet(packet);
    NORR_CHECK(!parsed.has_value() && parsed.error() == norr::Error::unsupported_version);
  }

  // IPv6 packet parsing. The length field excludes the fixed header.
  {
    std::array<std::byte, 40> packet{};
    packet[0] = std::byte{0x60};
    packet[4] = std::byte{0};
    packet[5] = std::byte{0};
    packet[6] = std::byte{17};
    packet[7] = std::byte{64};
    packet[8] = std::byte{0x20};
    packet[9] = std::byte{0x01};
    packet[24] = std::byte{0x20};
    packet[25] = std::byte{0x01};
    packet[39] = std::byte{1};

    const auto parsed = norr::parse_ip_packet(packet);
    NORR_CHECK(parsed.has_value());
    NORR_CHECK(parsed->family == norr::AddressFamily::ipv6);
    NORR_CHECK(parsed->hop_limit == 64);
    NORR_CHECK(parsed->protocol == 17);
    NORR_CHECK(parsed->header_length == norr::kIpv6HeaderSize);
    NORR_CHECK(parsed->total_length == packet.size());

    auto mismatched = packet;
    mismatched[5] = std::byte{8};
    NORR_CHECK(!norr::parse_ip_packet(mismatched).has_value());
  }
}
