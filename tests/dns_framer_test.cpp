#include <cstddef>
#include <cstdio>
#include <cstring>
#include <span>
#include <vector>

#include "check.hpp"
#include "norr/dns_framer.hpp"

namespace {
std::vector<std::byte> bytes_of(const char* text) {
  std::vector<std::byte> out(std::strlen(text));
  std::memcpy(out.data(), text, out.size());
  return out;
}

void round_trip_client_to_server() {
  norr::DnsFramer client;
  norr::DnsFramer server;
  client.configure(norr::DnsRole::client, "mail.example.com");
  server.configure(norr::DnsRole::server, "mail.example.com");

  const auto payload = bytes_of("HELLO-NORR-DNS-PAYLOAD-0123456789");
  std::vector<std::byte> wire(2048);
  std::vector<std::byte> back(2048);

  const auto wrapped = client.wrap(payload, wire);
  NORR_CHECK(wrapped.has_value());
  NORR_CHECK(static_cast<std::uint8_t>(wire[2]) == 0x01);
  NORR_CHECK(static_cast<std::uint8_t>(wire[3]) == 0x00);
  NORR_CHECK(static_cast<std::uint8_t>(wire[5]) == 0x01);

  const auto back_len = server.unwrap(std::span{wire}.first(*wrapped), back);
  NORR_CHECK(back_len.has_value());
  NORR_CHECK(*back_len == payload.size());
  NORR_CHECK(std::memcmp(back.data(), payload.data(), *back_len) == 0);
}

void round_trip_server_to_client() {
  norr::DnsFramer client;
  norr::DnsFramer server;
  client.configure(norr::DnsRole::client, "mail.example.com");
  server.configure(norr::DnsRole::server, "mail.example.com");

  const auto payload = bytes_of("response-direction-payload");
  std::vector<std::byte> wire(2048);
  std::vector<std::byte> back(2048);

  const auto wrapped = server.wrap(payload, wire);
  NORR_CHECK(wrapped.has_value());
  NORR_CHECK(static_cast<std::uint8_t>(wire[2]) == 0x81);
  NORR_CHECK(static_cast<std::uint8_t>(wire[3]) == 0x80);

  const auto back_len = client.unwrap(std::span{wire}.first(*wrapped), back);
  NORR_CHECK(back_len.has_value());
  NORR_CHECK(*back_len == payload.size());
  NORR_CHECK(std::memcmp(back.data(), payload.data(), *back_len) == 0);
}

void empty_payload_survives() {
  norr::DnsFramer client;
  norr::DnsFramer server;
  client.configure(norr::DnsRole::client, "");
  server.configure(norr::DnsRole::server, "");

  std::vector<std::byte> wire(2048);
  std::vector<std::byte> back(2048);
  const auto wrapped = client.wrap({}, wire);
  NORR_CHECK(wrapped.has_value());
  const auto back_len = server.unwrap(std::span{wire}.first(*wrapped), back);
  NORR_CHECK(back_len.has_value());
  NORR_CHECK(*back_len == 0);
}

void truncated_wire_rejected() {
  norr::DnsFramer server;
  server.configure(norr::DnsRole::server, "mail.example.com");
  std::vector<std::byte> wire(5, std::byte{0});
  std::vector<std::byte> back(2048);
  const auto result = server.unwrap(wire, back);
  NORR_CHECK(!result.has_value());
}

void malformed_label_rejected() {
  norr::DnsFramer server;
  server.configure(norr::DnsRole::server, "mail.example.com");
  std::vector<std::byte> wire(40, std::byte{0});
  wire[12] = std::byte{0x40};
  std::vector<std::byte> back(2048);
  const auto result = server.unwrap(wire, back);
  NORR_CHECK(!result.has_value());
}

void oversized_payload_rejected() {
  norr::DnsFramer client;
  client.configure(norr::DnsRole::client, "x");
  std::vector<std::byte> payload(70000, std::byte{0x41});
  std::vector<std::byte> wire(80000);
  const auto result = client.wrap(payload, wire);
  NORR_CHECK(!result.has_value());
}
}

int main() {
  round_trip_client_to_server();
  round_trip_server_to_client();
  empty_payload_survives();
  truncated_wire_rejected();
  malformed_label_rejected();
  oversized_payload_rejected();
  std::printf("dns_framer tests passed\n");
  return 0;
}
