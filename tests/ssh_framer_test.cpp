#include <cstddef>
#include <cstdio>
#include <cstring>
#include <span>
#include <vector>

#include "check.hpp"
#include "norr/ssh_framer.hpp"

namespace {
std::vector<std::byte> bytes_of(const char* text) {
  std::vector<std::byte> out(std::strlen(text));
  std::memcpy(out.data(), text, out.size());
  return out;
}

void round_trip_and_alignment() {
  norr::SshFramer framer;
  for (std::size_t len : {std::size_t{0}, std::size_t{1}, std::size_t{7}, std::size_t{8},
                          std::size_t{15}, std::size_t{1000}, std::size_t{1400}}) {
    std::vector<std::byte> payload(len);
    for (std::size_t i = 0; i < len; ++i) payload[i] = static_cast<std::byte>(i & 0xFF);
    std::vector<std::byte> wire(len + 64);
    const auto wrapped = framer.wrap(payload, wire);
    NORR_CHECK(wrapped.has_value());
    NORR_CHECK(*wrapped % norr::kSshBlockSize == 0);
    const auto padding = static_cast<std::size_t>(static_cast<std::uint8_t>(wire[4]));
    NORR_CHECK(padding >= norr::kSshMinPadding);

    std::vector<std::byte> back(len + 64);
    std::size_t consumed = 0;
    const auto unwrapped = framer.unwrap(std::span{wire}.first(*wrapped), back, consumed);
    NORR_CHECK(unwrapped.has_value());
    NORR_CHECK(*unwrapped == len);
    NORR_CHECK(consumed == *wrapped);
    NORR_CHECK(std::memcmp(back.data(), payload.data(), len) == 0);
  }
}

void two_records_back_to_back() {
  norr::SshFramer framer;
  const auto a = bytes_of("first-ssh-record");
  const auto b = bytes_of("second-one-here");
  std::vector<std::byte> wire(256);
  const auto w1 = framer.wrap(a, wire);
  NORR_CHECK(w1.has_value());
  const auto w2 = framer.wrap(b, std::span{wire}.subspan(*w1));
  NORR_CHECK(w2.has_value());

  std::vector<std::byte> back(256);
  std::size_t consumed = 0;
  const auto u1 = framer.unwrap(std::span{wire}.first(*w1 + *w2), back, consumed);
  NORR_CHECK(u1.has_value() && *u1 == a.size() && consumed == *w1);
  const auto u2 =
      framer.unwrap(std::span{wire}.subspan(consumed, *w2), back, consumed);
  NORR_CHECK(u2.has_value() && *u2 == b.size() && consumed == *w2);
}

void incomplete_wire_signals_incomplete() {
  norr::SshFramer framer;
  const auto payload = bytes_of("needs-more-bytes");
  std::vector<std::byte> wire(256);
  const auto wrapped = framer.wrap(payload, wire);
  NORR_CHECK(wrapped.has_value());
  std::vector<std::byte> back(256);
  std::size_t consumed = 0;
  const auto partial = framer.unwrap(std::span{wire}.first(*wrapped - 3), back, consumed);
  NORR_CHECK(!partial.has_value());
  NORR_CHECK(partial.error() == norr::SshFramerError::incomplete);
}

void bad_padding_rejected() {
  norr::SshFramer framer;
  std::vector<std::byte> wire(32, std::byte{0});
  wire[3] = std::byte{0x0A};
  wire[4] = std::byte{0x01};
  std::vector<std::byte> back(64);
  std::size_t consumed = 0;
  const auto result = framer.unwrap(wire, back, consumed);
  NORR_CHECK(!result.has_value());
  NORR_CHECK(result.error() == norr::SshFramerError::malformed);
}
}

int main() {
  round_trip_and_alignment();
  two_records_back_to_back();
  incomplete_wire_signals_incomplete();
  bad_padding_rejected();
  std::printf("ssh_framer tests passed\n");
  return 0;
}
