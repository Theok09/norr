#include <array>
#include <algorithm>
#include "check.hpp"
#include <cstddef>
#include <vector>

#include "norr/nonce.hpp"
#include "norr/packet.hpp"
#include "norr/replay_window.hpp"

// Padding to a 16-byte boundary, as WireGuard does.
//
// Without it the ciphertext length equals the inner packet length exactly, so
// an observer reads the size of every packet the tunnel carries. Padding costs
// at most 15 bytes and removes that signal.
void test_padding_alignment() {
  NORR_CHECK(norr::kPaddingAlignment == 16);

  // A length already on the boundary is unchanged: padding must not add a
  // whole block for nothing.
  NORR_CHECK(norr::padded_length(0) == 0);
  NORR_CHECK(norr::padded_length(16) == 16);
  NORR_CHECK(norr::padded_length(1600) == 1600);

  // Anything else rounds up to the next boundary.
  NORR_CHECK(norr::padded_length(1) == 16);
  NORR_CHECK(norr::padded_length(15) == 16);
  NORR_CHECK(norr::padded_length(17) == 32);
  NORR_CHECK(norr::padded_length(31) == 32);

  // The expansion is bounded: at most 15 bytes, never more.
  for (std::size_t length = 0; length < 200; ++length) {
    const auto padded = norr::padded_length(length);
    NORR_CHECK(padded >= length);
    NORR_CHECK(padded - length < norr::kPaddingAlignment);
    NORR_CHECK(padded % norr::kPaddingAlignment == 0);
  }

  // Every length in a block maps to the same padded size, which is the point:
  // the observable size no longer distinguishes them.
  for (std::size_t length = 81; length <= 96; ++length) {
    NORR_CHECK(norr::padded_length(length) == 96);
  }

  std::puts("packet: padding rounds to 16 and bounds expansion OK");
}

int main() {
  test_padding_alignment();
  constexpr std::array payload{std::byte{0x10}, std::byte{0x20}, std::byte{0x30}};
  const norr::PacketHeader header{.version = norr::kProtocolVersion, .type = norr::FrameType::data, .flags = 0, .key_id = 0xBEEF, .counter = 0x0102030405060708};
  const auto encoded = norr::serialize_packet(header, payload); NORR_CHECK(encoded.has_value());
  constexpr std::array expected_wire{std::byte{0x11}, std::byte{0x00}, std::byte{0xBE}, std::byte{0xEF}, std::byte{0x00}, std::byte{0x10}, std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}, std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08}, std::byte{0x00}, std::byte{0x03}, std::byte{0x10}, std::byte{0x20}, std::byte{0x30}};
  NORR_CHECK(encoded->size() == expected_wire.size());
  NORR_CHECK(std::ranges::equal(*encoded, expected_wire));
  const auto decoded = norr::parse_packet(*encoded); NORR_CHECK(decoded.has_value());
  NORR_CHECK(decoded->header.version == header.version); NORR_CHECK(decoded->header.type == header.type); NORR_CHECK(decoded->header.key_id == header.key_id); NORR_CHECK(decoded->header.counter == header.counter); NORR_CHECK(decoded->header.payload_length == payload.size());
  constexpr std::array<std::byte, 3> short_packet{};
  const auto malformed = norr::parse_packet(short_packet); NORR_CHECK(!malformed.has_value() && malformed.error() == norr::Error::malformed_packet);
  auto unknown_version = *encoded; unknown_version[0] = std::byte{0x21};
  const auto version_error = norr::parse_packet(unknown_version); NORR_CHECK(!version_error.has_value() && version_error.error() == norr::Error::unsupported_version);
  auto bad_length = *encoded; bad_length[15] = std::byte{4};
  const auto length_error = norr::parse_packet(bad_length); NORR_CHECK(!length_error.has_value() && length_error.error() == norr::Error::payload_length_mismatch);
  auto flags = *encoded; flags[1] = std::byte{1};
  const auto flags_error = norr::parse_packet(flags); NORR_CHECK(!flags_error.has_value() && flags_error.error() == norr::Error::unsupported_flags);
  const auto nonce = norr::make_nonce(0x0102030405060708); NORR_CHECK(nonce[4] == std::byte{0x08} && nonce[11] == std::byte{0x01});
  norr::PacketCounter final_counter{UINT64_MAX};
  NORR_CHECK(*final_counter.next() == UINT64_MAX); NORR_CHECK(final_counter.exhausted());
  const auto exhausted = final_counter.next(); NORR_CHECK(!exhausted.has_value() && exhausted.error() == norr::Error::counter_exhausted);
  // Basic accept/replay behaviour. The "too old" case is expressed relative to
  // the window size rather than a hard-coded counter, so resizing the window
  // cannot silently invalidate the assertion.
  norr::ReplayWindow replay;
  NORR_CHECK(replay.accept(10) == norr::ReplayResult::accepted);
  NORR_CHECK(replay.accept(10) == norr::ReplayResult::replayed);
  NORR_CHECK(replay.accept(12) == norr::ReplayResult::accepted);
  NORR_CHECK(replay.accept(11) == norr::ReplayResult::accepted);
  NORR_CHECK(replay.accept(11) == norr::ReplayResult::replayed);
  NORR_CHECK(replay.accept(100) == norr::ReplayResult::accepted);
  NORR_CHECK(replay.accept(0) == norr::ReplayResult::accepted);
  NORR_CHECK(replay.accept(norr::ReplayWindow::kWindowSize + 100) == norr::ReplayResult::accepted);
  NORR_CHECK(replay.accept(0) == norr::ReplayResult::too_old);

  // Counter zero is a real counter, not an "uninitialized" sentinel.
  {
    norr::ReplayWindow window;
    NORR_CHECK(window.accept(0) == norr::ReplayResult::accepted);
    NORR_CHECK(window.accept(0) == norr::ReplayResult::replayed);
  }
  // Window edges: the last counter inside the window is accepted, one beyond is
  // refused as too old.
  {
    constexpr auto edge = norr::ReplayWindow::kWindowSize - 1;
    norr::ReplayWindow window;
    NORR_CHECK(window.accept(edge) == norr::ReplayResult::accepted);
    NORR_CHECK(window.accept(0) == norr::ReplayResult::accepted);
  }
  {
    norr::ReplayWindow window;
    NORR_CHECK(window.accept(norr::ReplayWindow::kWindowSize) == norr::ReplayResult::accepted);
    NORR_CHECK(window.accept(0) == norr::ReplayResult::too_old);
    NORR_CHECK(window.accept(1) == norr::ReplayResult::accepted);
  }
  // A jump of a whole window clears history rather than leaving stale bits that
  // would make a fresh counter look like a replay.
  {
    norr::ReplayWindow window;
    NORR_CHECK(window.accept(0) == norr::ReplayResult::accepted);
    NORR_CHECK(window.accept(norr::ReplayWindow::kWindowSize) == norr::ReplayResult::accepted);
    NORR_CHECK(window.accept(norr::ReplayWindow::kWindowSize) == norr::ReplayResult::replayed);
    NORR_CHECK(window.accept(0) == norr::ReplayResult::too_old);
  }
  // Reordering deeper than 64 packets must still be accepted: this is why the
  // window is 8192 rather than the RFC 4303 default of 64.
  {
    norr::ReplayWindow window;
    NORR_CHECK(window.accept(5000) == norr::ReplayResult::accepted);
    NORR_CHECK(window.accept(4000) == norr::ReplayResult::accepted);
    NORR_CHECK(window.accept(100) == norr::ReplayResult::accepted);
    NORR_CHECK(window.accept(4000) == norr::ReplayResult::replayed);
    NORR_CHECK(window.accept(100) == norr::ReplayResult::replayed);
  }
  // Every counter across a full window stays independently tracked.
  {
    norr::ReplayWindow window;
    NORR_CHECK(window.accept(norr::ReplayWindow::kWindowSize) == norr::ReplayResult::accepted);
    for (std::uint64_t counter = 1; counter < norr::ReplayWindow::kWindowSize; ++counter) {
      NORR_CHECK(window.accept(counter) == norr::ReplayResult::accepted);
    }
    for (std::uint64_t counter = 1; counter < norr::ReplayWindow::kWindowSize; ++counter) {
      NORR_CHECK(window.accept(counter) == norr::ReplayResult::replayed);
    }
  }
  // A stale bit one window back must not survive a forward jump.
  {
    norr::ReplayWindow window;
    NORR_CHECK(window.accept(10) == norr::ReplayResult::accepted);
    NORR_CHECK(window.accept(10 + norr::ReplayWindow::kWindowSize) == norr::ReplayResult::accepted);
    NORR_CHECK(window.accept(10 + 1) == norr::ReplayResult::accepted);
  }
  // A jump to the maximum counter must not overflow the distance computation.
  {
    norr::ReplayWindow window;
    NORR_CHECK(window.accept(5) == norr::ReplayResult::accepted);
    NORR_CHECK(window.accept(UINT64_MAX) == norr::ReplayResult::accepted);
    NORR_CHECK(window.accept(5) == norr::ReplayResult::too_old);
    NORR_CHECK(window.accept(UINT64_MAX) == norr::ReplayResult::replayed);
  }

  // Largest representable packet round-trips; one byte more is refused.
  {
    const std::vector<std::byte> maximum_payload(norr::kMaximumPacketSize - norr::kPacketHeaderSize);
    // A DATA frame needs a real key id: zero is reserved for pre-session state.
    const norr::PacketHeader maximum_header{.version = norr::kProtocolVersion, .type = norr::FrameType::data, .key_id = 1};
    const auto encoded_maximum = norr::serialize_packet(maximum_header, maximum_payload);
    NORR_CHECK(encoded_maximum.has_value() && encoded_maximum->size() == norr::kMaximumPacketSize);
    NORR_CHECK(norr::parse_packet(*encoded_maximum).has_value());

    const std::vector<std::byte> oversized(norr::kMaximumPacketSize - norr::kPacketHeaderSize + 1);
    const auto refused = norr::serialize_packet(maximum_header, oversized);
    NORR_CHECK(!refused.has_value() && refused.error() == norr::Error::packet_too_large);
  }

  // Frame type must be inside the defined range; 0 and 7 are not.
  {
    auto header_with_type = [](std::uint8_t first_byte) {
      std::vector<std::byte> bytes(norr::kPacketHeaderSize);
      bytes[0] = static_cast<std::byte>(first_byte);
      bytes[5] = static_cast<std::byte>(norr::kPacketHeaderSize);
      return norr::parse_packet(bytes);
    };
    NORR_CHECK(!header_with_type(0x10).has_value());
    NORR_CHECK(!header_with_type(0x17).has_value());
    // Type 1 with key id zero is now refused, so a CONTROL frame is used here.
    NORR_CHECK(header_with_type(0x12).has_value());
  }

  // Key ID zero is reserved for pre-session state: a DATA frame may not use it,
  // while a CONTROL frame may.
  {
    const norr::PacketHeader reserved{.version = norr::kProtocolVersion, .type = norr::FrameType::data, .key_id = norr::kPreSessionKeyId};
    const auto refused = norr::serialize_packet(reserved, payload);
    NORR_CHECK(!refused.has_value() && refused.error() == norr::Error::reserved_key_id);

    const norr::PacketHeader control{.version = norr::kProtocolVersion, .type = norr::FrameType::control, .key_id = norr::kPreSessionKeyId};
    const auto allowed = norr::serialize_packet(control, payload);
    NORR_CHECK(allowed.has_value() && norr::parse_packet(*allowed).has_value());

    auto forged = *encoded;
    forged[2] = std::byte{0};
    forged[3] = std::byte{0};
    const auto rejected = norr::parse_packet(forged);
    NORR_CHECK(!rejected.has_value() && rejected.error() == norr::Error::reserved_key_id);
  }
}
