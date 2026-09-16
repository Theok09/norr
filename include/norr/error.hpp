// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#pragma once

#include <string_view>

namespace norr {
enum class Error {
  malformed_packet,
  packet_too_large,
  unsupported_version,
  unsupported_flags,
  payload_length_mismatch,
  counter_exhausted,
  reserved_key_id,
};

[[nodiscard]] constexpr std::string_view error_message(Error error) noexcept {
  switch (error) {
    case Error::malformed_packet: return "malformed packet";
    case Error::packet_too_large: return "packet too large";
    case Error::unsupported_version: return "unsupported version";
    case Error::unsupported_flags: return "unsupported flags";
    case Error::payload_length_mismatch: return "payload length mismatch";
    case Error::counter_exhausted: return "packet counter exhausted";
    case Error::reserved_key_id: return "reserved key id used by a session frame";
  }
  return "unknown error";
}

}
