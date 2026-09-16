// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#include "norr/key_schedule.hpp"

#include <algorithm>

namespace norr {
namespace {
constexpr void append_u32(std::array<std::byte, 64>& bytes, std::size_t& size,
                          std::uint32_t value) noexcept {
  for (std::size_t index = 0; index < 4; ++index) {
    bytes[size + index] =
        static_cast<std::byte>(value >> static_cast<unsigned>((3U - index) * 8U));
  }
  size += 4;
}

[[nodiscard]] constexpr bool append_text(std::array<std::byte, 64>& bytes, std::size_t& size,
                                         std::string_view text) noexcept {
  if (size + text.size() > bytes.size()) return false;
  for (const char character : text) {
    bytes[size++] = static_cast<std::byte>(static_cast<unsigned char>(character));
  }
  return true;
}

}

std::expected<KeyLabel, Error> make_key_label(std::string_view domain, KeyDirection direction,
                                              KeyGeneration generation) noexcept {
  if (domain.empty()) return std::unexpected(Error::malformed_packet);

  KeyLabel label{};
  const auto separator = std::string_view{":"};
  if (!append_text(label.bytes, label.size, kProtocolLabel) ||
      !append_text(label.bytes, label.size, separator) ||
      !append_text(label.bytes, label.size, domain) ||
      !append_text(label.bytes, label.size, separator) ||
      !append_text(label.bytes, label.size, direction_label(direction)) ||
      !append_text(label.bytes, label.size, separator)) {
    return std::unexpected(Error::packet_too_large);
  }
  if (label.size + 4 > label.bytes.size()) return std::unexpected(Error::packet_too_large);
  append_u32(label.bytes, label.size, generation);
  return label;
}

}
