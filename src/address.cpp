#include "norr/address.hpp"

#include <algorithm>
#include <charconv>

namespace norr {
namespace {
[[nodiscard]] std::expected<std::uint16_t, Error> parse_decimal(std::string_view text,
                                                                std::uint16_t maximum) noexcept {
  if (text.empty() || text.size() > 3) return std::unexpected(Error::malformed_packet);

  if (text.size() > 1 && text.front() == '0') return std::unexpected(Error::malformed_packet);
  std::uint16_t value{};
  const auto* const end = text.data() + text.size();
  const auto result = std::from_chars(text.data(), end, value);
  if (result.ec != std::errc{} || result.ptr != end || value > maximum) {
    return std::unexpected(Error::malformed_packet);
  }
  return value;
}

[[nodiscard]] std::expected<Address, Error> parse_ipv4(std::string_view text) noexcept {
  std::array<std::byte, 16> octets{};
  std::size_t index = 0;
  std::size_t offset = 0;
  bool consumed_all = false;

  while (index < 4) {
    const auto dot = text.find('.', offset);
    const auto field = text.substr(offset, dot == std::string_view::npos ? std::string_view::npos
                                                                        : dot - offset);
    const auto value = parse_decimal(field, 255);
    if (!value) return std::unexpected(value.error());
    octets[index] = static_cast<std::byte>(*value);
    ++index;
    if (dot == std::string_view::npos) {
      consumed_all = true;
      break;
    }
    offset = dot + 1;
  }

  if (index != 4 || !consumed_all) return std::unexpected(Error::malformed_packet);
  return Address::from_bytes(AddressFamily::ipv4, octets);
}

[[nodiscard]] std::expected<std::uint16_t, Error> parse_hextet(std::string_view text) noexcept {
  if (text.empty() || text.size() > 4) return std::unexpected(Error::malformed_packet);
  std::uint16_t value{};
  const auto* const end = text.data() + text.size();
  const auto result = std::from_chars(text.data(), end, value, 16);
  if (result.ec != std::errc{} || result.ptr != end) return std::unexpected(Error::malformed_packet);
  return value;
}

[[nodiscard]] std::expected<Address, Error> parse_ipv6(std::string_view text) noexcept {
  std::array<std::uint16_t, 8> hextets{};
  std::size_t head = 0;
  std::array<std::uint16_t, 8> tail_storage{};
  std::size_t tail = 0;

  const auto compression = text.find("::");
  if (compression != std::string_view::npos &&
      text.find("::", compression + 1) != std::string_view::npos) {
    return std::unexpected(Error::malformed_packet);
  }

  const auto head_text = compression == std::string_view::npos ? text : text.substr(0, compression);
  const auto tail_text =
      compression == std::string_view::npos ? std::string_view{} : text.substr(compression + 2);

  const auto split = [](std::string_view input, std::array<std::uint16_t, 8>& out,
                        std::size_t& count) -> std::expected<void, Error> {
    if (input.empty()) return {};
    std::size_t offset = 0;
    while (true) {
      const auto colon = input.find(':', offset);
      const auto field =
          input.substr(offset, colon == std::string_view::npos ? std::string_view::npos : colon - offset);
      if (count == out.size()) return std::unexpected(Error::malformed_packet);
      const auto value = parse_hextet(field);
      if (!value) return std::unexpected(value.error());
      out[count++] = *value;
      if (colon == std::string_view::npos) break;
      offset = colon + 1;
    }
    return {};
  };

  if (const auto parsed = split(head_text, hextets, head); !parsed) {
    return std::unexpected(parsed.error());
  }
  if (const auto parsed = split(tail_text, tail_storage, tail); !parsed) {
    return std::unexpected(parsed.error());
  }

  if (compression == std::string_view::npos) {
    if (head != 8) return std::unexpected(Error::malformed_packet);
  } else {
    if (head + tail >= 8) return std::unexpected(Error::malformed_packet);
    for (std::size_t index = 0; index < tail; ++index) {
      hextets[8 - tail + index] = tail_storage[index];
    }
  }

  std::array<std::byte, 16> octets{};
  for (std::size_t index = 0; index < 8; ++index) {
    octets[index * 2] = static_cast<std::byte>(hextets[index] >> 8U);
    octets[index * 2 + 1] = static_cast<std::byte>(hextets[index] & 0xFFU);
  }
  return Address::from_bytes(AddressFamily::ipv6, octets);
}

void append_decimal(std::string& out, std::uint16_t value) {
  char buffer[4]{};
  const auto result = std::to_chars(buffer, buffer + sizeof(buffer), value);
  out.append(buffer, static_cast<std::size_t>(result.ptr - buffer));
}

}

Address Address::from_bytes(AddressFamily family, std::span<const std::byte> bytes) noexcept {
  Address address;
  address.family_ = family;
  const auto length = std::min(bytes.size(), address.octets_.size());
  std::copy_n(bytes.begin(), length, address.octets_.begin());
  return address;
}

bool Address::bit(std::uint8_t index) const noexcept {
  if (index >= maximum_prefix_length(family_)) return false;
  const auto octet = static_cast<std::uint8_t>(octets_[index / 8U]);
  return ((octet >> (7U - (index % 8U))) & 1U) != 0U;
}

std::string Address::to_string() const {
  std::string out;
  if (family_ == AddressFamily::ipv4) {
    for (std::size_t index = 0; index < 4; ++index) {
      if (index != 0) out.push_back('.');
      append_decimal(out, static_cast<std::uint8_t>(octets_[index]));
    }
    return out;
  }

  constexpr char kDigits[] = "0123456789abcdef";
  for (std::size_t index = 0; index < 8; ++index) {
    if (index != 0) out.push_back(':');
    const auto high = static_cast<std::uint8_t>(octets_[index * 2]);
    const auto low = static_cast<std::uint8_t>(octets_[index * 2 + 1]);
    out.push_back(kDigits[high >> 4U]);
    out.push_back(kDigits[high & 0x0FU]);
    out.push_back(kDigits[low >> 4U]);
    out.push_back(kDigits[low & 0x0FU]);
  }
  return out;
}

std::expected<Address, Error> parse_address(std::string_view text) noexcept {
  if (text.empty()) return std::unexpected(Error::malformed_packet);
  if (text.find(':') != std::string_view::npos) return parse_ipv6(text);
  return parse_ipv4(text);
}

std::expected<Prefix, Error> Prefix::create(Address address, std::uint8_t length) noexcept {
  if (length > maximum_prefix_length(address.family())) {
    return std::unexpected(Error::malformed_packet);
  }

  std::array<std::byte, 16> octets{};
  const auto source = address.bytes();
  std::copy(source.begin(), source.end(), octets.begin());
  for (std::size_t index = length; index < address_length(address.family()) * 8U; ++index) {
    const auto mask = static_cast<std::uint8_t>(~(1U << (7U - (index % 8U))));
    octets[index / 8U] &= static_cast<std::byte>(mask);
  }

  Prefix prefix;
  prefix.address_ = Address::from_bytes(address.family(), octets);
  prefix.length_ = length;
  return prefix;
}

bool Prefix::contains(const Address& address) const noexcept {
  if (address.family() != address_.family()) return false;

  const auto whole_octets = static_cast<std::size_t>(length_) / 8U;
  const auto remaining_bits = static_cast<std::size_t>(length_) % 8U;
  const auto candidate = address.bytes();
  const auto network = address_.bytes();

  for (std::size_t index = 0; index < whole_octets; ++index) {
    if (candidate[index] != network[index]) return false;
  }
  if (remaining_bits == 0) return true;

  const auto mask = static_cast<std::uint8_t>(0xFFU << (8U - remaining_bits));
  const auto candidate_octet = static_cast<std::uint8_t>(candidate[whole_octets]);
  const auto network_octet = static_cast<std::uint8_t>(network[whole_octets]);
  return (candidate_octet & mask) == (network_octet & mask);
}

std::string Prefix::to_string() const {
  auto out = address_.to_string();
  out.push_back('/');
  append_decimal(out, length_);
  return out;
}

std::expected<Prefix, Error> parse_prefix(std::string_view text) noexcept {
  const auto slash = text.find('/');
  if (slash == std::string_view::npos) return std::unexpected(Error::malformed_packet);

  const auto address = parse_address(text.substr(0, slash));
  if (!address) return std::unexpected(address.error());

  const auto length_text = text.substr(slash + 1);
  if (length_text.empty() || length_text.size() > 3) {
    return std::unexpected(Error::malformed_packet);
  }
  if (length_text.size() > 1 && length_text.front() == '0') {
    return std::unexpected(Error::malformed_packet);
  }
  std::uint16_t length{};
  const auto* const end = length_text.data() + length_text.size();
  const auto result = std::from_chars(length_text.data(), end, length);
  if (result.ec != std::errc{} || result.ptr != end) {
    return std::unexpected(Error::malformed_packet);
  }
  return Prefix::create(*address, static_cast<std::uint8_t>(length));
}

}
