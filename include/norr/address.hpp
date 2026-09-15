#pragma once

#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>

#include "norr/error.hpp"

namespace norr {
enum class AddressFamily : std::uint8_t { ipv4 = 4, ipv6 = 6 };

[[nodiscard]] constexpr std::size_t address_length(AddressFamily family) noexcept {
  return family == AddressFamily::ipv4 ? 4U : 16U;
}

[[nodiscard]] constexpr std::uint8_t maximum_prefix_length(AddressFamily family) noexcept {
  return family == AddressFamily::ipv4 ? 32U : 128U;
}

class Address {
 public:
  Address() = default;

  [[nodiscard]] static Address from_bytes(AddressFamily family,
                                          std::span<const std::byte> bytes) noexcept;

  [[nodiscard]] AddressFamily family() const noexcept { return family_; }
  [[nodiscard]] std::span<const std::byte> bytes() const noexcept {
    return std::span<const std::byte>{octets_.data(), address_length(family_)};
  }

  [[nodiscard]] bool bit(std::uint8_t index) const noexcept;

  [[nodiscard]] std::string to_string() const;

  friend bool operator==(const Address&, const Address&) noexcept = default;

 private:
  AddressFamily family_{AddressFamily::ipv4};
  std::array<std::byte, 16> octets_{};
};

[[nodiscard]] std::expected<Address, Error> parse_address(std::string_view text) noexcept;

class Prefix {
 public:
  Prefix() = default;

  [[nodiscard]] static std::expected<Prefix, Error> create(Address address,
                                                           std::uint8_t length) noexcept;

  [[nodiscard]] const Address& address() const noexcept { return address_; }
  [[nodiscard]] std::uint8_t length() const noexcept { return length_; }
  [[nodiscard]] AddressFamily family() const noexcept { return address_.family(); }

  [[nodiscard]] bool contains(const Address& address) const noexcept;

  [[nodiscard]] std::string to_string() const;

  friend bool operator==(const Prefix&, const Prefix&) noexcept = default;

 private:
  Address address_{};
  std::uint8_t length_{};
};

[[nodiscard]] std::expected<Prefix, Error> parse_prefix(std::string_view text) noexcept;

}
