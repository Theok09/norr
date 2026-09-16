// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#pragma once

#include <cstdint>
#include <expected>
#include <string>
#include <string_view>

#include "norr/address.hpp"

namespace norr {
class Endpoint {
 public:
  Endpoint() = default;
  Endpoint(Address address, std::uint16_t port) noexcept
      : address_(address), port_(port) {}

  [[nodiscard]] const Address& address() const noexcept { return address_; }
  [[nodiscard]] std::uint16_t port() const noexcept { return port_; }
  [[nodiscard]] AddressFamily family() const noexcept { return address_.family(); }

  [[nodiscard]] std::string to_string() const;

  friend bool operator==(const Endpoint&, const Endpoint&) noexcept = default;

 private:
  Address address_{};
  std::uint16_t port_{};
};

[[nodiscard]] std::expected<Endpoint, Error> parse_endpoint(std::string_view text) noexcept;

}
