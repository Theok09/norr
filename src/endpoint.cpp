#include "norr/endpoint.hpp"

#include <charconv>

namespace norr {
namespace {
[[nodiscard]] std::expected<std::uint16_t, Error> parse_port(std::string_view text) noexcept {
  if (text.empty() || text.size() > 5) return std::unexpected(Error::malformed_packet);
  if (text.size() > 1 && text.front() == '0') return std::unexpected(Error::malformed_packet);
  std::uint32_t value{};
  const auto* const end = text.data() + text.size();
  const auto result = std::from_chars(text.data(), end, value);
  if (result.ec != std::errc{} || result.ptr != end) {
    return std::unexpected(Error::malformed_packet);
  }

  if (value == 0 || value > 65'535) return std::unexpected(Error::malformed_packet);
  return static_cast<std::uint16_t>(value);
}

}

std::string Endpoint::to_string() const {
  std::string out;
  const auto is_ipv6 = address_.family() == AddressFamily::ipv6;
  if (is_ipv6) out.push_back('[');
  out += address_.to_string();
  if (is_ipv6) out.push_back(']');
  out.push_back(':');

  char buffer[6]{};
  const auto result = std::to_chars(buffer, buffer + sizeof(buffer), port_);
  out.append(buffer, static_cast<std::size_t>(result.ptr - buffer));
  return out;
}

std::expected<Endpoint, Error> parse_endpoint(std::string_view text) noexcept {
  if (text.empty()) return std::unexpected(Error::malformed_packet);

  if (text.front() == '[') {
    const auto close = text.find(']');
    if (close == std::string_view::npos) return std::unexpected(Error::malformed_packet);
    if (close + 1 >= text.size() || text[close + 1] != ':') {
      return std::unexpected(Error::malformed_packet);
    }
    const auto address = parse_address(text.substr(1, close - 1));
    if (!address) return std::unexpected(address.error());
    if (address->family() != AddressFamily::ipv6) return std::unexpected(Error::malformed_packet);
    const auto port = parse_port(text.substr(close + 2));
    if (!port) return std::unexpected(port.error());
    return Endpoint{*address, *port};
  }

  const auto colon = text.rfind(':');
  if (colon == std::string_view::npos) return std::unexpected(Error::malformed_packet);
  if (text.find(':') != colon) return std::unexpected(Error::malformed_packet);

  const auto address = parse_address(text.substr(0, colon));
  if (!address) return std::unexpected(address.error());
  if (address->family() != AddressFamily::ipv4) return std::unexpected(Error::malformed_packet);
  const auto port = parse_port(text.substr(colon + 1));
  if (!port) return std::unexpected(port.error());
  return Endpoint{*address, *port};
}

}
