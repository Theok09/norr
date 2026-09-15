#include "check.hpp"
#include <string_view>

#include "norr/endpoint.hpp"

namespace {

norr::Endpoint endpoint_of(std::string_view text) {
  const auto parsed = norr::parse_endpoint(text);
  NORR_CHECK(parsed.has_value());
  return *parsed;
}

bool rejected(std::string_view text) { return !norr::parse_endpoint(text).has_value(); }

}  // namespace

int main() {
  // IPv4.
  {
    const auto endpoint = endpoint_of("10.0.0.1:51880");
    NORR_CHECK(endpoint.family() == norr::AddressFamily::ipv4);
    NORR_CHECK(endpoint.port() == 51880);
    NORR_CHECK(endpoint.to_string() == "10.0.0.1:51880");
  }

  // IPv6 requires brackets so the port separator is unambiguous.
  {
    const auto endpoint = endpoint_of("[2001:db8::1]:51880");
    NORR_CHECK(endpoint.family() == norr::AddressFamily::ipv6);
    NORR_CHECK(endpoint.port() == 51880);
    NORR_CHECK(endpoint.to_string() == "[2001:0db8:0000:0000:0000:0000:0000:0001]:51880");
  }

  NORR_CHECK(endpoint_of("[::1]:1").port() == 1);
  NORR_CHECK(endpoint_of("10.0.0.1:65535").port() == 65535);

  // A bare IPv6 literal is ambiguous and must be refused.
  NORR_CHECK(rejected("2001:db8::1:51880"));
  NORR_CHECK(rejected("::1:80"));

  // Malformed forms.
  NORR_CHECK(rejected(""));
  NORR_CHECK(rejected("10.0.0.1"));
  NORR_CHECK(rejected("10.0.0.1:"));
  NORR_CHECK(rejected(":51880"));
  NORR_CHECK(rejected("[2001:db8::1]51880"));
  NORR_CHECK(rejected("[2001:db8::1]:"));
  NORR_CHECK(rejected("[10.0.0.1]:80"));
  NORR_CHECK(rejected("10.0.0.1:0"));
  NORR_CHECK(rejected("10.0.0.1:65536"));
  NORR_CHECK(rejected("10.0.0.1:080"));
  NORR_CHECK(rejected("10.0.0.1:http"));
  NORR_CHECK(rejected("999.0.0.1:80"));

  // Equality compares both halves.
  NORR_CHECK(endpoint_of("10.0.0.1:80") == endpoint_of("10.0.0.1:80"));
  NORR_CHECK(!(endpoint_of("10.0.0.1:80") == endpoint_of("10.0.0.1:81")));
  NORR_CHECK(!(endpoint_of("10.0.0.1:80") == endpoint_of("10.0.0.2:80")));
}
