#include <cstddef>
#include <cstdint>
#include <span>

#include "norr/ip_packet.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const auto bytes = std::span{reinterpret_cast<const std::byte*>(data), size};
  static_cast<void>(norr::parse_ip_packet(bytes));
  return 0;
}
