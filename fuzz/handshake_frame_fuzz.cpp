#include <cstddef>
#include <cstdint>
#include <span>

#include "norr/handshake_frame.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const auto bytes = std::span{reinterpret_cast<const std::byte*>(data), size};
  static_cast<void>(norr::parse_handshake_frame(bytes));
  return 0;
}
