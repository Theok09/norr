#include <cstddef>
#include <cstdint>
#include <string_view>

#include "norr/config.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const std::string_view text{reinterpret_cast<const char*>(data), size};
  static_cast<void>(norr::parse_config(text));
  return 0;
}
