#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "norr/packet.hpp"

int main() {
  std::array<std::byte, 256> input{};
  std::uint32_t state = 0x6D2B79F5U;
  for (std::size_t iteration = 0; iteration < 100'000; ++iteration) {
    for (auto& byte : input) {
      state ^= state << 13U;
      state ^= state >> 17U;
      state ^= state << 5U;
      byte = static_cast<std::byte>(state);
    }
    const auto length = static_cast<std::size_t>(state % input.size());
    static_cast<void>(norr::parse_packet(std::span{input}.first(length)));
  }
}
