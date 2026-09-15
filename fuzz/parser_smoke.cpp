// Deterministic driver for the libFuzzer entry points on platforms without the
// libFuzzer runtime (notably Xcode). Real coverage-guided fuzzing runs in CI on
// Linux; this keeps the entry points compiled and exercised everywhere else.
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string_view>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size);

namespace {

// The two entry points live in separate translation units, so they are reached
// through the single libFuzzer symbol each one defines. Only one may be linked
// per binary; this driver is built once per parser by the build system.
void drive_random() {
  std::uint32_t state = 0x9E37'79B9U;
  std::vector<std::uint8_t> buffer(4096);
  for (int iteration = 0; iteration < 100'000; ++iteration) {
    state ^= state << 13U;
    state ^= state >> 17U;
    state ^= state << 5U;
    const std::size_t length = state % buffer.size();
    for (std::size_t index = 0; index < length; ++index) {
      state ^= state << 13U;
      state ^= state >> 17U;
      state ^= state << 5U;
      buffer[index] = static_cast<std::uint8_t>(state);
    }
    LLVMFuzzerTestOneInput(buffer.data(), length);
  }
}

void drive_seeds() {
  constexpr std::string_view seeds[] = {
      "[node]\nlisten_port = 1\n",
      "[identity]\nkey_file = \"k\"\n",
      "[network]\nmtu = auto\n",
      "[node]\nrole=\"server\"\n=\n[[",
      "\x01\x01\x00\x02\xA1\xB2",
      "\x04\x01\x00\x01\xFF",
      "\x00\x01\x00\x00",
  };
  for (const auto seed : seeds) {
    LLVMFuzzerTestOneInput(reinterpret_cast<const std::uint8_t*>(seed.data()), seed.size());
  }
}

}  // namespace

int main() {
  drive_random();
  drive_seeds();
  std::puts("parser smoke completed without crash");
}
