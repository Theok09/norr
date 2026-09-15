// The TCP reassembler against arbitrary byte streams.
//
// This parser reads a length prefix from the network and must never allocate
// on it, so it is the one most worth fuzzing on the fallback path.
#include <cstddef>
#include <cstdint>
#include <span>

#include "norr/tcp_transport.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  norr::FrameReassembler reassembler;
  const auto bytes = std::span{reinterpret_cast<const std::byte*>(data), size};

  // Feed in varying chunk sizes, because a stream parser's bugs live at the
  // boundaries between reads rather than inside one.
  std::size_t offset = 0;
  std::size_t chunk = 1;
  while (offset < bytes.size()) {
    const auto take = std::min(chunk, bytes.size() - offset);
    if (!reassembler.push(bytes.subspan(offset, take))) break;
    offset += take;
    chunk = chunk * 2 + 1;

    while (!reassembler.next().empty()) {
    }
    if (reassembler.violated()) break;
  }
  return 0;
}
