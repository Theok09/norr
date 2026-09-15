// The FEC header parser and decoder against arbitrary input.
//
// A peer controls the block id, index and block size, so the decoder must not
// let any of them size or index its state.
#include <cstddef>
#include <cstdint>
#include <span>

#include "norr/fec.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (size < norr::kFecHeaderSize) return 0;

  const auto bytes = std::span{reinterpret_cast<const std::byte*>(data), size};
  const auto header = norr::parse_fec_header(bytes);
  if (!header) return 0;

  static norr::FecDecoder decoder;
  static_cast<void>(decoder.receive(*header, bytes.subspan(norr::kFecHeaderSize),
                                    norr::Instant{}));
  static_cast<void>(decoder.expire(norr::Instant{} + std::chrono::seconds{1}));
  return 0;
}
