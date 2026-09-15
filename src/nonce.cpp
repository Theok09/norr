#include "norr/nonce.hpp"

namespace norr {
Nonce make_nonce(std::uint64_t counter) noexcept {
  Nonce nonce{};
  for (std::size_t index = 0; index < 8; ++index) {
    nonce[4 + index] = static_cast<std::byte>(counter >> static_cast<unsigned>(index * 8U));
  }
  return nonce;
}

std::expected<std::uint64_t, Error> PacketCounter::next() noexcept {
  if (exhausted_) return std::unexpected(Error::counter_exhausted);
  const auto counter = value_;
  if (value_ == UINT64_MAX) exhausted_ = true;
  else ++value_;
  return counter;
}

}
