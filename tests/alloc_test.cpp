// The datapath must not allocate per packet.
//
// `limits/resource-model.md` requires steady-state forwarding to run out of
// buffers owned by the worker. An allocation on the hot path is both a
// throughput cost and a failure mode: under memory pressure a packet path that
// allocates can fail where one that does not, cannot.
//
// This counts allocations around a sealed/opened packet rather than trusting
// that no `std::vector` appears in the code, because the ones that matter are
// the ones inside the functions being called.

#include "check.hpp"

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <new>
#include <vector>

#include "norr/crypto.hpp"
#include "norr/session.hpp"

namespace {

std::atomic<std::size_t> g_allocations{0};

}  // namespace

// Counting is global and process-wide, which is why this lives in its own
// binary: another test allocating in the background would make the count
// meaningless.
void* operator new(std::size_t size) {
  g_allocations.fetch_add(1, std::memory_order_relaxed);
  if (void* memory = std::malloc(size == 0 ? 1 : size)) return memory;
  throw std::bad_alloc{};
}

void operator delete(void* memory) noexcept { std::free(memory); }
void operator delete(void* memory, std::size_t) noexcept { std::free(memory); }

namespace {

norr::TrafficKeys make_keys(std::uint8_t fill) {
  norr::TrafficKey key{};
  key.fill(static_cast<std::byte>(fill));
  return norr::TrafficKeys{key, 0};
}

}  // namespace

int main() {
  if (!norr::crypto_available()) {
    std::puts("alloc: crypto backend absent, skipped");
    return 0;
  }
  NORR_CHECK(norr::crypto_init().has_value());

  norr::Session sender{1, 0x0011, 0x0022, make_keys(0xA1), make_keys(0xB2)};
  norr::Session receiver{2, 0x0022, 0x0011, make_keys(0xB2), make_keys(0xA1)};

  const std::vector<std::byte> plaintext(1200, std::byte{0x5A});
  std::vector<std::byte> wire(plaintext.size() + norr::kPacketHeaderSize + norr::kAeadTagSize);
  std::vector<std::byte> recovered(plaintext.size());

  // Warm up outside the measurement: the first call may touch lazily
  // initialised state that a steady-state packet never touches again.
  const auto warm = sender.seal(norr::FrameType::data, plaintext, wire);
  NORR_CHECK(warm.has_value());
  const auto warm_view = norr::parse_packet(std::span{wire}.first(*warm));
  NORR_CHECK(warm_view.has_value());
  NORR_CHECK(receiver.open(*warm_view, std::span{wire}.first(*warm), recovered).has_value());

  constexpr int kPackets = 1000;
  const auto before = g_allocations.load(std::memory_order_relaxed);

  for (int index = 0; index < kPackets; ++index) {
    const auto sealed = sender.seal(norr::FrameType::data, plaintext, wire);
    NORR_CHECK(sealed.has_value());

    const auto view = norr::parse_packet(std::span{wire}.first(*sealed));
    NORR_CHECK(view.has_value());

    const auto opened = receiver.open(*view, std::span{wire}.first(*sealed), recovered);
    NORR_CHECK(opened.has_value());
    NORR_CHECK(*opened == plaintext.size());
  }

  const auto after = g_allocations.load(std::memory_order_relaxed);
  const auto total = after - before;

  std::printf("alloc: %zu allocations for %d sealed and opened packets\n", total, kPackets);

  // Zero, not "few": seal writes its header straight into the caller's buffer
  // and the AEAD seals in place, so there is nothing left to allocate. A
  // regression here means a temporary crept back onto the packet path.
  NORR_CHECK(total == 0);

  std::puts("alloc: datapath is allocation-free per packet OK");
  return 0;
}
