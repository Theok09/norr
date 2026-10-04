#include "check.hpp"
#include <cstdio>
#include <set>
#include <vector>

#include "norr/spoof_envelope.hpp"

namespace {
std::uint32_t ip(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) {
  return (static_cast<std::uint32_t>(a) << 24U) | (static_cast<std::uint32_t>(b) << 16U) |
         (static_cast<std::uint32_t>(c) << 8U) | static_cast<std::uint32_t>(d);
}

std::uint32_t count_class(const std::vector<norr::SpoofCandidate>& v, norr::SpoofClass cls) {
  std::uint32_t n = 0;
  for (const auto& c : v) {
    if (c.cls == cls) ++n;
  }
  return n;
}

void test_classes_generated() {
  const auto real = ip(94, 183, 218, 24);
  const auto cands = norr::build_spoof_candidates(real, {.per_class = 8});
  NORR_CHECK(count_class(cands, norr::SpoofClass::same_host_24) == 8);
  NORR_CHECK(count_class(cands, norr::SpoofClass::same_host_16) == 8);
  NORR_CHECK(count_class(cands, norr::SpoofClass::neighbor_random) == 8);
  NORR_CHECK(count_class(cands, norr::SpoofClass::foreign_random) == 8);
  std::puts("spoof_envelope: each class generates the requested count OK");
}

void test_prefixes() {
  const auto real = ip(94, 183, 218, 24);
  const auto cands = norr::build_spoof_candidates(real, {.per_class = 16});
  for (const auto& c : cands) {
    if (c.cls == norr::SpoofClass::same_host_24) {
      NORR_CHECK((c.ip_be & 0xFFFFFF00U) == (real & 0xFFFFFF00U));
      NORR_CHECK((c.ip_be & 0xFFU) != 0 && (c.ip_be & 0xFFU) != 0xFFU);
    }
    if (c.cls == norr::SpoofClass::same_host_16) {
      NORR_CHECK((c.ip_be & 0xFFFF0000U) == (real & 0xFFFF0000U));
    }
  }
  std::puts("spoof_envelope: same-/24 and same-/16 keep the real prefix OK");
}

void test_isp_blocks() {
  const auto real = ip(94, 183, 218, 24);
  const std::vector<std::uint32_t> blocks{ip(2, 177, 0, 0), ip(5, 160, 0, 0)};
  const auto cands = norr::build_spoof_candidates(real, blocks, {.per_class = 4});
  NORR_CHECK(count_class(cands, norr::SpoofClass::same_isp_block) == 8);
  for (const auto& c : cands) {
    if (c.cls != norr::SpoofClass::same_isp_block) continue;
    const auto prefix = c.ip_be & 0xFFFFFF00U;
    NORR_CHECK(prefix == (blocks[0] & 0xFFFFFF00U) || prefix == (blocks[1] & 0xFFFFFF00U));
  }
  std::puts("spoof_envelope: isp-block candidates land in provided blocks OK");
}

void test_foreign_excludes_bogons() {
  const auto real = ip(94, 183, 218, 24);
  const auto cands = norr::build_spoof_candidates(real, {.per_class = 64});
  for (const auto& c : cands) {
    if (c.cls != norr::SpoofClass::foreign_random) continue;
    const auto octet = (c.ip_be >> 24U) & 0xFFU;
    NORR_CHECK(octet != 0 && octet != 10 && octet != 127 && octet < 224);
    NORR_CHECK((c.ip_be & 0xFFFFFF00U) != (real & 0xFFFFFF00U));
  }
  std::puts("spoof_envelope: foreign candidates exclude bogons and the real /24 OK");
}

void test_no_duplicates_and_determinism() {
  const auto real = ip(10, 20, 30, 40);
  const auto a = norr::build_spoof_candidates(real, {.per_class = 32, .seed = 42});
  const auto b = norr::build_spoof_candidates(real, {.per_class = 32, .seed = 42});
  NORR_CHECK(a.size() == b.size());
  std::set<std::uint32_t> uniq;
  for (std::size_t i = 0; i < a.size(); ++i) {
    NORR_CHECK(a[i].ip_be == b[i].ip_be);
    uniq.insert(a[i].ip_be);
  }
  NORR_CHECK(uniq.size() == a.size());
  std::puts("spoof_envelope: deterministic seed, no duplicate candidates OK");
}

void test_tally() {
  norr::SpoofClassTally tally;
  tally.record_survivor(norr::SpoofClass::same_host_24);
  NORR_CHECK(!tally.class_usable(norr::SpoofClass::same_host_24));
  tally.record_survivor(norr::SpoofClass::same_host_24);
  NORR_CHECK(tally.class_usable(norr::SpoofClass::same_host_24));
  tally.record_survivor(norr::SpoofClass::same_isp_block);
  tally.record_survivor(norr::SpoofClass::same_isp_block);
  NORR_CHECK(tally.usable_classes().size() == 2);
  std::puts("spoof_envelope: tally marks classes usable past the threshold OK");
}
}

int main() {
  test_classes_generated();
  test_prefixes();
  test_isp_blocks();
  test_foreign_excludes_bogons();
  test_no_duplicates_and_determinism();
  test_tally();
  std::puts("spoof_envelope: all tests passed");
  return 0;
}
