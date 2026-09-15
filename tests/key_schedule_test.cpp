#include <algorithm>
#include <array>
#include "check.hpp"
#include <string_view>

#include "norr/key_schedule.hpp"

namespace {

[[nodiscard]] bool equals_text(std::span<const std::byte> bytes, std::string_view text) {
  if (bytes.size() != text.size()) return false;
  for (std::size_t index = 0; index < text.size(); ++index) {
    if (bytes[index] != static_cast<std::byte>(static_cast<unsigned char>(text[index]))) {
      return false;
    }
  }
  return true;
}

}  // namespace

int main() {
  const auto data_label = norr::make_key_label(norr::kDataLabel,
                                               norr::KeyDirection::initiator_to_responder, 0);
  NORR_CHECK(data_label.has_value());

  // "norr v1:data:i2r:" followed by the big-endian generation.
  constexpr std::string_view kPrefix = "norr v1:data:i2r:";
  const auto view = data_label->view();
  NORR_CHECK(view.size() == kPrefix.size() + 4);
  NORR_CHECK(equals_text(view.subspan(0, kPrefix.size()), kPrefix));
  NORR_CHECK(view[kPrefix.size() + 0] == std::byte{0});
  NORR_CHECK(view[kPrefix.size() + 3] == std::byte{0});

  const auto generation_one =
      norr::make_key_label(norr::kDataLabel, norr::KeyDirection::initiator_to_responder, 1);
  NORR_CHECK(generation_one.has_value());
  NORR_CHECK(generation_one->view()[kPrefix.size() + 3] == std::byte{1});

  // Every axis of the label must change the bytes: domain, direction, generation.
  const auto control_label =
      norr::make_key_label(norr::kControlLabel, norr::KeyDirection::initiator_to_responder, 0);
  const auto reverse_label =
      norr::make_key_label(norr::kDataLabel, norr::KeyDirection::responder_to_initiator, 0);
  NORR_CHECK(control_label.has_value() && reverse_label.has_value());
  NORR_CHECK(!std::ranges::equal(view, control_label->view()));
  NORR_CHECK(!std::ranges::equal(view, reverse_label->view()));
  NORR_CHECK(!std::ranges::equal(view, generation_one->view()));

  // A large generation is encoded big-endian across all four bytes.
  const auto maximum = norr::make_key_label(norr::kDataLabel,
                                            norr::KeyDirection::responder_to_initiator,
                                            norr::kMaximumKeyGeneration);
  NORR_CHECK(maximum.has_value());
  const auto maximum_view = maximum->view();
  for (std::size_t index = 0; index < 4; ++index) {
    NORR_CHECK(maximum_view[maximum_view.size() - 4 + index] == std::byte{0xFF});
  }

  const auto empty_domain =
      norr::make_key_label("", norr::KeyDirection::initiator_to_responder, 0);
  NORR_CHECK(!empty_domain.has_value());
}
