#pragma once

#include <string_view>

namespace norr {

[[nodiscard]] bool notify_supervisor(std::string_view state) noexcept;

[[nodiscard]] bool notify_ready() noexcept;

[[nodiscard]] bool notify_stopping() noexcept;

[[nodiscard]] bool under_supervisor() noexcept;

}
