#pragma once

#include <cstdint>
#include <expected>
#include <string>
#include <string_view>

namespace norr {
enum class PrivilegeError {
  unsupported,
  not_permitted,
  capability_failed,
  user_lookup_failed,
  setuid_failed,
  still_privileged,
};

[[nodiscard]] constexpr std::string_view privilege_error_message(PrivilegeError error) noexcept {
  switch (error) {
    case PrivilegeError::unsupported: return "privilege operations not supported here";
    case PrivilegeError::not_permitted: return "operation not permitted";
    case PrivilegeError::capability_failed: return "capability change failed";
    case PrivilegeError::user_lookup_failed: return "user lookup failed";
    case PrivilegeError::setuid_failed: return "could not change user";
    case PrivilegeError::still_privileged: return "privileges were not actually dropped";
  }
  return "unknown privilege error";
}

[[nodiscard]] bool privilege_control_supported() noexcept;

[[nodiscard]] bool running_as_root() noexcept;

[[nodiscard]] std::expected<void, PrivilegeError> disable_core_dumps() noexcept;

[[nodiscard]] std::expected<void, PrivilegeError> set_no_new_privileges() noexcept;

[[nodiscard]] std::expected<void, PrivilegeError> drop_to_user(std::string_view username) noexcept;

[[nodiscard]] std::expected<void, PrivilegeError> drop_capabilities() noexcept;

[[nodiscard]] std::expected<void, PrivilegeError> check_key_file_permissions(
    const std::string& path) noexcept;

struct PrivilegeState {
  bool root{};
  bool core_dumps_disabled{};
  bool no_new_privileges{};
  std::uint32_t uid{};
  std::uint32_t gid{};
};

[[nodiscard]] PrivilegeState current_privilege_state() noexcept;

}
