// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#include "norr/privilege.hpp"

#include <array>
#include <cerrno>

#if defined(__linux__)
#include <grp.h>
#include <linux/capability.h>
#include <pwd.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace norr {
bool privilege_control_supported() noexcept {
#if defined(__linux__)
  return true;
#else
  return false;
#endif
}

#if !defined(__linux__)

bool running_as_root() noexcept { return false; }

std::expected<void, PrivilegeError> disable_core_dumps() noexcept {
  return std::unexpected(PrivilegeError::unsupported);
}

std::expected<void, PrivilegeError> set_no_new_privileges() noexcept {
  return std::unexpected(PrivilegeError::unsupported);
}

std::expected<void, PrivilegeError> drop_to_user(std::string_view) noexcept {
  return std::unexpected(PrivilegeError::unsupported);
}

std::expected<void, PrivilegeError> drop_capabilities() noexcept {
  return std::unexpected(PrivilegeError::unsupported);
}

std::expected<void, PrivilegeError> drop_privileges(std::string_view, bool, bool) noexcept {
  return std::unexpected(PrivilegeError::unsupported);
}

bool has_net_admin() noexcept { return false; }

bool has_net_raw() noexcept { return false; }

std::expected<void, PrivilegeError> check_key_file_permissions(const std::string&) noexcept {
  return std::unexpected(PrivilegeError::unsupported);
}

PrivilegeState current_privilege_state() noexcept { return PrivilegeState{}; }

#else

bool running_as_root() noexcept { return ::geteuid() == 0; }

std::expected<void, PrivilegeError> disable_core_dumps() noexcept {
  rlimit limit{};
  limit.rlim_cur = 0;
  limit.rlim_max = 0;
  if (::setrlimit(RLIMIT_CORE, &limit) != 0) {
    return std::unexpected(PrivilegeError::not_permitted);
  }

  if (::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) {
    return std::unexpected(PrivilegeError::not_permitted);
  }
  return {};
}

std::expected<void, PrivilegeError> set_no_new_privileges() noexcept {
  if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
    return std::unexpected(PrivilegeError::not_permitted);
  }
  return {};
}

namespace {
constexpr std::uint32_t kNetAdminBit = 1U << CAP_NET_ADMIN;
constexpr std::uint32_t kNetRawBit = 1U << CAP_NET_RAW;

[[nodiscard]] bool read_capabilities(std::array<__user_cap_data_struct, 2>& data) noexcept {
  __user_cap_header_struct header{.version = _LINUX_CAPABILITY_VERSION_3, .pid = 0};
  return ::syscall(SYS_capget, &header, data.data()) == 0;
}

[[nodiscard]] bool set_capabilities(std::uint32_t low_bits) noexcept {
  __user_cap_header_struct header{.version = _LINUX_CAPABILITY_VERSION_3, .pid = 0};
  std::array<__user_cap_data_struct, 2> data{};
  data[0].effective = low_bits;
  data[0].permitted = low_bits;
  data[0].inheritable = 0;
  return ::syscall(SYS_capset, &header, data.data()) == 0;
}

void clear_ambient() noexcept {
#if defined(PR_CAP_AMBIENT)
  static_cast<void>(::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0));
#endif
}
}

bool has_net_admin() noexcept {
  std::array<__user_cap_data_struct, 2> data{};
  if (!read_capabilities(data)) return false;
  return (data[0].effective & kNetAdminBit) != 0U;
}

bool has_net_raw() noexcept {
  std::array<__user_cap_data_struct, 2> data{};
  if (!read_capabilities(data)) return false;
  return (data[0].effective & kNetRawBit) != 0U;
}

std::expected<void, PrivilegeError> drop_capabilities() noexcept {
  clear_ambient();
  if (!set_capabilities(0)) return std::unexpected(PrivilegeError::capability_failed);
  return {};
}

std::expected<void, PrivilegeError> drop_privileges(std::string_view username,
                                                    bool keep_net_admin,
                                                    bool keep_net_raw) noexcept {
  std::array<__user_cap_data_struct, 2> current{};
  if (!read_capabilities(current)) return std::unexpected(PrivilegeError::capability_failed);
  std::uint32_t keep = 0U;
  if (keep_net_admin) keep |= current[0].permitted & kNetAdminBit;
  if (keep_net_raw) keep |= current[0].permitted & kNetRawBit;

  if (running_as_root()) {
    for (unsigned capability = 0; capability < 64; ++capability) {
      if (keep_net_admin && capability == CAP_NET_ADMIN) continue;
      if (keep_net_raw && capability == CAP_NET_RAW) continue;
      if (::prctl(PR_CAPBSET_DROP, capability, 0, 0, 0) != 0 && errno != EINVAL) {
        return std::unexpected(PrivilegeError::capability_failed);
      }
    }
    if (::prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) != 0) {
      return std::unexpected(PrivilegeError::capability_failed);
    }
    if (const auto dropped = drop_to_user(username); !dropped) return dropped;
    static_cast<void>(::prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0));
  }

  clear_ambient();
  if (!set_capabilities(keep)) return std::unexpected(PrivilegeError::capability_failed);
  if (running_as_root()) return std::unexpected(PrivilegeError::still_privileged);
  return {};
}

std::expected<void, PrivilegeError> drop_to_user(std::string_view username) noexcept {
  if (username.empty()) return std::unexpected(PrivilegeError::user_lookup_failed);
  if (!running_as_root()) return {};

  const std::string name{username};
  const auto* entry = ::getpwnam(name.c_str());
  if (entry == nullptr) return std::unexpected(PrivilegeError::user_lookup_failed);

  const auto target_uid = entry->pw_uid;
  const auto target_gid = entry->pw_gid;
  if (target_uid == 0) return std::unexpected(PrivilegeError::not_permitted);

  if (::setgroups(0, nullptr) != 0) return std::unexpected(PrivilegeError::setuid_failed);

  if (::setresgid(target_gid, target_gid, target_gid) != 0) {
    return std::unexpected(PrivilegeError::setuid_failed);
  }
  if (::setresuid(target_uid, target_uid, target_uid) != 0) {
    return std::unexpected(PrivilegeError::setuid_failed);
  }

  if (::geteuid() != target_uid || ::getuid() != target_uid) {
    return std::unexpected(PrivilegeError::still_privileged);
  }
  if (::setuid(0) == 0) {
    return std::unexpected(PrivilegeError::still_privileged);
  }
  return {};
}

std::expected<void, PrivilegeError> check_key_file_permissions(const std::string& path) noexcept {
  struct stat info {};
  if (::stat(path.c_str(), &info) != 0) {
    return std::unexpected(PrivilegeError::user_lookup_failed);
  }

  if ((info.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
    return std::unexpected(PrivilegeError::not_permitted);
  }
  return {};
}

PrivilegeState current_privilege_state() noexcept {
  PrivilegeState state{};
  state.root = running_as_root();
  state.uid = ::getuid();
  state.gid = ::getgid();

  rlimit limit{};
  if (::getrlimit(RLIMIT_CORE, &limit) == 0) {
    state.core_dumps_disabled = limit.rlim_cur == 0;
  }
  const auto no_new = ::prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
  state.no_new_privileges = no_new == 1;
  return state;
}

#endif
}
