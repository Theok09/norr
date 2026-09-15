#include "norr/privilege.hpp"

#include <cerrno>

#if defined(__linux__)
#include <grp.h>
#include <pwd.h>
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

std::expected<void, PrivilegeError> drop_capabilities() noexcept {
  if (!running_as_root()) return {};

  return std::unexpected(PrivilegeError::not_permitted);
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
