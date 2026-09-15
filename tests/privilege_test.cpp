// Privilege reduction and process hardening.
//
// Most of this cannot be exercised without root, so the tests assert the
// behaviour that is reachable and report the rest as skipped rather than
// silently passing.

#include "check.hpp"
#include <cstdio>
#include <cstdlib>
#include <string>

#include "norr/privilege.hpp"

namespace {

void test_state_reporting() {
  const auto state = norr::current_privilege_state();

  if (!norr::privilege_control_supported()) {
    std::puts("privilege: not supported on this platform, skipped");
    return;
  }

  // The reported uid must match what the process actually has: a wrong answer
  // here would make every later decision wrong.
  NORR_CHECK(state.root == norr::running_as_root());
  std::printf("privilege: uid=%u gid=%u root=%s\n", state.uid, state.gid,
              state.root ? "yes" : "no");
}

#if defined(__linux__)

void test_core_dumps_can_be_disabled() {
  const auto before = norr::current_privilege_state();
  NORR_CHECK(norr::disable_core_dumps().has_value());

  const auto after = norr::current_privilege_state();
  NORR_CHECK(after.core_dumps_disabled);
  static_cast<void>(before);

  // A core file from a tunnel contains session keys, so this is closing a real
  // exposure rather than a theoretical one.
  std::puts("privilege: core dumps disabled OK");
}

void test_no_new_privileges() {
  NORR_CHECK(norr::set_no_new_privileges().has_value());

  const auto state = norr::current_privilege_state();
  NORR_CHECK(state.no_new_privileges);

  // Once set this cannot be unset, so a later exec of a setuid binary cannot
  // undo a privilege drop.
  NORR_CHECK(norr::set_no_new_privileges().has_value());

  std::puts("privilege: no-new-privileges set OK");
}

void test_key_file_permissions() {
  const std::string path = "/tmp/norr_key_test";

  // A key readable by others is compromised, and must be refused.
  std::system(("install -m 0644 /dev/null " + path).c_str());
  const auto loose = norr::check_key_file_permissions(path);
  NORR_CHECK(!loose.has_value());
  NORR_CHECK(loose.error() == norr::PrivilegeError::not_permitted);

  // Group-readable is equally wrong: a shared group is not a trust boundary.
  std::system(("chmod 0640 " + path).c_str());
  NORR_CHECK(!norr::check_key_file_permissions(path).has_value());

  // Owner-only is the only acceptable mode.
  std::system(("chmod 0600 " + path).c_str());
  NORR_CHECK(norr::check_key_file_permissions(path).has_value());

  std::system(("rm -f " + path).c_str());

  // A missing file is reported rather than treated as acceptable.
  NORR_CHECK(!norr::check_key_file_permissions("/nonexistent/norr/key").has_value());

  std::puts("privilege: key file permissions enforced OK");
}

void test_drop_when_unprivileged() {
  if (norr::running_as_root()) {
    std::puts("privilege: running as root, unprivileged-path test skipped");
    return;
  }

  // Dropping when already unprivileged is a no-op rather than an error: a
  // caller should not have to branch on whether it started as root.
  NORR_CHECK(norr::drop_to_user("nobody").has_value());
  NORR_CHECK(norr::drop_capabilities().has_value());

  std::puts("privilege: dropping while unprivileged is a no-op OK");
}

void test_root_refuses_to_drop_to_root() {
  if (!norr::running_as_root()) {
    std::puts("privilege: not root, root-target test skipped");
    return;
  }

  // Dropping "to root" is not a drop. Accepting it would leave a process
  // believing it is unprivileged while it is not.
  const auto result = norr::drop_to_user("root");
  NORR_CHECK(!result.has_value());
  NORR_CHECK(result.error() == norr::PrivilegeError::not_permitted);

  std::puts("privilege: refuses to 'drop' to root OK");
}

void test_unknown_user_is_refused() {
  if (!norr::running_as_root()) {
    std::puts("privilege: not root, unknown-user test skipped");
    return;
  }

  const auto result = norr::drop_to_user("norr_no_such_user_12345");
  NORR_CHECK(!result.has_value());
  NORR_CHECK(result.error() == norr::PrivilegeError::user_lookup_failed);

  // An empty name must not be treated as "current user".
  NORR_CHECK(!norr::drop_to_user("").has_value());

  std::puts("privilege: unknown user refused OK");
}

#endif  // __linux__

}  // namespace

int main() {
  test_state_reporting();

#if defined(__linux__)
  test_key_file_permissions();
  test_drop_when_unprivileged();
  test_root_refuses_to_drop_to_root();
  test_unknown_user_is_refused();
  // These change process state irreversibly, so they run last.
  test_core_dumps_can_be_disabled();
  test_no_new_privileges();
#endif
  return 0;
}
