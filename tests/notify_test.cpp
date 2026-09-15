#include "check.hpp"

#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#if defined(__linux__)
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#endif

#include "norr/notify.hpp"

namespace {

#if defined(__linux__)

void test_without_a_supervisor_nothing_is_sent() {
  ::unsetenv("NOTIFY_SOCKET");
  NORR_CHECK(!norr::under_supervisor());

  NORR_CHECK(!norr::notify_ready());
  NORR_CHECK(!norr::notify_stopping());

  ::setenv("NOTIFY_SOCKET", "", 1);
  NORR_CHECK(!norr::under_supervisor());
  NORR_CHECK(!norr::notify_ready());

  std::puts("notify: absent supervisor reports false OK");
}

void test_ready_reaches_a_listening_socket() {
  const std::string path = "/tmp/norr-notify-test.sock";
  ::unlink(path.c_str());

  const int listener = ::socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  NORR_CHECK(listener >= 0);

  sockaddr_un address{};
  address.sun_family = AF_UNIX;
  std::memcpy(address.sun_path, path.c_str(), path.size());
  NORR_CHECK(::bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);

  ::setenv("NOTIFY_SOCKET", path.c_str(), 1);
  NORR_CHECK(norr::under_supervisor());

  NORR_CHECK(norr::notify_ready());

  char buffer[64]{};
  const auto received = ::recv(listener, buffer, sizeof(buffer) - 1, MSG_DONTWAIT);
  NORR_CHECK(received > 0);
  NORR_CHECK(std::string(buffer, static_cast<std::size_t>(received)) == "READY=1");

  NORR_CHECK(norr::notify_stopping());
  const auto stopping = ::recv(listener, buffer, sizeof(buffer) - 1, MSG_DONTWAIT);
  NORR_CHECK(stopping > 0);
  NORR_CHECK(std::string(buffer, static_cast<std::size_t>(stopping)) == "STOPPING=1");

  ::close(listener);
  ::unlink(path.c_str());
  ::unsetenv("NOTIFY_SOCKET");

  std::puts("notify: READY=1 and STOPPING=1 reach the supervisor socket OK");
}

void test_abstract_socket_is_supported() {
  const int listener = ::socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  NORR_CHECK(listener >= 0);

  const std::string name = "norr-notify-abstract";
  sockaddr_un address{};
  address.sun_family = AF_UNIX;
  address.sun_path[0] = '\0';
  std::memcpy(address.sun_path + 1, name.c_str(), name.size());
  const auto length =
      static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + 1 + name.size());
  NORR_CHECK(::bind(listener, reinterpret_cast<sockaddr*>(&address), length) == 0);

  const std::string advertised = "@" + name;
  ::setenv("NOTIFY_SOCKET", advertised.c_str(), 1);

  NORR_CHECK(norr::notify_ready());

  char buffer[64]{};
  const auto received = ::recv(listener, buffer, sizeof(buffer) - 1, MSG_DONTWAIT);
  NORR_CHECK(received > 0);
  NORR_CHECK(std::string(buffer, static_cast<std::size_t>(received)) == "READY=1");

  ::close(listener);
  ::unsetenv("NOTIFY_SOCKET");

  std::puts("notify: abstract supervisor socket OK");
}

void test_unreachable_socket_is_reported() {
  ::setenv("NOTIFY_SOCKET", "/tmp/norr-notify-does-not-exist.sock", 1);
  NORR_CHECK(norr::under_supervisor());

  NORR_CHECK(!norr::notify_ready());

  ::unsetenv("NOTIFY_SOCKET");
  std::puts("notify: unreachable supervisor reported rather than ignored OK");
}

#endif

}

int main() {
#if defined(__linux__)
  test_without_a_supervisor_nothing_is_sent();
  test_ready_reaches_a_listening_socket();
  test_abstract_socket_is_supported();
  test_unreachable_socket_is_reported();
#else
  NORR_CHECK(!norr::under_supervisor());
  NORR_CHECK(!norr::notify_ready());
  std::puts("notify: Linux only, guards verified");
#endif
  return 0;
}
