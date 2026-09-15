#include "norr/notify.hpp"

#include <cstddef>
#include <cstdlib>
#include <cstring>

#if defined(__linux__)
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#endif

#include "norr/file_descriptor.hpp"

namespace norr {

#if !defined(__linux__)

bool notify_supervisor(std::string_view) noexcept { return false; }
bool under_supervisor() noexcept { return false; }

#else

bool under_supervisor() noexcept {
  const char* path = std::getenv("NOTIFY_SOCKET");
  return path != nullptr && path[0] != '\0';
}

bool notify_supervisor(std::string_view state) noexcept {
  const char* path = std::getenv("NOTIFY_SOCKET");
  if (path == nullptr || path[0] == '\0') return false;
  if (state.empty()) return false;

  const auto length = std::strlen(path);
  sockaddr_un address{};
  if (length >= sizeof(address.sun_path)) return false;

  address.sun_family = AF_UNIX;
  std::memcpy(address.sun_path, path, length);

  if (address.sun_path[0] == '@') address.sun_path[0] = '\0';

  FileDescriptor socket{::socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0)};
  if (!socket.valid()) return false;

  const auto address_length =
      static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + length);

  const auto sent = ::sendto(socket.get(), state.data(), state.size(), MSG_NOSIGNAL,
                             reinterpret_cast<const sockaddr*>(&address), address_length);
  return sent == static_cast<ssize_t>(state.size());
}

#endif

bool notify_ready() noexcept { return notify_supervisor("READY=1"); }

bool notify_stopping() noexcept { return notify_supervisor("STOPPING=1"); }

}
