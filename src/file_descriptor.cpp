#include "norr/file_descriptor.hpp"

#include <unistd.h>

#include <cerrno>

namespace norr {
void FileDescriptor::reset(int descriptor) noexcept {
  if (descriptor_ != kInvalid) {
    const auto saved = errno;
    ::close(descriptor_);
    errno = saved;
  }
  descriptor_ = descriptor;
}

}
