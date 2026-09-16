// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
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
