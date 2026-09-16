// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#pragma once

#include <utility>

namespace norr {
class FileDescriptor {
 public:
  static constexpr int kInvalid = -1;

  FileDescriptor() = default;
  explicit FileDescriptor(int descriptor) noexcept : descriptor_(descriptor) {}

  FileDescriptor(const FileDescriptor&) = delete;
  FileDescriptor& operator=(const FileDescriptor&) = delete;

  FileDescriptor(FileDescriptor&& other) noexcept
      : descriptor_(std::exchange(other.descriptor_, kInvalid)) {}

  FileDescriptor& operator=(FileDescriptor&& other) noexcept {
    if (this != &other) {
      reset();
      descriptor_ = std::exchange(other.descriptor_, kInvalid);
    }
    return *this;
  }

  ~FileDescriptor() { reset(); }

  [[nodiscard]] int get() const noexcept { return descriptor_; }
  [[nodiscard]] bool valid() const noexcept { return descriptor_ != kInvalid; }
  explicit operator bool() const noexcept { return valid(); }

  [[nodiscard]] int release() noexcept { return std::exchange(descriptor_, kInvalid); }

  void reset(int descriptor = kInvalid) noexcept;

 private:
  int descriptor_{kInvalid};
};

}
