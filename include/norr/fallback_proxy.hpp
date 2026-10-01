// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <vector>

#include "norr/endpoint.hpp"
#include "norr/file_descriptor.hpp"
#include "norr/udp_transport.hpp"

namespace norr {
class FallbackProxy {
 public:
  static constexpr std::size_t kBufferLimit = 65536;

  FallbackProxy() = default;

  [[nodiscard]] std::expected<void, TransportError> start(FileDescriptor client,
                                                          const Endpoint& cover,
                                                          std::span<const std::byte> prelude);

  [[nodiscard]] bool active() const noexcept { return active_; }
  [[nodiscard]] int client_fd() const noexcept { return client_.get(); }
  [[nodiscard]] int cover_fd() const noexcept { return cover_.get(); }
  [[nodiscard]] bool wants_cover_write() const noexcept { return connecting_ || !to_cover_.empty(); }
  [[nodiscard]] bool wants_client_write() const noexcept { return !to_client_.empty(); }

  void pump();
  void close() noexcept;

 private:
  FileDescriptor client_;
  FileDescriptor cover_;
  std::vector<std::byte> to_cover_;
  std::vector<std::byte> to_client_;
  bool connecting_{};
  [[maybe_unused]] bool client_eof_{};
  [[maybe_unused]] bool cover_eof_{};
  bool active_{};
};
}
