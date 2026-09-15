#pragma once

#include <cstdint>
#include <expected>
#include <string>
#include <string_view>

#include "norr/control_plane.hpp"
#include "norr/endpoint.hpp"
#include "norr/file_descriptor.hpp"
#include "norr/session.hpp"
#include "norr/udp_transport.hpp"
#include "norr/worker.hpp"

namespace norr {
enum class MetricsError {
  unsupported_platform,
  bind_failed,
  already_started,
};

[[nodiscard]] constexpr std::string_view metrics_error_message(MetricsError error) noexcept {
  switch (error) {
    case MetricsError::unsupported_platform: return "metrics endpoint requires Linux";
    case MetricsError::bind_failed: return "cannot bind the metrics address";
    case MetricsError::already_started: return "metrics endpoint already started";
  }
  return "unknown metrics error";
}

struct MetricsSnapshot {
  const WorkerStats* worker{};
  const ControlStats* control{};
  const TunStats* tun{};
  const TransportStats* transport{};
  std::size_t sessions{};
  std::size_t peers{};
};

[[nodiscard]] std::string render_prometheus(const MetricsSnapshot& snapshot);

class MetricsServer {
 public:
  static constexpr std::size_t kMaximumRequestBytes = 8192;

  MetricsServer() = default;
  ~MetricsServer();

  MetricsServer(const MetricsServer&) = delete;
  MetricsServer& operator=(const MetricsServer&) = delete;

  [[nodiscard]] std::expected<void, MetricsError> start(const Endpoint& bind_address);

  void stop() noexcept;

  [[nodiscard]] bool listening() const noexcept { return socket_.valid(); }

  [[nodiscard]] std::expected<std::uint16_t, MetricsError> local_port() const;

  std::size_t poll(const MetricsSnapshot& snapshot);

  [[nodiscard]] std::uint64_t requests_served() const noexcept { return served_; }

 private:
  FileDescriptor socket_;
  std::uint64_t served_{};
};

}
