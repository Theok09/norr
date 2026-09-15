#pragma once

#include <atomic>
#include <cstdint>
#include <expected>
#include <memory>
#include <string>
#include <string_view>

#include "norr/config.hpp"
#include "norr/carrier.hpp"
#include "norr/control_plane.hpp"
#include "norr/crypto.hpp"
#include "norr/routing.hpp"
#include "norr/metrics.hpp"
#include "norr/session.hpp"
#include "norr/timers.hpp"
#include "norr/tun.hpp"
#include "norr/udp_transport.hpp"
#include "norr/worker.hpp"

namespace norr {
enum class RuntimeError {
  unsupported_platform,
  crypto_unavailable,
  key_file_unreadable,
  key_file_permissions,
  key_file_malformed,
  peer_key_malformed,
  peer_endpoint_malformed,
  peer_prefix_malformed,
  routing_conflict,
  tun_failed,
  bind_failed,
  control_failed,
  option_not_implemented,
};

[[nodiscard]] constexpr std::string_view runtime_error_message(RuntimeError error) noexcept {
  switch (error) {
    case RuntimeError::unsupported_platform: return "runtime requires Linux";
    case RuntimeError::crypto_unavailable: return "crypto backend unavailable";
    case RuntimeError::key_file_unreadable: return "identity key file cannot be read";
    case RuntimeError::key_file_permissions: return "identity key file is readable by others";
    case RuntimeError::key_file_malformed: return "identity key file is not a 64-character hex key";
    case RuntimeError::peer_key_malformed: return "peer public key is malformed";
    case RuntimeError::peer_endpoint_malformed: return "peer endpoint is not address:port";
    case RuntimeError::peer_prefix_malformed: return "peer allowed_ips entry is not a prefix";
    case RuntimeError::routing_conflict: return "two peers claim the same prefix";
    case RuntimeError::tun_failed: return "cannot open the TUN device";
    case RuntimeError::bind_failed: return "cannot bind the listen port";
    case RuntimeError::control_failed: return "cannot configure the control plane";
    case RuntimeError::option_not_implemented:
      return "configuration requests a feature this build does not implement";
  }
  return "unknown runtime error";
}

struct RuntimeDiagnostic {
  RuntimeError error{};
  std::string detail;
};

class Runtime {
 public:
  Runtime() = default;
  ~Runtime();

  Runtime(const Runtime&) = delete;
  Runtime& operator=(const Runtime&) = delete;

  [[nodiscard]] std::expected<void, RuntimeDiagnostic> start(const Config& config);

  void run();

  void stop() noexcept { running_.store(false, std::memory_order_relaxed); }

  [[nodiscard]] bool running() const noexcept {
    return running_.load(std::memory_order_relaxed);
  }

  [[nodiscard]] const std::string& interface_name() const noexcept { return tun_.name(); }
  [[nodiscard]] std::size_t peer_count() const noexcept { return peer_count_; }
  [[nodiscard]] const WorkerStats& stats() const;
  [[nodiscard]] const ControlStats& control_stats() const;
  [[nodiscard]] TransportKind active_transport() const noexcept { return active_kind_; }
  [[nodiscard]] const MetricsServer& metrics() const noexcept { return metrics_; }

  [[nodiscard]] std::size_t dial_configured_peers();

 private:

  void service_timers(Instant now);

  void send_keepalive(PeerId peer);

  [[nodiscard]] bool dispatch_control(const Endpoint& source,
                                      std::span<const std::byte> datagram);

  void send_outgoing(const OutgoingHandshake& outgoing);

  TunDevice tun_;
  UdpTransport transport_;
  RoutingTable routes_;
  SessionTable sessions_;
  TimerWheel timers_;
  std::unique_ptr<Carrier> carrier_;
  std::unique_ptr<ControlPlane> control_;
  std::unique_ptr<Worker> worker_;
  MetricsServer metrics_;

  KeyPair local_static_{};
  TransportKind active_kind_{TransportKind::udp};
  std::size_t peer_count_{};

  bool handled_control_{};
  std::atomic<bool> running_{false};
};

[[nodiscard]] std::expected<PrivateKey, RuntimeError> load_private_key(const std::string& path);

[[nodiscard]] bool decode_hex(std::string_view text, std::span<std::byte> out) noexcept;

}
