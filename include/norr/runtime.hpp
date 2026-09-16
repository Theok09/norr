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

  // Remembers where the configuration came from, so a reload can re-read it.
  void set_config_path(std::string path) { config_path_ = std::move(path); }

  void run();

  void stop() noexcept { running_.store(false, std::memory_order_relaxed); }

  [[nodiscard]] bool running() const noexcept {
    return running_.load(std::memory_order_relaxed);
  }

  [[nodiscard]] const std::string& interface_name() const noexcept { return tun_.name(); }
  [[nodiscard]] std::size_t peer_count() const noexcept { return peer_count_; }
  [[nodiscard]] const WorkerStats& stats() const;
  [[nodiscard]] const ControlStats& control_stats() const;
  [[nodiscard]] FecMode fec_mode() const;
  [[nodiscard]] const FecStats& fec_encode_stats() const;
  [[nodiscard]] const FecStats& fec_decode_stats() const;
  [[nodiscard]] TransportKind active_transport() const noexcept { return active_kind_; }
  [[nodiscard]] const MetricsServer& metrics() const noexcept { return metrics_; }

  [[nodiscard]] std::size_t dial_configured_peers();

  // Re-reads the configuration and applies what can change while running:
  // the peer set, their keys, endpoints and prefixes.
  //
  // Anything bound to the interface or the socket — the TUN name, the listen
  // port, the addresses, the carrier — is refused rather than half-applied,
  // because changing those means recreating the device and dropping every
  // session, which is a restart by another name.
  [[nodiscard]] std::expected<std::size_t, RuntimeDiagnostic> reload(const std::string& path);

  // Safe to call from a signal handler: it only stores to an atomic flag.
  void request_reload() noexcept { reload_requested_.store(true, std::memory_order_relaxed); }

 private:

  void service_timers(Instant now);

  void send_keepalive(PeerId peer);

  void redial_dead_peers(Instant now);

  // Accepts an inbound TCP connection and advances the carrier's connect and
  // TLS handshake. A no-op unless the TCP carrier is the active one.
  void service_tcp_carrier(Instant now);

  // Drives the QUIC handshake and dials the Noise handshake once it is up.
  // A no-op unless the QUIC carrier is the active one.
  void service_quic_carrier();

  // Samples each carrier's health and switches when the active one stops
  // working. Only runs when more than one carrier was built.
  void evaluate_transport_paths(Instant now);

  // Builds whichever carriers this configuration and build can support.
  [[nodiscard]] std::expected<void, RuntimeDiagnostic> build_carriers(
      const Config& config, const Endpoint& bind_address);

  [[nodiscard]] bool dispatch_control(const Endpoint& source,
                                      std::span<const std::byte> datagram);

  void send_outgoing(const OutgoingHandshake& outgoing);

  TunDevice tun_;
  UdpTransport transport_;
  RoutingTable routes_;
  SessionTable sessions_;
  TimerWheel timers_;
  // Observes whichever carrier is active. The three below own them, so a
  // switch is a pointer change and the inactive carriers keep their state.
  Carrier* carrier_{};
  std::unique_ptr<QuicConnection> quic_;
  TcpTransport tcp_;
  TcpListener tcp_listener_;
  std::unique_ptr<ControlPlane> control_;
  std::unique_ptr<Worker> worker_;
  MetricsServer metrics_;

  KeyPair local_static_{};
  TransportKind active_kind_{TransportKind::udp};
  std::size_t peer_count_{};

  bool handled_control_{};
  std::atomic<bool> reload_requested_{false};
  bool tcp_ready_{};
  bool quic_ready_{};

  // Every carrier that could be used, kept alive so a switch is a pointer
  // change rather than a reconnection.
  std::unique_ptr<Carrier> udp_carrier_;
  std::unique_ptr<Carrier> tcp_carrier_;
  std::unique_ptr<Carrier> quic_carrier_;
  PathSelector paths_;
  bool automatic_fallback_{};
  Instant last_path_check_{};
  std::uint64_t last_tx_errors_{};
  std::string config_path_;
  std::uint16_t listen_port_{};
  Instant last_liveness_sweep_{};
  std::atomic<bool> running_{false};
};

[[nodiscard]] std::expected<PrivateKey, RuntimeError> load_private_key(const std::string& path);

[[nodiscard]] bool decode_hex(std::string_view text, std::span<std::byte> out) noexcept;

}
