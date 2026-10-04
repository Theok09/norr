// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#pragma once

#include <atomic>
#include <cstdint>
#include <expected>
#include <memory>
#include <string>
#include <string_view>

#include "norr/config.hpp"
#include "norr/congestion.hpp"
#include "norr/carrier.hpp"
#include "norr/fallback_proxy.hpp"
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

  [[nodiscard]] Duration measured_rtt() const noexcept { return last_rtt_; }

  [[nodiscard]] bool congestion_active() const noexcept { return congestion_enabled_; }
  [[nodiscard]] const CongestionStats& congestion_stats() const noexcept {
    return congestion_.stats();
  }
  [[nodiscard]] double pacing_rate() const noexcept {
    return congestion_.rate_bytes_per_second();
  }

  [[nodiscard]] FecMode fec_mode() const;
  [[nodiscard]] const FecStats& fec_encode_stats() const;
  [[nodiscard]] const FecStats& fec_decode_stats() const;
  [[nodiscard]] TransportKind active_transport() const noexcept { return active_kind_; }
  [[nodiscard]] const MetricsServer& metrics() const noexcept { return metrics_; }

  [[nodiscard]] std::size_t dial_configured_peers();

  [[nodiscard]] std::expected<std::size_t, RuntimeDiagnostic> reload(const std::string& path);

  void request_reload() noexcept { reload_requested_.store(true, std::memory_order_relaxed); }

 private:

  void service_timers(Instant now);

  void send_keepalive(PeerId peer);
  void send_control(PeerId peer, std::span<const std::byte> payload);
  void answer_echo(PeerId peer, std::span<const std::byte> token);
  void note_echo_reply(PeerId peer, std::span<const std::byte> token);

  void redial_dead_peers(Instant now);
  void request_session(PeerId peer);
  void wait_for_work(Instant now);
  void report_loss(Instant now);
  void apply_congestion_control(Instant now);

  void service_tcp_carrier(Instant now);

  void service_quic_carrier();

  void evaluate_transport_paths(Instant now);

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
  Instant tcp_accepted_at_{};
  Instant tcp_ready_since_{};
  std::uint64_t tcp_silence_resets_{};
  bool quic_ready_{};
  Endpoint reality_cover_{};
  bool reality_cover_valid_{};
  std::vector<FallbackProxy> fallbacks_;
  void service_fallbacks();

  bool reality_server_{};
  PrivateKey reality_server_priv_{};
  std::uint64_t reality_window_{120};
  std::string reality_sni_{};
  std::vector<TcpTransport> pending_;
  std::vector<Instant> pending_since_;
  void drive_pending(Instant now);
  [[nodiscard]] Instant primary_heard();

  IcmpTransport icmp_transport_;
  std::unique_ptr<UdpCarrier> udp_carrier_;
  std::unique_ptr<IcmpCarrier> icmp_carrier_;
  std::unique_ptr<TcpCarrier> tcp_carrier_;
  std::unique_ptr<QuicCarrier> quic_carrier_;
  PathSelector paths_;
  bool automatic_fallback_{};
  Instant last_path_check_{};
  std::uint64_t last_tx_errors_{};
  std::uint64_t last_retries_{};
  std::uint32_t consecutive_stalls_{};
  Instant switched_at_{};

  Duration last_rtt_{};
  Duration min_rtt_{};
  Instant min_rtt_at_{};
  std::uint64_t socket_drops_{};
  [[nodiscard]] bool rtt_inflated() const noexcept;
  [[nodiscard]] std::uint64_t read_socket_drops() const noexcept;

  CongestionController congestion_;
  bool congestion_enabled_{};
  Instant last_congestion_sample_{};
  std::uint64_t last_bytes_sent_{};
  std::uint64_t last_bytes_dropped_{};
  std::string config_path_;
  std::uint16_t listen_port_{};
  Instant last_liveness_sweep_{};
  std::uint32_t fwmark_{};
  Instant last_loss_report_{};
  bool fec_configured_{};
  std::atomic<bool> running_{false};
};

[[nodiscard]] std::expected<PrivateKey, RuntimeError> load_private_key(const std::string& path);

[[nodiscard]] bool decode_hex(std::string_view text, std::span<std::byte> out) noexcept;
}
