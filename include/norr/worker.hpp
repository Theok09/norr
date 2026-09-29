// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <span>
#include <utility>
#include <string_view>
#include <vector>

#include "norr/ip_packet.hpp"
#include "norr/offload.hpp"
#include "norr/parallel.hpp"
#include "norr/pacer.hpp"
#include "norr/qos.hpp"
#include "norr/routing.hpp"
#include "norr/session.hpp"
#include "norr/carrier.hpp"
#include "norr/fec.hpp"
#include "norr/traffic_profile.hpp"
#include "norr/tun.hpp"
#include "norr/udp_transport.hpp"

namespace norr {
enum class DropReason {
  none,
  malformed_inner_packet,
  malformed_outer_packet,
  no_route,
  no_session,
  source_not_authorized,
  policy_denied,
  routing_loop,
  hop_limit,
  authentication_failed,
  replayed,
  too_old,
  counter_exhausted,
  no_endpoint,
  send_failed,
  tun_write_failed,
  oversized,
};

[[nodiscard]] constexpr std::string_view drop_reason_message(DropReason reason) noexcept {
  switch (reason) {
    case DropReason::none: return "not dropped";
    case DropReason::malformed_inner_packet: return "malformed inner IP packet";
    case DropReason::malformed_outer_packet: return "malformed Norr packet";
    case DropReason::no_route: return "no route to destination";
    case DropReason::no_session: return "no session for peer or key id";
    case DropReason::source_not_authorized: return "source address not authorized for peer";
    case DropReason::policy_denied: return "denied by address policy";
    case DropReason::routing_loop: return "destination routes back to the ingress peer";
    case DropReason::hop_limit: return "hop limit exceeded";
    case DropReason::authentication_failed: return "authentication failed";
    case DropReason::replayed: return "replayed packet";
    case DropReason::too_old: return "counter below the replay window";
    case DropReason::counter_exhausted: return "send counter exhausted; rekey required";
    case DropReason::no_endpoint: return "peer endpoint unknown";
    case DropReason::send_failed: return "transport send failed";
    case DropReason::tun_write_failed: return "TUN write failed";
    case DropReason::oversized: return "packet exceeds the configured maximum";
  }
  return "unknown drop reason";
}

struct WorkerStats {
  std::uint64_t tun_to_udp{};
  std::uint64_t udp_to_tun{};
  std::uint64_t keepalives_received{};
  std::uint64_t drops{};

  std::array<std::uint64_t, 17> drop_reasons{};

  void record_drop(DropReason reason) noexcept {
    ++drops;
    drop_reasons[static_cast<std::size_t>(reason)] += 1;
  }

  [[nodiscard]] std::uint64_t drops_for(DropReason reason) const noexcept {
    return drop_reasons[static_cast<std::size_t>(reason)];
  }
};

class Worker {
 public:

  static constexpr std::size_t kFrameBufferSize = TunDevice::kMaximumFrameSize;

  Worker(TunDevice& tun, Carrier& carrier, RoutingTable& routes, SessionTable& sessions);

  void set_carrier(Carrier& carrier) noexcept { transport_ = &carrier; }

  void set_mtu(std::size_t mtu);
  [[nodiscard]] std::size_t mtu() const noexcept { return mtu_; }

  using SessionRequest = std::function<void(PeerId)>;
  void set_session_request(SessionRequest request) { session_request_ = std::move(request); }
  [[nodiscard]] Carrier& carrier() const noexcept { return *transport_; }

  [[nodiscard]] std::size_t pump_tun_to_udp(std::size_t max_frames = 64);

  [[nodiscard]] std::size_t pump_udp_to_tun(std::size_t max_datagrams = 64);

  std::size_t poll();

  [[nodiscard]] const WorkerStats& stats() const noexcept { return stats_; }

  void enable_queueing(double bytes_per_second, std::size_t burst_bytes, Instant now);

  void enable_fec(FecMode mode);

  [[nodiscard]] FecMode fec_mode() const noexcept { return fec_mode_; }
  [[nodiscard]] const FecStats& fec_stats() const noexcept;
  [[nodiscard]] const FecStats& fec_decode_stats() const noexcept;
  [[nodiscard]] bool fec_pending() const noexcept;

  void set_traffic_profile(TrafficProfile profile) noexcept { profile_ = profile; }

  [[nodiscard]] TrafficProfile traffic_profile() const noexcept { return profile_; }

  std::size_t send_chaff(Instant now);

  [[nodiscard]] std::uint64_t chaff_sent() const noexcept { return chaff_sent_; }

  [[nodiscard]] bool queueing_enabled() const noexcept { return queueing_enabled_; }
  [[nodiscard]] const Scheduler& scheduler() const noexcept { return scheduler_; }
  [[nodiscard]] const Pacer& pacer() const noexcept { return pacer_; }

  void set_pacing_rate(double bytes_per_second) noexcept {
    if (queueing_enabled_) pacer_.set_rate_bytes_per_second(bytes_per_second);
  }

  [[nodiscard]] std::uint64_t bytes_sent() const noexcept { return bytes_sent_; }
  [[nodiscard]] std::uint64_t bytes_dropped() const noexcept { return bytes_dropped_; }

  std::size_t flush(Instant now) {
    flush_tun_writes();
    flush_fec(now);
    return drain_queue(now);
  }

  using EchoResponder = std::function<void(PeerId, std::span<const std::byte>)>;

  void set_echo_responder(EchoResponder responder) { echo_responder_ = std::move(responder); }

  using EchoReplyHandler = std::function<void(PeerId, std::span<const std::byte>)>;

  void set_echo_reply_handler(EchoReplyHandler handler) {
    echo_reply_handler_ = std::move(handler);
  }

  using IngressFilter = std::function<bool(const Endpoint&, std::span<const std::byte>)>;

  void set_ingress_filter(IngressFilter filter) { ingress_filter_ = std::move(filter); }

  using ProvisionalOpener = std::function<std::optional<std::size_t>(
      const PacketView&, std::span<const std::byte>, std::span<std::byte>, const Endpoint&)>;

  void set_provisional_opener(ProvisionalOpener opener) {
    provisional_opener_ = std::move(opener);
  }

  [[nodiscard]] DropReason forward_from_tun(std::span<const std::byte> frame);

  std::size_t flush_transmit();

  [[nodiscard]] DropReason forward_from_transport(const Endpoint& source,
                                                  std::span<const std::byte> datagram);

  [[nodiscard]] DropReason forward_sealed(const Endpoint& source,
                                          std::span<const std::byte> datagram,
                                          bool recovered = false);

  [[nodiscard]] std::optional<FecPlan> note_peer_loss(PeerId peer, double raw_loss,
                                                      double residual_loss, bool rtt_inflated,
                                                      Instant now);

  [[nodiscard]] FecPlan peer_fec_plan(PeerId peer) const noexcept;

  using LossReportHandler = std::function<void(PeerId, double, double)>;
  void set_loss_report_handler(LossReportHandler handler) {
    loss_report_handler_ = std::move(handler);
  }

 private:

  [[nodiscard]] std::size_t drain_queue(Instant now);

  [[nodiscard]] DropReason route_from_tun(std::span<const std::byte> frame, bool batch);

  [[nodiscard]] DropReason deliver_opened(PeerId ingress_peer, FrameType type,
                                          std::span<const std::byte> padded_plaintext, bool stable);

  [[nodiscard]] bool stage_receive(const Endpoint& source, std::span<const std::byte> datagram);

  std::size_t settle_receive();

  void flush_fec(Instant now);

  TunDevice* tun_;
  Carrier* transport_;
  RoutingTable* routes_;
  SessionTable* sessions_;

  std::vector<std::byte> tun_read_buffer_;
  std::vector<std::byte> encrypt_buffer_;
  std::vector<std::byte> pad_buffer_;
  std::vector<std::byte> decrypt_buffer_;
  ReceiveBuffers receive_pool_;
  std::vector<InboundDatagram> inbound_;

  Scheduler scheduler_;
  Pacer pacer_;
  std::uint64_t bytes_sent_{};
  std::uint64_t bytes_dropped_{};

  TrafficProfile profile_{TrafficProfile::standard};
  Instant last_outbound_{};
  std::uint64_t chaff_sent_{};
  bool queueing_enabled_{};

  IngressFilter ingress_filter_;
  ProvisionalOpener provisional_opener_;
  SessionRequest session_request_;

  std::size_t mtu_{kDefaultTunnelMtu};
  std::vector<std::byte> segment_scratch_;
  TcpCoalescer coalescer_;
  void flush_tun_writes();
  std::vector<std::vector<std::byte>> transmit_slots_;
  std::vector<OutboundDatagram> transmit_batch_;

  struct TransmitJob {
    std::shared_ptr<Session> session;
    std::uint64_t counter{};
    std::size_t length{};
    Endpoint destination{};
    std::size_t sealed{};
    std::size_t fec{kNoFec};
    std::uint32_t flow{};
    bool ok{};
  };
  static constexpr std::size_t kNoFec = static_cast<std::size_t>(-1);
  std::vector<std::vector<std::byte>> transmit_plain_;
  std::vector<std::vector<std::byte>> parity_slots_;
  std::vector<TransmitJob> transmit_jobs_;

  struct ReceiveJob {
    std::shared_ptr<Session> session;
    PacketView view{};
    std::span<const std::byte> datagram;
    Endpoint source{};
    std::size_t length{};
    SessionError error{};
    bool ok{};
  };
  std::vector<std::vector<std::byte>> receive_plain_;
  std::vector<ReceiveJob> receive_jobs_;

  ParallelRunner runner_;
  EchoResponder echo_responder_;
  EchoReplyHandler echo_reply_handler_;
  LossReportHandler loss_report_handler_;

  struct FecPeer {
    PeerId peer{kNoPeer};
    Endpoint destination{};
    FecEncoder encoder;
    Instant last_symbol{};
    AdaptiveFec controller{};
    std::uint64_t packets{};
    std::uint64_t packets_at_report{};
    std::uint64_t send_failures_at_report{};
    std::uint64_t sent_at_report{};
    Instant last_report{};
  };
  struct FecSource {
    Endpoint source{};
    FecDecoder decoder;
    Instant last_seen{};
  };
  static constexpr std::size_t kMaximumFecSources = 256;

  [[nodiscard]] FecPeer& fec_peer(PeerId peer, const Endpoint& destination);
  [[nodiscard]] std::size_t fec_index(PeerId peer, const Endpoint& destination);
  void send_parity(FecPeer& entry, std::span<const std::vector<std::byte>> parity);
  [[nodiscard]] FecSource& fec_source(const Endpoint& source, Instant now);
  std::size_t send_all(std::span<const OutboundDatagram> datagrams);

  FecMode fec_mode_{FecMode::off};
  std::vector<FecPeer> fec_peers_;
  std::vector<FecSource> fec_sources_;
  std::vector<std::byte> fec_buffer_;
  std::vector<OutboundDatagram> fec_batch_;
  mutable FecStats fec_encode_total_{};
  mutable FecStats fec_decode_total_{};

  WorkerStats stats_{};
};
}
