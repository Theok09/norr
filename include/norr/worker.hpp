#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <span>
#include <utility>
#include <string_view>
#include <vector>

#include "norr/ip_packet.hpp"
#include "norr/pacer.hpp"
#include "norr/qos.hpp"
#include "norr/routing.hpp"
#include "norr/session.hpp"
#include "norr/carrier.hpp"
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
  [[nodiscard]] Carrier& carrier() const noexcept { return *transport_; }

  [[nodiscard]] std::size_t pump_tun_to_udp(std::size_t max_frames = 64);

  [[nodiscard]] std::size_t pump_udp_to_tun(std::size_t max_datagrams = 64);

  std::size_t poll();

  [[nodiscard]] const WorkerStats& stats() const noexcept { return stats_; }

  void enable_queueing(double bytes_per_second, std::size_t burst_bytes, Instant now);

  [[nodiscard]] bool queueing_enabled() const noexcept { return queueing_enabled_; }
  [[nodiscard]] const Scheduler& scheduler() const noexcept { return scheduler_; }
  [[nodiscard]] const Pacer& pacer() const noexcept { return pacer_; }

  std::size_t flush(Instant now) { return drain_queue(now); }

  using IngressFilter = std::function<bool(const Endpoint&, std::span<const std::byte>)>;

  void set_ingress_filter(IngressFilter filter) { ingress_filter_ = std::move(filter); }

  using ProvisionalOpener = std::function<std::optional<std::size_t>(
      const PacketView&, std::span<const std::byte>, std::span<std::byte>, const Endpoint&)>;

  void set_provisional_opener(ProvisionalOpener opener) {
    provisional_opener_ = std::move(opener);
  }

  [[nodiscard]] DropReason forward_from_tun(std::span<const std::byte> frame);

  [[nodiscard]] DropReason forward_from_transport(const Endpoint& source,
                                                  std::span<const std::byte> datagram);

 private:

  [[nodiscard]] std::size_t drain_queue(Instant now);

  TunDevice* tun_;
  Carrier* transport_;
  RoutingTable* routes_;
  SessionTable* sessions_;

  std::vector<std::byte> tun_read_buffer_;
  std::vector<std::byte> encrypt_buffer_;
  std::vector<std::byte> decrypt_buffer_;
  ReceiveBuffers receive_pool_;
  std::vector<InboundDatagram> inbound_;

  Scheduler scheduler_;
  Pacer pacer_;
  bool queueing_enabled_{};

  IngressFilter ingress_filter_;
  ProvisionalOpener provisional_opener_;

  WorkerStats stats_{};
};

}
