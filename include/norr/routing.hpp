#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <vector>

#include "norr/address.hpp"
#include "norr/ip_packet.hpp"

namespace norr {
using PeerId = std::uint32_t;
inline constexpr PeerId kNoPeer = 0;

enum class RoutingError {
  duplicate_prefix,
  invalid_peer,
  prefix_family_mismatch,
  too_many_prefixes,
};

[[nodiscard]] constexpr std::string_view routing_error_message(RoutingError error) noexcept {
  switch (error) {
    case RoutingError::duplicate_prefix: return "prefix already assigned to another peer";
    case RoutingError::invalid_peer: return "invalid peer id";
    case RoutingError::prefix_family_mismatch: return "prefix family mismatch";
    case RoutingError::too_many_prefixes: return "peer prefix limit exceeded";
  }
  return "unknown routing error";
}

enum class ForwardDecision {
  forward,

  deliver_local,
  no_route,
  source_not_authorized,
  multicast_denied,
  unspecified_address,
  loopback_address,
  hop_limit_exceeded,
  routing_loop,
};

[[nodiscard]] constexpr std::string_view forward_decision_message(ForwardDecision decision) noexcept {
  switch (decision) {
    case ForwardDecision::forward: return "forward";
    case ForwardDecision::deliver_local: return "deliver to the local interface";
    case ForwardDecision::no_route: return "no route to destination";
    case ForwardDecision::source_not_authorized: return "source address not authorized for peer";
    case ForwardDecision::multicast_denied: return "multicast denied by default";
    case ForwardDecision::unspecified_address: return "unspecified address";
    case ForwardDecision::loopback_address: return "loopback address";
    case ForwardDecision::hop_limit_exceeded: return "hop limit exceeded";
    case ForwardDecision::routing_loop: return "destination routes back to the ingress peer";
  }
  return "unknown decision";
}

struct ForwardResult {
  ForwardDecision decision{ForwardDecision::no_route};
  PeerId peer{kNoPeer};

  [[nodiscard]] explicit operator bool() const noexcept {
    return decision == ForwardDecision::forward || decision == ForwardDecision::deliver_local;
  }
};

class RoutingTable {
 public:
  static constexpr std::size_t kMaximumPrefixes = 4096;

  [[nodiscard]] std::expected<void, RoutingError> add(PeerId peer, const Prefix& prefix);

  [[nodiscard]] std::expected<void, RoutingError> add_local(const Prefix& prefix);

  [[nodiscard]] bool is_local(const Address& address) const noexcept;

  [[nodiscard]] PeerId lookup(const Address& address) const noexcept;

  [[nodiscard]] bool is_authorized(PeerId peer, const Address& address) const noexcept;

  [[nodiscard]] ForwardResult classify(const IpPacketView& packet,
                                       PeerId ingress_peer) const noexcept;

  [[nodiscard]] std::size_t size() const noexcept { return entries_.size(); }

  // Drops every peer prefix, keeping the local ones.
  //
  // A reload rebuilds peer routing from the new configuration. Local addresses
  // belong to the interface, which a reload does not touch.
  void clear_peer_routes() noexcept { entries_.clear(); }

 private:
  struct Entry {
    Prefix prefix;
    PeerId peer{kNoPeer};
  };

  std::vector<Entry> entries_;
  std::vector<Prefix> local_;
};

}
