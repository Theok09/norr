// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#include "norr/routing.hpp"

#include <algorithm>

namespace norr {
std::expected<void, RoutingError> RoutingTable::add(PeerId peer, const Prefix& prefix) {
  if (peer == kNoPeer) return std::unexpected(RoutingError::invalid_peer);
  if (entries_.size() >= kMaximumPrefixes) {
    return std::unexpected(RoutingError::too_many_prefixes);
  }

  for (const auto& entry : entries_) {
    if (entry.prefix == prefix) {
      if (entry.peer == peer) return {};
      return std::unexpected(RoutingError::duplicate_prefix);
    }
  }

  const auto position = std::ranges::lower_bound(
      entries_, prefix.length(), std::ranges::greater{},
      [](const Entry& entry) { return entry.prefix.length(); });
  entries_.insert(position, Entry{.prefix = prefix, .peer = peer});
  return {};
}

std::expected<void, RoutingError> RoutingTable::add_local(const Prefix& prefix) {
  if (local_.size() >= kMaximumPrefixes) {
    return std::unexpected(RoutingError::too_many_prefixes);
  }

  if (std::ranges::find(local_, prefix) != local_.end()) return {};
  local_.push_back(prefix);
  return {};
}

bool RoutingTable::is_local(const Address& address) const noexcept {
  return std::ranges::any_of(local_, [&](const Prefix& prefix) {
    return prefix.family() == address.family() && prefix.contains(address);
  });
}

PeerId RoutingTable::lookup(const Address& address) const noexcept {
  for (const auto& entry : entries_) {
    if (entry.prefix.family() != address.family()) continue;
    if (entry.prefix.contains(address)) return entry.peer;
  }
  return kNoPeer;
}

bool RoutingTable::is_authorized(PeerId peer, const Address& address) const noexcept {
  if (peer == kNoPeer) return false;
  for (const auto& entry : entries_) {
    if (entry.peer != peer) continue;
    if (entry.prefix.family() != address.family()) continue;
    if (entry.prefix.contains(address)) return true;
  }
  return false;
}

ForwardResult RoutingTable::classify(const IpPacketView& packet,
                                     PeerId ingress_peer) const noexcept {
  const auto refuse = [](ForwardDecision decision) {
    return ForwardResult{.decision = decision, .peer = kNoPeer};
  };

  if (is_multicast(packet.destination)) return refuse(ForwardDecision::multicast_denied);
  if (is_unspecified(packet.destination) || is_unspecified(packet.source)) {
    return refuse(ForwardDecision::unspecified_address);
  }
  if (is_loopback(packet.destination) || is_loopback(packet.source)) {
    return refuse(ForwardDecision::loopback_address);
  }

  if (packet.hop_limit <= 1) return refuse(ForwardDecision::hop_limit_exceeded);

  if (ingress_peer != kNoPeer && !is_authorized(ingress_peer, packet.source)) {
    return refuse(ForwardDecision::source_not_authorized);
  }

  if (is_local(packet.destination)) {
    return ForwardResult{.decision = ForwardDecision::deliver_local, .peer = kNoPeer};
  }

  const auto destination_peer = lookup(packet.destination);
  if (destination_peer == kNoPeer) return refuse(ForwardDecision::no_route);

  if (destination_peer == ingress_peer) return refuse(ForwardDecision::routing_loop);

  return ForwardResult{.decision = ForwardDecision::forward, .peer = destination_peer};
}

}
