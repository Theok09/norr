// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#include "norr/capability.hpp"

#include <algorithm>

namespace norr {
std::expected<NegotiatedCapabilities, NegotiationError> negotiate_capabilities(
    const CapabilityOffer& local, const CapabilityOffer& peer) noexcept {
  if (local.version.major != peer.version.major) {
    return std::unexpected(NegotiationError::major_version_mismatch);
  }
  const auto enabled = local.supported & peer.supported;
  const auto required = local.required | peer.required;
  if ((enabled & required) != required) {
    return std::unexpected(NegotiationError::required_capability_missing);
  }
  return NegotiatedCapabilities{
      .version = {.major = local.version.major, .minor = std::min(local.version.minor, peer.version.minor)},
      .enabled = enabled,
  };
}

}
