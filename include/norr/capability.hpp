#pragma once

#include <cstdint>
#include <expected>

namespace norr {
struct ProtocolVersion {
  std::uint8_t major{1};
  std::uint8_t minor{0};
};

enum class Capability : std::uint32_t {
  ipv6 = 1U << 0U,
  udp_batching = 1U << 1U,
  gso_gro = 1U << 2U,
  fec = 1U << 3U,
  health_telemetry = 1U << 4U,
};

struct CapabilityOffer {
  ProtocolVersion version;
  std::uint32_t supported{};
  std::uint32_t required{};
};

enum class NegotiationError { major_version_mismatch, required_capability_missing };

struct NegotiatedCapabilities {
  ProtocolVersion version;
  std::uint32_t enabled{};
};

[[nodiscard]] constexpr std::uint32_t capability_mask(Capability capability) noexcept {
  return static_cast<std::uint32_t>(capability);
}

[[nodiscard]] std::expected<NegotiatedCapabilities, NegotiationError> negotiate_capabilities(
    const CapabilityOffer& local, const CapabilityOffer& peer) noexcept;

}
