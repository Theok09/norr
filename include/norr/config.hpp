// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#pragma once

#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <vector>

#include "norr/fec.hpp"
#include "norr/traffic_profile.hpp"

namespace norr {
enum class ConfigError {
  unreadable_file,
  syntax_error,
  unknown_section,
  unknown_key,
  duplicate_key,
  missing_required,
  invalid_value,
  value_out_of_range,
  port_conflict,
  invalid_mtu,
  incompatible_options,
};

[[nodiscard]] constexpr std::string_view config_error_message(ConfigError error) noexcept {
  switch (error) {
    case ConfigError::unreadable_file: return "configuration file cannot be read";
    case ConfigError::syntax_error: return "syntax error";
    case ConfigError::unknown_section: return "unknown section";
    case ConfigError::unknown_key: return "unknown key";
    case ConfigError::duplicate_key: return "duplicate key";
    case ConfigError::missing_required: return "missing required value";
    case ConfigError::invalid_value: return "invalid value";
    case ConfigError::value_out_of_range: return "value out of allowed range";
    case ConfigError::port_conflict: return "listen port conflicts with a peer endpoint";
    case ConfigError::invalid_mtu: return "invalid MTU";
    case ConfigError::incompatible_options: return "incompatible options";
  }
  return "unknown configuration error";
}

struct ConfigDiagnostic {
  ConfigError error{};
  std::size_t line{};
  std::string detail;
};

enum class NodeRole { server, client };
enum class TransportMode { automatic, udp, quic, tcp_tls };

inline constexpr std::uint16_t kMinimumMtu = 1280;
inline constexpr std::uint16_t kMaximumMtu = 9000;
inline constexpr std::uint16_t kAutomaticMtu = 0;

struct NetworkConfig {
  bool ipv4{true};
  bool ipv6{true};
  std::uint16_t mtu{kAutomaticMtu};

  std::vector<std::string> addresses;
};

struct PeerEntry {
  std::string name;
  std::string public_key;
  std::string preshared_key;
  std::string endpoint;
  std::vector<std::string> allowed_ips;
};

struct Config {
  NodeRole role{NodeRole::server};
  std::uint16_t listen_port{};
  std::string identity_key_file;
  NetworkConfig network;
  TransportMode transport{TransportMode::automatic};

  bool qos_enabled{false};
  std::uint64_t qos_rate_bytes{};
  std::uint64_t qos_burst_bytes{};
  FecMode fec{FecMode::off};
  TrafficProfile profile{TrafficProfile::standard};
  bool metrics_enabled{false};
  std::string metrics_listen;
  std::string tun_name{"norr0"};
  std::vector<PeerEntry> peers;
};

[[nodiscard]] std::expected<Config, ConfigDiagnostic> parse_config(std::string_view text);
[[nodiscard]] std::expected<Config, ConfigDiagnostic> load_config_file(const std::string& path);

}
