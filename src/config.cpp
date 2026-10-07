// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#include "norr/config.hpp"

#include "norr/endpoint.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <fstream>
#include <ios>
#include <optional>
#include <sstream>
#include <unordered_set>

namespace norr {
namespace {
[[nodiscard]] bool carries_datagrams(TransportMode mode) noexcept {
  switch (mode) {
    case TransportMode::automatic:
    case TransportMode::udp:
    case TransportMode::icmp:
    case TransportMode::ipip:
    case TransportMode::gre:
    case TransportMode::esp:
    case TransportMode::ah:
    case TransportMode::ospf: return true;
    case TransportMode::dns: return true;
    case TransportMode::quic:
    case TransportMode::tcp_tls: break;
  }
  return false;
}
}

namespace {
using Diagnostic = ConfigDiagnostic;

[[nodiscard]] std::string_view trim(std::string_view text) noexcept {
  const auto is_space = [](char c) noexcept {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
  };
  while (!text.empty() && is_space(text.front())) text.remove_prefix(1);
  while (!text.empty() && is_space(text.back())) text.remove_suffix(1);
  return text;
}

[[nodiscard]] std::expected<std::string_view, ConfigError> unquote(std::string_view value) noexcept {
  if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
    return value.substr(1, value.size() - 2);
  }
  if (value.find('"') != std::string_view::npos) return std::unexpected(ConfigError::syntax_error);
  return value;
}

[[nodiscard]] std::expected<bool, ConfigError> parse_bool(std::string_view value) noexcept {
  if (value == "true") return true;
  if (value == "false") return false;
  return std::unexpected(ConfigError::invalid_value);
}

[[nodiscard]] std::expected<std::uint64_t, ConfigError> parse_uint(std::string_view value) noexcept {
  if (value.empty()) return std::unexpected(ConfigError::invalid_value);
  std::uint64_t parsed{};
  const auto* const begin = value.data();
  const auto* const end = begin + value.size();
  const auto result = std::from_chars(begin, end, parsed);
  if (result.ec != std::errc{} || result.ptr != end) {
    return std::unexpected(ConfigError::invalid_value);
  }
  return parsed;
}

[[nodiscard]] std::expected<std::int32_t, ConfigError> parse_int32(std::string_view value) noexcept {
  if (value.empty()) return std::unexpected(ConfigError::invalid_value);
  std::int32_t parsed{};
  const auto* const begin = value.data();
  const auto* const end = begin + value.size();
  const auto result = std::from_chars(begin, end, parsed);
  if (result.ec != std::errc{} || result.ptr != end) {
    return std::unexpected(ConfigError::invalid_value);
  }
  return parsed;
}

[[nodiscard]] std::expected<std::uint16_t, ConfigError> parse_port(std::string_view value) noexcept {
  const auto parsed = parse_uint(value);
  if (!parsed) return std::unexpected(parsed.error());

  if (*parsed == 0 || *parsed > 65'535) return std::unexpected(ConfigError::value_out_of_range);
  return static_cast<std::uint16_t>(*parsed);
}

[[nodiscard]] bool is_hex_key(std::string_view value) noexcept {
  if (value.size() != 64) return false;
  return std::all_of(value.begin(), value.end(), [](char c) noexcept {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
  });
}

[[nodiscard]] std::vector<std::string_view> split_list(std::string_view value) {
  std::vector<std::string_view> parts;
  while (!value.empty()) {
    const auto comma = value.find(',');
    parts.push_back(trim(value.substr(0, comma)));
    if (comma == std::string_view::npos) break;
    value.remove_prefix(comma + 1);
  }
  return parts;
}

[[nodiscard]] std::expected<std::uint16_t, ConfigError> parse_mtu(std::string_view value) noexcept {
  if (value == "auto") return kAutomaticMtu;
  const auto parsed = parse_uint(value);
  if (!parsed) return std::unexpected(ConfigError::invalid_mtu);
  if (*parsed < kMinimumMtu || *parsed > kMaximumMtu) {
    return std::unexpected(ConfigError::invalid_mtu);
  }
  return static_cast<std::uint16_t>(*parsed);
}
}

[[nodiscard]] std::optional<std::string> deprecated_note(std::string_view qualified) {
  struct Alias {
    std::string_view key;
    std::string_view note;
  };
  static constexpr std::array<Alias, 0> kDeprecated{};
  for (const auto& alias : kDeprecated) {
    if (qualified == alias.key) return std::string{alias.note};
  }
  return std::nullopt;
}

std::expected<Config, ConfigDiagnostic> parse_config(std::string_view text) {
  Config config{};
  std::string section;
  std::unordered_set<std::string> seen;
  std::unordered_set<std::string> present;

  std::size_t line_number = 0;
  std::size_t offset = 0;
  while (offset <= text.size()) {
    const auto newline = text.find('\n', offset);
    const auto raw = text.substr(offset, newline == std::string_view::npos
                                             ? std::string_view::npos
                                             : newline - offset);
    offset = newline == std::string_view::npos ? text.size() + 1 : newline + 1;
    ++line_number;

    auto line = trim(raw);
    if (const auto comment = line.find('#'); comment != std::string_view::npos) {
      line = trim(line.substr(0, comment));
    }
    if (line.empty()) continue;

    if (line.front() == '[') {
      if (line.size() > 4 && line.starts_with("[[") && line.ends_with("]]")) {
        const auto name = trim(line.substr(2, line.size() - 4));
        if (name == "peer") {
          config.peers.emplace_back();
        } else if (name == "forward") {
          config.forwards.emplace_back();
        } else {
          return std::unexpected(
              Diagnostic{ConfigError::unknown_section, line_number, std::string{name}});
        }
        section = std::string{name};
        continue;
      }
      if (line.back() != ']' || line.size() <= 2) {
        return std::unexpected(Diagnostic{ConfigError::syntax_error, line_number,
                                          std::string{line}});
      }
      section = std::string{trim(line.substr(1, line.size() - 2))};
      static const std::unordered_set<std::string> known{
          "node", "identity", "network",       "transport",
          "qos",  "fec",      "observability", "congestion"};
      if (!known.contains(section)) {
        return std::unexpected(Diagnostic{ConfigError::unknown_section, line_number, section});
      }
      continue;
    }

    const auto equals = line.find('=');
    if (equals == std::string_view::npos || section.empty()) {
      return std::unexpected(Diagnostic{ConfigError::syntax_error, line_number, std::string{line}});
    }
    const auto key = trim(line.substr(0, equals));
    const auto unquoted = unquote(trim(line.substr(equals + 1)));
    if (!unquoted) {
      return std::unexpected(Diagnostic{unquoted.error(), line_number, std::string{key}});
    }
    const auto value = *unquoted;
    if (key.empty()) {
      return std::unexpected(Diagnostic{ConfigError::syntax_error, line_number, std::string{line}});
    }

    const auto qualified = section + "." + std::string{key};
    const auto scoped = section == "peer"      ? std::to_string(config.peers.size()) + "." + qualified
                        : section == "forward" ? std::to_string(config.forwards.size()) + "." + qualified
                                               : qualified;
    if (!seen.insert(scoped).second) {
      return std::unexpected(Diagnostic{ConfigError::duplicate_key, line_number, qualified});
    }
    present.insert(qualified);

    const auto fail = [&](ConfigError error) {
      return std::unexpected(Diagnostic{error, line_number, qualified});
    };

    if (qualified == "node.role") {
      if (value == "server") config.role = NodeRole::server;
      else if (value == "client") config.role = NodeRole::client;
      else return fail(ConfigError::invalid_value);
    } else if (qualified == "node.listen_port") {
      const auto port = parse_port(value);
      if (!port) return fail(port.error());
      config.listen_port = *port;
    } else if (qualified == "node.user") {
      if (value.empty() || value.size() > 32) return fail(ConfigError::invalid_value);
      config.user = std::string{value};
    } else if (qualified == "node.tun") {
      if (value.empty() || value.size() > 15) return fail(ConfigError::invalid_value);
      config.tun_name = std::string{value};
    } else if (section == "forward") {
      auto& entry = config.forwards.back();
      if (key == "name") {
        if (value.empty()) return fail(ConfigError::invalid_value);
        entry.name = std::string{value};
      } else if (key == "listen_port") {
        const auto port = parse_port(value);
        if (!port) return fail(port.error());
        entry.port = *port;
      } else if (key == "target") {
        if (!parse_endpoint(value)) return fail(ConfigError::invalid_value);
        entry.target = std::string{value};
      } else if (key == "preserve_source") {
        const auto flag = parse_bool(value);
        if (!flag) return fail(flag.error());
        entry.preserve_source = *flag;
      } else if (key == "protocol") {
        if (value == "tcp") {
          entry.tcp = true;
          entry.udp = false;
        } else if (value == "udp") {
          entry.tcp = false;
          entry.udp = true;
        } else if (value == "both") {
          entry.tcp = true;
          entry.udp = true;
        } else {
          return fail(ConfigError::invalid_value);
        }
      } else {
        return fail(ConfigError::unknown_key);
      }
    } else if (section == "peer") {
      auto& entry = config.peers.back();
      if (key == "name") {
        if (value.empty()) return fail(ConfigError::invalid_value);
        entry.name = std::string{value};
      } else if (key == "public_key") {
        if (!is_hex_key(value)) return fail(ConfigError::invalid_value);
        entry.public_key = std::string{value};
      } else if (key == "preshared_key") {
        if (!is_hex_key(value)) return fail(ConfigError::invalid_value);
        entry.preshared_key = std::string{value};
      } else if (key == "endpoint") {
        if (value.empty() || value.find(':') == std::string_view::npos) {
          return fail(ConfigError::invalid_value);
        }
        entry.endpoint = std::string{value};
      } else if (key == "routes") {
        const auto flag = parse_bool(value);
        if (!flag) return fail(flag.error());
        entry.routes = *flag;
      } else if (key == "allowed_ips") {
        for (const auto part : split_list(value)) {
          if (part.empty() || part.find('/') == std::string_view::npos) {
            return fail(ConfigError::invalid_value);
          }
          entry.allowed_ips.emplace_back(part);
        }
        if (entry.allowed_ips.empty()) return fail(ConfigError::invalid_value);
      } else {
        return fail(ConfigError::unknown_key);
      }
    } else if (qualified == "identity.key_file") {
      if (value.empty()) return fail(ConfigError::invalid_value);
      config.identity_key_file = std::string{value};
    } else if (qualified == "network.ipv4" || qualified == "network.ipv6") {
      const auto flag = parse_bool(value);
      if (!flag) return fail(flag.error());
      (key == "ipv4" ? config.network.ipv4 : config.network.ipv6) = *flag;
    } else if (qualified == "network.address") {
      for (const auto part : split_list(value)) {
        if (part.empty() || part.find('/') == std::string_view::npos) {
          return fail(ConfigError::invalid_value);
        }
        config.network.addresses.emplace_back(part);
      }
      if (config.network.addresses.empty()) return fail(ConfigError::invalid_value);
    } else if (qualified == "network.fwmark") {
      const auto mark = parse_uint(value);
      if (!mark) return fail(mark.error());
      if (*mark == 0 || *mark > 0xFFFF'FFFFULL) return fail(ConfigError::value_out_of_range);
      config.network.fwmark = static_cast<std::uint32_t>(*mark);
    } else if (qualified == "network.return_via_tunnel") {
      const auto flag = parse_bool(value);
      if (!flag) return fail(flag.error());
      config.network.return_via_tunnel = *flag;
    } else if (qualified == "network.offload") {
      const auto flag = parse_bool(value);
      if (!flag) return fail(flag.error());
      config.network.offload = *flag;
    } else if (qualified == "network.forward") {
      const auto flag = parse_bool(value);
      if (!flag) return fail(flag.error());
      config.network.forward = *flag;
    } else if (qualified == "network.mtu") {
      const auto mtu = parse_mtu(value);
      if (!mtu) return fail(mtu.error());
      config.network.mtu = *mtu;
    } else if (qualified == "transport.mode") {
      if (value == "auto") config.transport = TransportMode::automatic;
      else if (value == "udp") config.transport = TransportMode::udp;
      else if (value == "quic") config.transport = TransportMode::quic;
      else if (value == "tcp-tls") config.transport = TransportMode::tcp_tls;
      else if (value == "icmp") config.transport = TransportMode::icmp;
      else if (value == "ipip") config.transport = TransportMode::ipip;
      else if (value == "gre") config.transport = TransportMode::gre;
      else if (value == "esp") config.transport = TransportMode::esp;
      else if (value == "ah") config.transport = TransportMode::ah;
      else if (value == "ospf") config.transport = TransportMode::ospf;
      else if (value == "dns") config.transport = TransportMode::dns;
      else return fail(ConfigError::invalid_value);
    } else if (qualified == "qos.enabled") {
      const auto flag = parse_bool(value);
      if (!flag) return fail(flag.error());
      config.qos_enabled = *flag;
    } else if (qualified == "qos.rate_bytes") {
      const auto rate = parse_uint(value);
      if (!rate) return fail(rate.error());
      if (*rate == 0) return fail(ConfigError::value_out_of_range);
      config.qos_rate_bytes = *rate;
    } else if (qualified == "qos.burst_bytes") {
      const auto burst = parse_uint(value);
      if (!burst) return fail(burst.error());
      if (*burst == 0) return fail(ConfigError::value_out_of_range);
      config.qos_burst_bytes = *burst;
    } else if (qualified == "congestion.brutal_rate_bytes") {
      const auto rate = parse_uint(value);
      if (!rate) return fail(rate.error());
      if (*rate == 0) return fail(ConfigError::value_out_of_range);
      config.brutal_rate_bytes = *rate;
    } else if (qualified == "transport.connections") {
      const auto count = parse_uint(value);
      if (!count) return fail(count.error());
      if (*count < 1 || *count > 8) return fail(ConfigError::value_out_of_range);
      config.tcp_connections = static_cast<std::uint8_t>(*count);
    } else if (qualified == "transport.profile") {
      if (value == "standard") config.profile = TrafficProfile::standard;
      else if (value == "quic") config.profile = TrafficProfile::quic;
      else if (value == "dns") config.profile = TrafficProfile::dns;
      else return fail(ConfigError::invalid_value);
    } else if (qualified == "transport.obfuscation") {
      if (value == "off") config.obfuscation.mode = ObfuscationMode::off;
      else if (value == "header-mask") config.obfuscation.mode = ObfuscationMode::header_mask;
      else if (value == "full") config.obfuscation.mode = ObfuscationMode::full;
      else return fail(ConfigError::invalid_value);
    } else if (qualified == "transport.junk") {
      const auto flag = parse_bool(value);
      if (!flag) return fail(flag.error());
      config.obfuscation.junk_padding = *flag;
    } else if (qualified == "transport.uniform_length") {
      const auto flag = parse_bool(value);
      if (!flag) return fail(flag.error());
      config.obfuscation.uniform_length = *flag;
    } else if (qualified == "transport.junk_max") {
      const auto max = parse_uint(value);
      if (!max) return fail(max.error());
      if (*max == 0 || *max > kMaximumJunkLength) return fail(ConfigError::value_out_of_range);
      config.obfuscation.junk_max = static_cast<std::uint8_t>(*max);
    } else if (qualified == "transport.priming") {
      const auto flag = parse_bool(value);
      if (!flag) return fail(flag.error());
      config.obfuscation.priming = *flag;
    } else if (qualified == "node.log_level") {
      if (value != "debug" && value != "info" && value != "warn" && value != "error" &&
          value != "off") {
        return fail(ConfigError::invalid_value);
      }
      config.log_level = value;
    } else if (qualified == "node.tuning") {
      if (value != "off" && value != "balanced" && value != "throughput" && value != "saver") {
        return fail(ConfigError::invalid_value);
      }
      config.tuning_profile = value;
    } else if (qualified == "transport.icmp_echo_request_only") {
      const auto flag = parse_bool(value);
      if (!flag) return fail(flag.error());
      config.icmp_echo_request_only = *flag;
    } else if (qualified == "transport.icmp_silence_kernel") {
      const auto flag = parse_bool(value);
      if (!flag) return fail(flag.error());
      config.icmp_silence_kernel = *flag;
    } else if (qualified == "transport.dns_domain") {
      config.dns_domain = std::string{value};
    } else if (qualified == "transport.rekey_interval") {
      const auto parsed = parse_int32(value);
      if (!parsed) return fail(parsed.error());
      config.rekey_interval_seconds = *parsed;
    } else if (qualified == "transport.rotate_interval") {
      const auto parsed = parse_int32(value);
      if (!parsed) return fail(parsed.error());
      config.rotate_interval_seconds = *parsed;
    } else if (qualified == "transport.spoof") {
      const auto flag = parse_bool(value);
      if (!flag) return fail(flag.error());
      config.spoof_enabled = *flag;
    } else if (qualified == "transport.spoof_sources") {
      config.spoof_sources.clear();
      for (const auto part : split_list(value)) {
        const auto parsed = parse_address(part);
        if (!parsed || parsed->family() != AddressFamily::ipv4) {
          return fail(ConfigError::invalid_value);
        }
        const auto octets = parsed->bytes();
        const auto be = (static_cast<std::uint32_t>(octets[0]) << 24U) |
                        (static_cast<std::uint32_t>(octets[1]) << 16U) |
                        (static_cast<std::uint32_t>(octets[2]) << 8U) |
                        static_cast<std::uint32_t>(octets[3]);
        if (be != 0) config.spoof_sources.push_back(be);
      }
      if (config.spoof_sources.empty()) return fail(ConfigError::invalid_value);
    } else if (qualified == "transport.camouflage") {
      if (value == "off") config.camouflage = CamouflageMode::off;
      else if (value == "fake-tls") config.camouflage = CamouflageMode::fake_tls;
      else if (value == "pop3") config.camouflage = CamouflageMode::pop3;
      else if (value == "smtp") config.camouflage = CamouflageMode::smtp;
      else if (value == "xmpp") config.camouflage = CamouflageMode::xmpp;
      else if (value == "ssh") config.camouflage = CamouflageMode::ssh;
      else if (value == "raw") config.camouflage = CamouflageMode::raw;
      else return fail(ConfigError::invalid_value);
    } else if (qualified == "transport.sni") {
      if (value.empty() || value.size() > 2048) return fail(ConfigError::invalid_value);
      config.camouflage_sni_pool.clear();
      std::string_view rest{value};
      while (!rest.empty()) {
        auto comma = rest.find(',');
        auto item = rest.substr(0, comma);
        while (!item.empty() && (item.front() == ' ' || item.front() == '\t')) item.remove_prefix(1);
        while (!item.empty() && (item.back() == ' ' || item.back() == '\t')) item.remove_suffix(1);
        if (!item.empty() && item.size() <= 253) config.camouflage_sni_pool.emplace_back(item);
        if (comma == std::string_view::npos) break;
        rest.remove_prefix(comma + 1);
      }
      if (config.camouflage_sni_pool.empty()) return fail(ConfigError::invalid_value);
      config.camouflage_sni = config.camouflage_sni_pool.front();
    } else if (qualified == "transport.reality_private_key") {
      if (!is_hex_key(value)) return fail(ConfigError::invalid_value);
      config.reality_private_key = std::string{value};
    } else if (qualified == "transport.reality_public_key") {
      if (!is_hex_key(value)) return fail(ConfigError::invalid_value);
      config.reality_public_key = std::string{value};
    } else if (qualified == "transport.reality_short_id") {
      if (value.size() != 16) return fail(ConfigError::invalid_value);
      config.reality_short_id = std::string{value};
    } else if (qualified == "transport.reality_cover") {
      if (value.empty() || value.size() > 300) return fail(ConfigError::invalid_value);
      config.reality_cover = std::string{value};
    } else if (qualified == "fec.mode") {
      if (value == "off") config.fec = FecMode::off;
      else if (value == "light") config.fec = FecMode::light;
      else if (value == "moderate") config.fec = FecMode::moderate;
      else if (value == "aggressive") config.fec = FecMode::aggressive;
      else if (value == "auto") config.fec = FecMode::automatic;
      else return fail(ConfigError::invalid_value);
    } else if (qualified == "observability.metrics") {
      const auto flag = parse_bool(value);
      if (!flag) return fail(flag.error());
      config.metrics_enabled = *flag;
    } else if (qualified == "observability.listen") {
      if (value.empty() || value.find(':') == std::string_view::npos) {
        return fail(ConfigError::invalid_value);
      }
      config.metrics_listen = std::string{value};
    } else if (auto note = deprecated_note(qualified)) {
      config.notes.push_back(std::move(*note));
    } else {
      return fail(ConfigError::unknown_key);
    }
  }

  if (!present.contains("node.listen_port")) {
    return std::unexpected(Diagnostic{ConfigError::missing_required, 0, "node.listen_port"});
  }
  if (!present.contains("identity.key_file")) {
    return std::unexpected(Diagnostic{ConfigError::missing_required, 0, "identity.key_file"});
  }
  std::unordered_set<std::string> peer_keys;
  for (std::size_t index = 0; index < config.peers.size(); ++index) {
    auto& peer = config.peers[index];
    const auto label = peer.name.empty() ? "peer[" + std::to_string(index) + "]" : peer.name;

    if (peer.public_key.empty()) {
      return std::unexpected(
          Diagnostic{ConfigError::missing_required, 0, label + ".public_key"});
    }
    if (peer.allowed_ips.empty()) {
      return std::unexpected(
          Diagnostic{ConfigError::missing_required, 0, label + ".allowed_ips"});
    }
    std::string lowered = peer.public_key;
    std::transform(lowered.begin(), lowered.end(), lowered.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    peer.public_key = lowered;
    if (!peer_keys.insert(lowered).second) {
      return std::unexpected(
          Diagnostic{ConfigError::duplicate_key, 0, label + ".public_key"});
    }
  }

  std::unordered_set<std::string> forwarded;
  for (std::size_t index = 0; index < config.forwards.size(); ++index) {
    const auto& forward = config.forwards[index];
    const auto label = forward.name.empty() ? "forward[" + std::to_string(index) + "]" : forward.name;
    if (forward.port == 0) {
      return std::unexpected(Diagnostic{ConfigError::missing_required, 0, label + ".listen_port"});
    }
    if (forward.target.empty()) {
      return std::unexpected(Diagnostic{ConfigError::missing_required, 0, label + ".target"});
    }
    for (const auto* protocol : {"tcp", "udp"}) {
      const bool used = std::string_view{protocol} == "tcp" ? forward.tcp : forward.udp;
      if (!used) continue;
      if (!forwarded.insert(std::string{protocol} + "/" + std::to_string(forward.port)).second) {
        return std::unexpected(Diagnostic{ConfigError::duplicate_key, 0, label + ".listen_port"});
      }
    }
    if (forward.port == config.listen_port && forward.udp) {
      return std::unexpected(
          Diagnostic{ConfigError::incompatible_options, 0, label + " uses the tunnel port"});
    }
  }

  if (config.qos_enabled && config.qos_rate_bytes == 0) {
    return std::unexpected(Diagnostic{ConfigError::missing_required, 0, "qos.rate_bytes"});
  }
  if (!config.qos_enabled && (config.qos_rate_bytes != 0 || config.qos_burst_bytes != 0)) {
    return std::unexpected(
        Diagnostic{ConfigError::incompatible_options, 0, "qos.rate_bytes without qos.enabled"});
  }
  if (config.qos_enabled && config.qos_burst_bytes == 0) {
    config.qos_burst_bytes = config.qos_rate_bytes / 10 + kMaximumMtu;
  }

  if (config.metrics_enabled && config.metrics_listen.empty()) {
    return std::unexpected(Diagnostic{ConfigError::missing_required, 0, "observability.listen"});
  }
  if (!config.metrics_enabled && !config.metrics_listen.empty()) {
    return std::unexpected(Diagnostic{ConfigError::incompatible_options, 0,
                                      "observability.listen without observability.metrics"});
  }

  if (config.spoof_enabled && config.spoof_sources.empty()) {
    return std::unexpected(Diagnostic{ConfigError::missing_required, 0, "transport.spoof_sources"});
  }
  if (!config.spoof_enabled && !config.spoof_sources.empty()) {
    return std::unexpected(Diagnostic{ConfigError::incompatible_options, 0,
                                      "transport.spoof_sources without transport.spoof"});
  }
  if (config.spoof_enabled && config.transport != TransportMode::automatic &&
      config.transport != TransportMode::udp) {
    return std::unexpected(Diagnostic{ConfigError::incompatible_options, 0,
                                      "transport.spoof applies to the udp transport"});
  }

  if (!config.network.ipv4 && !config.network.ipv6) {
    return std::unexpected(Diagnostic{ConfigError::incompatible_options, 0,
                                      "network.ipv4 and network.ipv6 are both disabled"});
  }

  if (config.obfuscation.mode == ObfuscationMode::off &&
      (config.obfuscation.junk_padding || config.obfuscation.priming)) {
    return std::unexpected(Diagnostic{ConfigError::incompatible_options, 0,
                                      "transport.junk/priming require transport.obfuscation"});
  }
  if (config.obfuscation.junk_padding &&
      config.obfuscation.mode != ObfuscationMode::full) {
    return std::unexpected(Diagnostic{ConfigError::incompatible_options, 0,
                                      "transport.junk requires transport.obfuscation = full"});
  }
  const bool tcp_framed_carrier =
      (config.transport == TransportMode::tcp_tls || config.transport == TransportMode::automatic) &&
      (config.camouflage == CamouflageMode::pop3 || config.camouflage == CamouflageMode::smtp ||
       config.camouflage == CamouflageMode::xmpp || config.camouflage == CamouflageMode::ssh ||
       config.camouflage == CamouflageMode::raw);
  if (config.obfuscation.mode != ObfuscationMode::off &&
      !carries_datagrams(config.transport) && !tcp_framed_carrier) {
    return std::unexpected(Diagnostic{
        ConfigError::incompatible_options, 0,
        "transport.obfuscation applies to the datagram transports (udp, icmp, ipip, gre, esp, "
        "ah, ospf) or a framed tcp carrier (camouflage = pop3/smtp/xmpp/ssh/raw)"});
  }

  if (config.camouflage != CamouflageMode::off &&
      config.transport != TransportMode::automatic &&
      config.transport != TransportMode::tcp_tls) {
    return std::unexpected(Diagnostic{ConfigError::incompatible_options, 0,
                                      "transport.camouflage applies to the tcp-tls transport"});
  }

  return config;
}

std::expected<Config, ConfigDiagnostic> load_config_file(const std::string& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) return std::unexpected(Diagnostic{ConfigError::unreadable_file, 0, path});
  std::ostringstream buffer;
  buffer << input.rdbuf();
  if (!input.good() && !input.eof()) {
    return std::unexpected(Diagnostic{ConfigError::unreadable_file, 0, path});
  }
  return parse_config(buffer.str());
}
}
