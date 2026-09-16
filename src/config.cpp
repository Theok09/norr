#include "norr/config.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <fstream>
#include <ios>
#include <sstream>
#include <unordered_set>

namespace norr {
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
        if (name != "peer") {
          return std::unexpected(
              Diagnostic{ConfigError::unknown_section, line_number, std::string{name}});
        }
        config.peers.emplace_back();
        section = "peer";
        continue;
      }
      if (line.back() != ']' || line.size() <= 2) {
        return std::unexpected(Diagnostic{ConfigError::syntax_error, line_number,
                                          std::string{line}});
      }
      section = std::string{trim(line.substr(1, line.size() - 2))};
      static const std::unordered_set<std::string> known{
          "node", "identity", "network", "transport", "qos", "fec", "observability"};
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
    const auto scoped = section == "peer"
                            ? std::to_string(config.peers.size()) + "." + qualified
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
    } else if (qualified == "node.tun") {
      if (value.empty() || value.size() > 15) return fail(ConfigError::invalid_value);
      config.tun_name = std::string{value};
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
    } else if (qualified == "network.mtu") {
      const auto mtu = parse_mtu(value);
      if (!mtu) return fail(mtu.error());
      config.network.mtu = *mtu;
    } else if (qualified == "transport.mode") {
      if (value == "auto") config.transport = TransportMode::automatic;
      else if (value == "udp") config.transport = TransportMode::udp;
      else if (value == "quic") config.transport = TransportMode::quic;
      else if (value == "tcp-tls") config.transport = TransportMode::tcp_tls;
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
    } else if (qualified == "fec.mode") {
      if (value == "off") config.fec = FecMode::off;
      else if (value == "light") config.fec = FecMode::light;
      else if (value == "moderate") config.fec = FecMode::moderate;
      else if (value == "aggressive") config.fec = FecMode::aggressive;
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

  if (!config.network.ipv4 && !config.network.ipv6) {
    return std::unexpected(Diagnostic{ConfigError::incompatible_options, 0,
                                      "network.ipv4 and network.ipv6 are both disabled"});
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
