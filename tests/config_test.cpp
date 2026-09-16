#include "check.hpp"
#include <string>
#include <string_view>

#include "norr/config.hpp"

namespace {

constexpr std::string_view kValid = R"(# Example configuration
[node]
role = "server"
listen_port = 51880

[identity]
key_file = "/etc/norr/node.key"

[network]
ipv4 = true
ipv6 = true
mtu = "auto"

[transport]
mode = "auto"

[qos]
enabled = true
rate_bytes = 12500000
burst_bytes = 65536

[fec]
mode = "moderate"

[observability]
metrics = true
listen = "127.0.0.1:9101"
)";

constexpr std::string_view kMinimal = R"(
[node]
listen_port = 1194
[identity]
key_file = "k"
)";

norr::ConfigError error_of(std::string_view text) {
  const auto parsed = norr::parse_config(text);
  NORR_CHECK(!parsed.has_value());
  return parsed.error().error;
}

}  // namespace

int main() {
  const auto valid = norr::parse_config(kValid);
  NORR_CHECK(valid.has_value());
  NORR_CHECK(valid->role == norr::NodeRole::server);
  NORR_CHECK(valid->listen_port == 51880);
  NORR_CHECK(valid->identity_key_file == "/etc/norr/node.key");
  NORR_CHECK(valid->network.ipv4 && valid->network.ipv6);
  NORR_CHECK(valid->network.mtu == norr::kAutomaticMtu);
  NORR_CHECK(valid->transport == norr::TransportMode::automatic);
  NORR_CHECK(valid->qos_enabled);
  NORR_CHECK(valid->fec == norr::FecMode::moderate);
  NORR_CHECK(valid->metrics_enabled);
  NORR_CHECK(valid->qos_rate_bytes == 12'500'000);
  NORR_CHECK(valid->qos_burst_bytes == 65'536);
  NORR_CHECK(valid->metrics_listen == "127.0.0.1:9101");

  const auto minimal = norr::parse_config(kMinimal);
  NORR_CHECK(minimal.has_value());
  NORR_CHECK(minimal->listen_port == 1194);
  NORR_CHECK(minimal->network.mtu == norr::kAutomaticMtu);

  // Defaults must match what the datapath implements, so a configuration that
  // says nothing starts. A default of "on" for a feature the runtime refuses
  // would make every minimal config fail to start.
  NORR_CHECK(!minimal->qos_enabled);
  NORR_CHECK(minimal->fec == norr::FecMode::off);
  NORR_CHECK(!minimal->metrics_enabled);
  NORR_CHECK(minimal->transport == norr::TransportMode::automatic);

  // Required values.
  NORR_CHECK(error_of("[identity]\nkey_file = \"k\"\n") == norr::ConfigError::missing_required);
  NORR_CHECK(error_of("[node]\nlisten_port = 1\n") == norr::ConfigError::missing_required);

  // Ports.
  NORR_CHECK(error_of("[node]\nlisten_port = 0\n[identity]\nkey_file = \"k\"\n") ==
         norr::ConfigError::value_out_of_range);
  NORR_CHECK(error_of("[node]\nlisten_port = 65536\n[identity]\nkey_file = \"k\"\n") ==
         norr::ConfigError::value_out_of_range);
  NORR_CHECK(error_of("[node]\nlisten_port = http\n[identity]\nkey_file = \"k\"\n") ==
         norr::ConfigError::invalid_value);

  // MTU bounds; "auto" is the only accepted non-numeric spelling.
  NORR_CHECK(error_of("[node]\nlisten_port = 1\n[identity]\nkey_file = \"k\"\n[network]\nmtu = 100\n") ==
         norr::ConfigError::invalid_mtu);
  NORR_CHECK(error_of("[node]\nlisten_port = 1\n[identity]\nkey_file = \"k\"\n[network]\nmtu = 99999\n") ==
         norr::ConfigError::invalid_mtu);
  const auto explicit_mtu =
      norr::parse_config("[node]\nlisten_port = 1\n[identity]\nkey_file = \"k\"\n[network]\nmtu = 1420\n");
  NORR_CHECK(explicit_mtu.has_value() && explicit_mtu->network.mtu == 1420);

  // The floor must match what the TUN device will actually accept. A value
  // between the old 576 bound and the real 1280 minimum parsed cleanly and
  // then failed at startup, which told the operator far too late.
  NORR_CHECK(error_of("[node]\nlisten_port = 1\n[identity]\nkey_file = \"k\"\n[network]\nmtu = 900\n") ==
         norr::ConfigError::invalid_mtu);
  const auto floor_mtu =
      norr::parse_config("[node]\nlisten_port = 1\n[identity]\nkey_file = \"k\"\n[network]\nmtu = 1280\n");
  NORR_CHECK(floor_mtu.has_value() && floor_mtu->network.mtu == 1280);

  // Structural errors.
  NORR_CHECK(error_of("[nope]\n") == norr::ConfigError::unknown_section);
  NORR_CHECK(error_of("[node]\nbogus = 1\n") == norr::ConfigError::unknown_key);
  NORR_CHECK(error_of("[node]\nlisten_port = 1\nlisten_port = 2\n") == norr::ConfigError::duplicate_key);
  NORR_CHECK(error_of("listen_port = 1\n") == norr::ConfigError::syntax_error);
  NORR_CHECK(error_of("[node\n") == norr::ConfigError::syntax_error);
  NORR_CHECK(error_of("[node]\nlisten_port\n") == norr::ConfigError::syntax_error);

  // QoS and metrics must be fully specified or fully absent: an enabled
  // feature with no parameter would start and then do nothing.
  {
    constexpr std::string_view kPrologue =
        "[node]\nlisten_port = 1\n[identity]\nkey_file = \"k\"\n";
    const auto option_error = [&](std::string_view body) {
      const std::string text = std::string{kPrologue} + std::string{body};
      return error_of(text);
    };

    NORR_CHECK(option_error("[qos]\nenabled = true\n") == norr::ConfigError::missing_required);
    NORR_CHECK(option_error("[qos]\nenabled = false\nrate_bytes = 1000\n") ==
               norr::ConfigError::incompatible_options);
    NORR_CHECK(option_error("[qos]\nenabled = true\nrate_bytes = 0\n") ==
               norr::ConfigError::value_out_of_range);

    NORR_CHECK(option_error("[observability]\nmetrics = true\n") ==
               norr::ConfigError::missing_required);
    NORR_CHECK(option_error("[observability]\nmetrics = false\nlisten = \"127.0.0.1:9100\"\n") ==
               norr::ConfigError::incompatible_options);
    NORR_CHECK(option_error("[observability]\nmetrics = true\nlisten = \"nohost\"\n") ==
               norr::ConfigError::invalid_value);

    // A burst that is not given is derived rather than left at zero, which
    // would stall the pacer.
    const auto derived = norr::parse_config(std::string{kPrologue} +
                                            "[qos]\nenabled = true\nrate_bytes = 1000000\n");
    NORR_CHECK(derived.has_value());
    NORR_CHECK(derived->qos_burst_bytes > 0);
  }

  // Peers.
  {
    constexpr std::string_view kPeers = R"(
[node]
listen_port = 51820
tun = "norr9"
[identity]
key_file = "k"

[[peer]]
name = "edge-1"
public_key = "AA00000000000000000000000000000000000000000000000000000000000011"
endpoint = "198.51.100.10:51820"
allowed_ips = "10.80.0.2/32, fd00::2/128"

[[peer]]
name = "edge-2"
public_key = "bb00000000000000000000000000000000000000000000000000000000000022"
allowed_ips = "10.80.0.3/32"
)";
    const auto parsed = norr::parse_config(kPeers);
    NORR_CHECK(parsed.has_value());
    NORR_CHECK(parsed->tun_name == "norr9");
    NORR_CHECK(parsed->peers.size() == 2);
    NORR_CHECK(parsed->peers[0].name == "edge-1");
    // Keys are normalised to lowercase, so the same key written two ways is
    // still recognised as a duplicate.
    NORR_CHECK(parsed->peers[0].public_key ==
               "aa00000000000000000000000000000000000000000000000000000000000011");
    NORR_CHECK(parsed->peers[0].endpoint == "198.51.100.10:51820");
    NORR_CHECK(parsed->peers[0].allowed_ips.size() == 2);
    NORR_CHECK(parsed->peers[0].allowed_ips[1] == "fd00::2/128");
    // A peer that only listens needs no endpoint.
    NORR_CHECK(parsed->peers[1].endpoint.empty());
  }

  constexpr std::string_view kPeerPrologue =
      "[node]\nlisten_port = 1\n[identity]\nkey_file = \"k\"\n";
  // The combined text is held in a named local: `error_of` takes a view, so
  // passing a temporary string would leave it dangling.
  const auto peer_error = [&](std::string_view body) {
    const std::string text = std::string{kPeerPrologue} + std::string{body};
    return error_of(text);
  };

  // A key that is not 64 hex characters is a configuration error, not a
  // handshake that silently never completes.
  NORR_CHECK(peer_error("[[peer]]\npublic_key = \"abcd\"\nallowed_ips = \"10.0.0.1/32\"\n") ==
             norr::ConfigError::invalid_value);
  NORR_CHECK(peer_error("[[peer]]\npublic_key = \"" + std::string(63, 'a') +
                        "z\"\nallowed_ips = \"10.0.0.1/32\"\n") ==
             norr::ConfigError::invalid_value);

  // Both fields are required: a peer without a key cannot be authenticated,
  // and one without prefixes can never be routed to.
  NORR_CHECK(peer_error("[[peer]]\nallowed_ips = \"10.0.0.1/32\"\n") ==
             norr::ConfigError::missing_required);
  NORR_CHECK(peer_error("[[peer]]\npublic_key = \"" + std::string(64, 'a') + "\"\n") ==
             norr::ConfigError::missing_required);

  // An allowed_ips entry must be a prefix, not a bare address.
  NORR_CHECK(peer_error("[[peer]]\npublic_key = \"" + std::string(64, 'a') +
                        "\"\nallowed_ips = \"10.0.0.1\"\n") == norr::ConfigError::invalid_value);

  // An endpoint must carry a port.
  NORR_CHECK(peer_error("[[peer]]\npublic_key = \"" + std::string(64, 'a') +
                        "\"\nendpoint = \"198.51.100.1\"\nallowed_ips = \"10.0.0.1/32\"\n") ==
             norr::ConfigError::invalid_value);

  // Two peers sharing a static key would make the key id ambiguous, so the
  // second could never be addressed.
  NORR_CHECK(peer_error("[[peer]]\npublic_key = \"" + std::string(64, 'a') +
                        "\"\nallowed_ips = \"10.0.0.1/32\"\n[[peer]]\npublic_key = \"" +
                        std::string(64, 'A') + "\"\nallowed_ips = \"10.0.0.2/32\"\n") ==
             norr::ConfigError::duplicate_key);

  // Each peer block is its own namespace, so two peers may both set the same
  // key name, but one peer setting it twice is still a duplicate.
  NORR_CHECK(peer_error("[[peer]]\npublic_key = \"" + std::string(64, 'a') +
                        "\"\npublic_key = \"" + std::string(64, 'b') +
                        "\"\nallowed_ips = \"10.0.0.1/32\"\n") ==
             norr::ConfigError::duplicate_key);

  NORR_CHECK(peer_error("[[bogus]]\n") == norr::ConfigError::unknown_section);
  NORR_CHECK(peer_error("[[peer]]\nbogus = 1\n") == norr::ConfigError::unknown_key);

  // Both address families disabled leaves no way to carry traffic.
  NORR_CHECK(error_of("[node]\nlisten_port = 1\n[identity]\nkey_file = \"k\"\n"
                  "[network]\nipv4 = false\nipv6 = false\n") ==
         norr::ConfigError::incompatible_options);

  // Enumerations.
  NORR_CHECK(error_of("[node]\nrole = \"peer\"\nlisten_port = 1\n[identity]\nkey_file = \"k\"\n") ==
         norr::ConfigError::invalid_value);
  const auto tcp =
      norr::parse_config("[node]\nlisten_port = 1\n[identity]\nkey_file = \"k\"\n"
                         "[transport]\nmode = \"tcp-tls\"\n");
  NORR_CHECK(tcp.has_value() && tcp->transport == norr::TransportMode::tcp_tls);

  // Diagnostics carry the offending line.
  const auto diagnostic = norr::parse_config("[node]\nlisten_port = 1\nbogus = 2\n");
  NORR_CHECK(!diagnostic.has_value());
  NORR_CHECK(diagnostic.error().line == 3);

  // A missing file is reported, not treated as an empty configuration.
  const auto missing = norr::load_config_file("/nonexistent/norr/does-not-exist.toml");
  NORR_CHECK(!missing.has_value() && missing.error().error == norr::ConfigError::unreadable_file);
}
