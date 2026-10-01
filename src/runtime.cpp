// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#include "norr/runtime.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <optional>
#include <vector>

#if defined(__linux__)
#include <linux/sock_diag.h>
#include <poll.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <cstring>
#endif
#include <thread>

#include "norr/address.hpp"
#include "norr/blake2s.hpp"
#include "norr/reality.hpp"
#include "norr/handshake.hpp"
#include "norr/handshake_frame.hpp"
#include "norr/packet.hpp"
#include "norr/privilege.hpp"

namespace norr {
namespace {
using Diagnostic = RuntimeDiagnostic;

[[nodiscard]] int hex_value(char c) noexcept {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

[[nodiscard]] bool looks_like_handshake(std::span<const std::byte> datagram) noexcept {
  static_assert(kProtocolVersion >= 1,
                "transport byte 0 must stay above the handshake message range");
  static_assert(static_cast<unsigned>(HandshakeMessage::cookie_reply) < 0x10U,
                "a handshake message number reached the transport range");
  if (datagram.empty()) return false;
  return static_cast<std::uint8_t>(datagram[0]) < 0x10U;
}
}


#if defined(__linux__)
std::optional<Endpoint> resolve_cover(const std::string& host_port) noexcept {
  const auto colon = host_port.rfind(':');
  if (colon == std::string::npos || colon == 0) return std::nullopt;
  const auto host = host_port.substr(0, colon);
  const auto port = static_cast<std::uint16_t>(std::atoi(host_port.c_str() + colon + 1));
  if (port == 0) return std::nullopt;

  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* result = nullptr;
  if (::getaddrinfo(host.c_str(), nullptr, &hints, &result) != 0 || result == nullptr) {
    return std::nullopt;
  }
  std::optional<Endpoint> endpoint;
  for (auto* ai = result; ai != nullptr; ai = ai->ai_next) {
    if (ai->ai_family == AF_INET) {
      std::array<std::byte, 4> octets{};
      const auto* in = reinterpret_cast<sockaddr_in*>(ai->ai_addr);
      std::memcpy(octets.data(), &in->sin_addr.s_addr, 4);
      endpoint = Endpoint{Address::from_bytes(AddressFamily::ipv4, octets), port};
      break;
    }
    if (ai->ai_family == AF_INET6) {
      std::array<std::byte, 16> octets{};
      const auto* in6 = reinterpret_cast<sockaddr_in6*>(ai->ai_addr);
      std::memcpy(octets.data(), &in6->sin6_addr, 16);
      endpoint = Endpoint{Address::from_bytes(AddressFamily::ipv6, octets), port};
    }
  }
  ::freeaddrinfo(result);
  return endpoint;
}
#else
std::optional<Endpoint> resolve_cover(const std::string&) noexcept { return std::nullopt; }
#endif

bool decode_hex(std::string_view text, std::span<std::byte> out) noexcept {
  if (text.size() != out.size() * 2) return false;
  for (std::size_t index = 0; index < out.size(); ++index) {
    const auto high = hex_value(text[index * 2]);
    const auto low = hex_value(text[index * 2 + 1]);
    if (high < 0 || low < 0) return false;
    out[index] = static_cast<std::byte>((high << 4) | low);
  }
  return true;
}

std::expected<PrivateKey, RuntimeError> load_private_key(const std::string& path) {
  if (!check_key_file_permissions(path)) {
    return std::unexpected(RuntimeError::key_file_permissions);
  }

  std::ifstream input(path, std::ios::binary);
  if (!input) return std::unexpected(RuntimeError::key_file_unreadable);
  std::string contents;
  std::getline(input, contents);

  while (!contents.empty() && (contents.back() == '\r' || contents.back() == '\n' ||
                               contents.back() == ' ' || contents.back() == '\t')) {
    contents.pop_back();
  }

  std::string_view view{contents};
  if (view.starts_with("private ")) view.remove_prefix(8);

  PrivateKey key{};
  if (!decode_hex(view, key)) return std::unexpected(RuntimeError::key_file_malformed);
  return key;
}

Runtime::~Runtime() { stop(); }

std::expected<void, RuntimeDiagnostic> Runtime::start(const Config& config) {
  if (!TunDevice::supported() || !UdpTransport::supported()) {
    return std::unexpected(Diagnostic{RuntimeError::unsupported_platform, {}});
  }
  if (!crypto_available() || !crypto_init()) {
    return std::unexpected(Diagnostic{RuntimeError::crypto_unavailable, {}});
  }

  const auto private_key = load_private_key(config.identity_key_file);
  if (!private_key) {
    return std::unexpected(Diagnostic{private_key.error(), config.identity_key_file});
  }
  const auto public_key = derive_public_key(*private_key);
  if (!public_key) {
    return std::unexpected(Diagnostic{RuntimeError::key_file_malformed, config.identity_key_file});
  }
  local_static_ = KeyPair{.public_key = *public_key, .private_key = *private_key};

  if (const auto opened = tun_.open(config.tun_name, true, false, config.network.offload); !opened) {
    return std::unexpected(Diagnostic{RuntimeError::tun_failed,
                                      std::string{tun_error_message(opened.error())}});
  }

  std::size_t tunnel_mtu = kDefaultTunnelMtu;
  if (config.network.mtu != kAutomaticMtu) {
    if (const auto applied = tun_.set_mtu(config.network.mtu); !applied) {
      return std::unexpected(Diagnostic{RuntimeError::tun_failed,
                                        "network.mtu: " +
                                            std::string{tun_error_message(applied.error())}});
    }
    tunnel_mtu = config.network.mtu;
  } else if (!tun_.set_mtu(static_cast<std::uint16_t>(kDefaultTunnelMtu))) {
    if (const auto current = tun_.mtu(); current) tunnel_mtu = *current;
  }

  const auto bind_text = (config.network.ipv6 ? std::string{"[::]:"} : std::string{"0.0.0.0:"}) +
                         std::to_string(config.listen_port);
  const auto bind_address = parse_endpoint(bind_text);
  if (!bind_address) {
    return std::unexpected(Diagnostic{RuntimeError::bind_failed, bind_text});
  }
  if (const auto bound = transport_.start(*bind_address); !bound) {
    return std::unexpected(Diagnostic{RuntimeError::bind_failed,
                                      std::string{transport_error_message(bound.error())}});
  }
  fwmark_ = config.network.fwmark;
  if (fwmark_ != 0) {
    if (const auto marked = transport_.set_mark(fwmark_); !marked) {
      return std::unexpected(Diagnostic{RuntimeError::bind_failed,
                                        "network.fwmark: " +
                                            std::string{transport_error_message(marked.error())}});
    }
    tcp_.set_mark(fwmark_);
  }

  control_ = std::make_unique<ControlPlane>(local_static_, sessions_, timers_);

  for (const auto& text : config.network.addresses) {
    const auto prefix = parse_prefix(text);
    const auto host = parse_address(std::string_view{text}.substr(0, text.find('/')));
    if (!prefix || !host) {
      return std::unexpected(Diagnostic{RuntimeError::peer_prefix_malformed, text});
    }
    const auto own = Prefix::create(*host, maximum_prefix_length(host->family()));
    if (!own) {
      return std::unexpected(Diagnostic{RuntimeError::peer_prefix_malformed, text});
    }
    if (const auto added = routes_.add_local(*own); !added) {
      return std::unexpected(Diagnostic{RuntimeError::routing_conflict,
                                        text + ": " +
                                            std::string{routing_error_message(added.error())}});
    }
  }

  PeerId next_peer = 1;
  for (const auto& entry : config.peers) {
    PeerConfig peer{};
    peer.id = next_peer++;
    if (!decode_hex(entry.public_key, peer.static_public)) {
      return std::unexpected(Diagnostic{RuntimeError::peer_key_malformed, entry.name});
    }
    if (!entry.preshared_key.empty() && !decode_hex(entry.preshared_key, peer.preshared)) {
      return std::unexpected(Diagnostic{RuntimeError::peer_key_malformed,
                                        entry.name + ".preshared_key"});
    }
    if (!entry.endpoint.empty()) {
      const auto parsed = parse_endpoint(entry.endpoint);
      if (!parsed) {
        return std::unexpected(
            Diagnostic{RuntimeError::peer_endpoint_malformed, entry.endpoint});
      }
      peer.endpoint = *parsed;
    }

    for (const auto& text : entry.allowed_ips) {
      const auto prefix = parse_prefix(text);
      if (!prefix) {
        return std::unexpected(Diagnostic{RuntimeError::peer_prefix_malformed, text});
      }
      if (const auto added = routes_.add(peer.id, *prefix); !added) {
        return std::unexpected(Diagnostic{RuntimeError::routing_conflict,
                                          text + ": " +
                                              std::string{routing_error_message(added.error())}});
      }
    }

    if (const auto installed = control_->add_peer(peer); !installed) {
      return std::unexpected(Diagnostic{RuntimeError::control_failed,
                                        std::string{control_error_message(installed.error())}});
    }
    ++peer_count_;
  }

  listen_port_ = config.listen_port;

  if (config.transport == TransportMode::quic) {
    const PeerConfig* partner = nullptr;
    for (PeerId peer = 1; peer <= peer_count_; ++peer) {
      const auto* candidate = control_->find_peer(peer);
      if (candidate == nullptr) continue;
      partner = candidate;
      if (candidate->endpoint.has_value()) break;
    }
    if (partner == nullptr) {
      return std::unexpected(Diagnostic{RuntimeError::control_failed,
                                        "transport.mode = quic needs a configured peer"});
    }
    if (peer_count_ > 1) {
      return std::unexpected(
          Diagnostic{RuntimeError::option_not_implemented,
                     "transport.mode = quic carries one peer per connection; "
                     "configure a single peer or use udp"});
    }
    if (!quic_available()) {
      return std::unexpected(Diagnostic{RuntimeError::option_not_implemented,
                                        "transport.mode = quic needs a QUIC backend"});
    }

    auto connection = make_quic_connection();
    if (!connection) {
      return std::unexpected(Diagnostic{RuntimeError::option_not_implemented,
                                        std::string{quic_error_message(connection.error())}});
    }
    quic_ = std::move(*connection);

    const auto listening = !partner->endpoint.has_value();
    const auto far = listening ? *bind_address : *partner->endpoint;

    quic_carrier_ = std::make_unique<QuicCarrier>(*quic_, transport_, far, *bind_address, listening);
    carrier_ = quic_carrier_.get();
    active_kind_ = TransportKind::quic;
  } else if (config.transport == TransportMode::tcp_tls) {
    const PeerConfig* partner = nullptr;
    for (PeerId peer = 1; peer <= peer_count_; ++peer) {
      const auto* candidate = control_->find_peer(peer);
      if (candidate == nullptr) continue;
      partner = candidate;
      if (candidate->endpoint.has_value()) break;
    }
    if (partner == nullptr) {
      return std::unexpected(Diagnostic{RuntimeError::control_failed,
                                        "transport.mode = tcp-tls needs a configured peer"});
    }
    if (peer_count_ > 1) {
      return std::unexpected(
          Diagnostic{RuntimeError::option_not_implemented,
                     "transport.mode = tcp-tls carries one peer per connection; "
                     "configure a single peer or use udp"});
    }
    const bool camouflaged = config.camouflage == CamouflageMode::fake_tls;
    if (!camouflaged && !tls_available()) {
      return std::unexpected(Diagnostic{RuntimeError::option_not_implemented,
                                        "transport.mode = tcp-tls needs a TLS backend"});
    }

    const auto dialing = partner->endpoint.has_value();
    Endpoint far = dialing ? *partner->endpoint : *bind_address;

    if (!dialing) {
      if (const auto listening = tcp_listener_.listen(*bind_address); !listening) {
        return std::unexpected(
            Diagnostic{RuntimeError::bind_failed,
                       std::string{transport_error_message(listening.error())}});
      }
    }

    tcp_carrier_ = std::make_unique<TcpCarrier>(tcp_, far, dialing, partner->preshared);
    tcp_carrier_->set_connections(config.tcp_connections);
    if (camouflaged) {
      tcp_carrier_->set_camouflage(config.camouflage_sni);
      auto camo_obfuscation = config.obfuscation;
      if (camo_obfuscation.mode == ObfuscationMode::off) {
        camo_obfuscation.mode = ObfuscationMode::header_mask;
      }
      tcp_carrier_->configure_obfuscation(camo_obfuscation, partner->preshared);
      if (config.role == NodeRole::server && !config.reality_private_key.empty()) {
        PrivateKey reality_priv{};
        if (decode_hex(config.reality_private_key, reality_priv)) {
          tcp_carrier_->set_reality_server(reality_priv, 120);
          if (!config.reality_cover.empty()) {
            if (auto cover = resolve_cover(config.reality_cover); cover.has_value()) {
              reality_cover_ = *cover;
              reality_cover_valid_ = true;
            }
          }
        }
      } else if (!config.reality_public_key.empty() && !config.reality_short_id.empty()) {
        PublicKey reality_pub{};
        RealityShortId reality_sid{};
        if (decode_hex(config.reality_public_key, reality_pub) &&
            decode_hex(config.reality_short_id, reality_sid)) {
          tcp_carrier_->set_reality_client(reality_pub, reality_sid);
        }
      }
    }
    carrier_ = tcp_carrier_.get();
    active_kind_ = TransportKind::tcp_tls;
  } else if (config.transport == TransportMode::icmp) {
    const PeerConfig* partner = nullptr;
    for (PeerId peer = 1; peer <= peer_count_; ++peer) {
      const auto* candidate = control_->find_peer(peer);
      if (candidate == nullptr) continue;
      partner = candidate;
      if (candidate->endpoint.has_value()) break;
    }
    if (partner == nullptr) {
      return std::unexpected(Diagnostic{RuntimeError::control_failed,
                                        "transport.mode = icmp needs a configured peer"});
    }
    if (peer_count_ > 1) {
      return std::unexpected(
          Diagnostic{RuntimeError::option_not_implemented,
                     "transport.mode = icmp carries one peer per socket; configure a single peer"});
    }
    if (!IcmpTransport::supported()) {
      return std::unexpected(Diagnostic{RuntimeError::option_not_implemented,
                                        "transport.mode = icmp needs the Linux raw-socket backend"});
    }
    const auto role = config.role == NodeRole::client ? IcmpTransport::Role::client
                                                      : IcmpTransport::Role::server;
    if (role == IcmpTransport::Role::server) {
      if (std::ofstream sysctl{"/proc/sys/net/ipv4/icmp_echo_ignore_all"}; sysctl) {
        sysctl << "1\n";
      } else {
        std::fprintf(stderr,
                     "icmp: could not set icmp_echo_ignore_all; kernel echo replies may "
                     "collide with the tunnel\n");
      }
    }
    if (const auto ok = icmp_transport_.start(*bind_address, role); !ok) {
      return std::unexpected(Diagnostic{RuntimeError::bind_failed,
                                        std::string{transport_error_message(ok.error())}});
    }
    if (fwmark_ != 0) static_cast<void>(icmp_transport_.set_mark(fwmark_));
    {
      const auto domain = std::as_bytes(std::span{std::string_view{"norr-icmp-id-v1"}});
      const auto digest = Blake2s::hash(domain, partner->preshared);
      auto id = static_cast<std::uint16_t>(
          (static_cast<unsigned>(static_cast<std::uint8_t>(digest[0])) << 8U) |
          static_cast<unsigned>(static_cast<std::uint8_t>(digest[1])));
      if (id == 0) id = 1;
      icmp_transport_.set_identifier(id);
    }
    const auto far = partner->endpoint.has_value() ? *partner->endpoint : *bind_address;
    icmp_carrier_ = std::make_unique<IcmpCarrier>(icmp_transport_, far);
    auto icmp_obfuscation = config.obfuscation;
    if (icmp_obfuscation.mode == ObfuscationMode::off) {
      icmp_obfuscation.mode = ObfuscationMode::header_mask;
    }
    icmp_carrier_->configure_obfuscation(icmp_obfuscation, partner->preshared);
    if (config.role == NodeRole::client) icmp_carrier_->prime();
    carrier_ = icmp_carrier_.get();
    active_kind_ = TransportKind::icmp;
  } else {
    udp_carrier_ = std::make_unique<UdpCarrier>(transport_);
    if (config.obfuscation.mode != ObfuscationMode::off) {
      if (peer_count_ != 1) {
        return std::unexpected(
            Diagnostic{RuntimeError::option_not_implemented,
                       "transport.obfuscation carries one peer per socket; configure a "
                       "single peer"});
      }
      const auto* partner = control_->find_peer(1);
      const auto preshared = partner != nullptr ? partner->preshared : PresharedKey{};
      udp_carrier_->configure_obfuscation(config.obfuscation, preshared);
      if (config.role == NodeRole::client) udp_carrier_->prime();
    }
    carrier_ = udp_carrier_.get();
    active_kind_ = TransportKind::udp;
  }

  if (config.transport == TransportMode::automatic && peer_count_ == 1) {
    const auto* partner = control_->find_peer(1);

    const bool dials = config.role == NodeRole::client;
    const auto far = partner != nullptr && partner->endpoint.has_value()
                         ? *partner->endpoint
                         : Endpoint{};

    const bool camouflaged = config.camouflage == CamouflageMode::fake_tls;
    if (partner != nullptr && (camouflaged || tls_available())) {
      if (!dials) {
        if (const auto listening = tcp_listener_.listen(*bind_address); !listening) {
          return std::unexpected(
              Diagnostic{RuntimeError::bind_failed,
                         std::string{transport_error_message(listening.error())}});
        }
      }
      tcp_carrier_ = std::make_unique<TcpCarrier>(tcp_, far, dials, partner->preshared);
      tcp_carrier_->set_connections(config.tcp_connections);
      if (camouflaged) {
      tcp_carrier_->set_camouflage(config.camouflage_sni);
      auto camo_obfuscation = config.obfuscation;
      if (camo_obfuscation.mode == ObfuscationMode::off) {
        camo_obfuscation.mode = ObfuscationMode::header_mask;
      }
      tcp_carrier_->configure_obfuscation(camo_obfuscation, partner->preshared);
      if (config.role == NodeRole::server && !config.reality_private_key.empty()) {
        PrivateKey reality_priv{};
        if (decode_hex(config.reality_private_key, reality_priv)) {
          tcp_carrier_->set_reality_server(reality_priv, 120);
          if (!config.reality_cover.empty()) {
            if (auto cover = resolve_cover(config.reality_cover); cover.has_value()) {
              reality_cover_ = *cover;
              reality_cover_valid_ = true;
            }
          }
        }
      } else if (!config.reality_public_key.empty() && !config.reality_short_id.empty()) {
        PublicKey reality_pub{};
        RealityShortId reality_sid{};
        if (decode_hex(config.reality_public_key, reality_pub) &&
            decode_hex(config.reality_short_id, reality_sid)) {
          tcp_carrier_->set_reality_client(reality_pub, reality_sid);
        }
      }
    }
      paths_.add_path(TransportKind::tcp_tls);
    }
    if (partner != nullptr && quic_available()) {
      auto connection = make_quic_connection();
      if (connection) {
        quic_ = std::move(*connection);
        quic_carrier_ = std::make_unique<QuicCarrier>(*quic_, transport_, far,
                                                      *bind_address, !dials);
        paths_.add_path(TransportKind::quic);
      }
    }
    if (tcp_carrier_ != nullptr || quic_carrier_ != nullptr) {
      paths_.add_path(TransportKind::udp);

      paths_.set_active(TransportKind::udp);
      automatic_fallback_ = true;
      last_path_check_ = std::chrono::steady_clock::now();
    }
  }

  worker_ = std::make_unique<Worker>(tun_, *carrier_, routes_, sessions_);
  worker_->set_mtu(tunnel_mtu);
  worker_->set_session_request([this](PeerId peer) { request_session(peer); });

  worker_->set_echo_responder(
      [this](PeerId peer, std::span<const std::byte> token) { answer_echo(peer, token); });
  worker_->set_echo_reply_handler(
      [this](PeerId peer, std::span<const std::byte> token) { note_echo_reply(peer, token); });

  worker_->set_loss_report_handler(
      [this](PeerId peer, double raw, double residual) {
        const auto plan = worker_->note_peer_loss(peer, raw, residual, rtt_inflated(),
                                                  std::chrono::steady_clock::now());
        if (!plan) return;
        if (plan->active()) {
          std::fprintf(stderr, "fec: %zu+%zu x%zu for %.1f%% loss\n", plan->data, plan->parity,
                       plan->lanes, raw * 100.0);
        } else {
          std::fprintf(stderr, "fec: off at %.1f%% loss\n", raw * 100.0);
        }
      });
  fec_configured_ = config.fec != FecMode::off;
  if (config.fec != FecMode::off) {
    worker_->enable_fec(config.fec);
  }

  if (config.profile != TrafficProfile::standard) {
    worker_->set_traffic_profile(config.profile);
  }

  if (config.qos_enabled) {
    worker_->enable_queueing(static_cast<double>(config.qos_rate_bytes),
                             config.qos_burst_bytes, std::chrono::steady_clock::now());

    CongestionConfig tuning{};
    tuning.maximum_rate_bytes = static_cast<double>(config.qos_rate_bytes);
    congestion_ = CongestionController{tuning, static_cast<double>(config.qos_rate_bytes)};
    congestion_enabled_ = true;
  }

  if (config.metrics_enabled) {
    const auto listen = parse_endpoint(config.metrics_listen);
    if (!listen) {
      return std::unexpected(Diagnostic{RuntimeError::bind_failed, config.metrics_listen});
    }
    if (const auto started = metrics_.start(*listen); !started) {
      return std::unexpected(Diagnostic{RuntimeError::bind_failed,
                                        config.metrics_listen + ": " +
                                            std::string{metrics_error_message(started.error())}});
    }
  }

  worker_->set_ingress_filter(
      [this](const Endpoint& source, std::span<const std::byte> datagram) {
        return dispatch_control(source, datagram);
      });

  worker_->set_provisional_opener([this](const PacketView& view,
                                         std::span<const std::byte> datagram,
                                         std::span<std::byte> out,
                                         const Endpoint& source) -> std::optional<std::size_t> {
    const auto opened = control_->try_promote_provisional(view, datagram, out, source);
    if (!opened) return std::nullopt;
    return *opened;
  });

  return {};
}

std::expected<std::size_t, RuntimeDiagnostic> Runtime::reload(const std::string& path) {
  const auto config = load_config_file(path);
  if (!config) {
    const auto& problem = config.error();
    return std::unexpected(Diagnostic{RuntimeError::control_failed,
                                      std::string{config_error_message(problem.error)} +
                                          (problem.detail.empty() ? "" : " (" + problem.detail + ")")});
  }

  if (config->tun_name != tun_.name()) {
    return std::unexpected(Diagnostic{RuntimeError::option_not_implemented,
                                      "node.tun cannot change on reload"});
  }
  if (config->listen_port != listen_port_) {
    return std::unexpected(Diagnostic{RuntimeError::option_not_implemented,
                                      "node.listen_port cannot change on reload"});
  }
  if (config->transport != TransportMode::automatic && config->transport != TransportMode::udp) {
    return std::unexpected(Diagnostic{RuntimeError::option_not_implemented,
                                      "transport.mode cannot change on reload"});
  }
  if (config->fec != worker_->fec_mode()) {
    return std::unexpected(Diagnostic{RuntimeError::option_not_implemented,
                                      "fec.mode cannot change on reload: the peer would still be "
                                      "framing symbols the old way"});
  }

  struct Incoming {
    PeerConfig peer;
    std::vector<Prefix> prefixes;
  };
  std::vector<Incoming> incoming;
  incoming.reserve(config->peers.size());

  for (const auto& entry : config->peers) {
    Incoming next{};
    if (!decode_hex(entry.public_key, next.peer.static_public)) {
      return std::unexpected(Diagnostic{RuntimeError::peer_key_malformed, entry.name});
    }
    if (!entry.preshared_key.empty() && !decode_hex(entry.preshared_key, next.peer.preshared)) {
      return std::unexpected(
          Diagnostic{RuntimeError::peer_key_malformed, entry.name + ".preshared_key"});
    }
    if (!entry.endpoint.empty()) {
      const auto parsed = parse_endpoint(entry.endpoint);
      if (!parsed) {
        return std::unexpected(Diagnostic{RuntimeError::peer_endpoint_malformed, entry.endpoint});
      }
      next.peer.endpoint = *parsed;
    }
    for (const auto& text : entry.allowed_ips) {
      const auto prefix = parse_prefix(text);
      if (!prefix) {
        return std::unexpected(Diagnostic{RuntimeError::peer_prefix_malformed, text});
      }
      next.prefixes.push_back(*prefix);
    }
    incoming.push_back(std::move(next));
  }

  std::unordered_map<PeerId, bool> still_present;
  for (PeerId peer = 1; peer <= peer_count_; ++peer) still_present[peer] = false;

  routes_.clear_peer_routes();

  for (auto& next : incoming) {
    PeerId id = kNoPeer;
    for (PeerId peer = 1; peer <= peer_count_; ++peer) {
      const auto* existing = control_->find_peer(peer);
      if (existing != nullptr &&
          constant_time_equal(existing->static_public, next.peer.static_public)) {
        id = peer;
        break;
      }
    }
    if (id == kNoPeer) id = static_cast<PeerId>(++peer_count_);

    next.peer.id = id;
    still_present[id] = true;

    for (const auto& prefix : next.prefixes) {
      if (const auto added = routes_.add(id, prefix); !added) {
        return std::unexpected(Diagnostic{RuntimeError::routing_conflict,
                                          std::string{routing_error_message(added.error())}});
      }
    }
    if (const auto installed = control_->add_peer(next.peer); !installed) {
      return std::unexpected(Diagnostic{RuntimeError::control_failed,
                                        std::string{control_error_message(installed.error())}});
    }
  }

  for (const auto& [peer, present] : still_present) {
    if (!present) control_->forget_peer(peer);
  }

  return incoming.size();
}

std::size_t Runtime::dial_configured_peers() {
  const auto now = std::chrono::steady_clock::now();
  std::size_t started = 0;
  for (PeerId peer = 1; peer <= peer_count_; ++peer) {
    const auto* configured = control_->find_peer(peer);
    if (configured == nullptr || !configured->endpoint.has_value()) continue;
    const auto outgoing = control_->start_handshake(peer, now);
    if (!outgoing) continue;
    send_outgoing(*outgoing);
    ++started;
  }
  return started;
}

void Runtime::send_outgoing(const OutgoingHandshake& outgoing) {
  const OutboundDatagram datagram{.destination = outgoing.destination,
                                  .payload = outgoing.datagram};
  const std::array<OutboundDatagram, 1> batch{datagram};

  static_cast<void>(carrier_->send_batch(batch));
}

void Runtime::send_control(PeerId peer, std::span<const std::byte> payload) {
  auto session = sessions_.find_by_peer(peer);
  if (session == nullptr || !session->endpoint().has_value()) return;

  std::array<std::byte, kPacketHeaderSize + 1 + kEchoTokenSize + kAeadTagSize> frame{};
  const auto sealed = session->seal(FrameType::control, payload, frame);
  if (!sealed) return;

  const OutboundDatagram datagram{.destination = *session->endpoint(),
                                  .payload = std::span{frame}.first(*sealed)};
  const std::array<OutboundDatagram, 1> batch{datagram};
  static_cast<void>(carrier_->send_batch(batch));
}

void Runtime::send_keepalive(PeerId peer) {
  const auto now = std::chrono::steady_clock::now();
  const auto stamp = static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count());

  std::array<std::byte, 1 + kEchoTokenSize> payload{};
  payload[0] = kEchoRequest;
  for (std::size_t index = 0; index < kEchoTokenSize; ++index) {
    payload[1 + index] = static_cast<std::byte>((stamp >> (8 * (7 - index))) & 0xFFU);
  }

  send_control(peer, payload);
}

void Runtime::answer_echo(PeerId peer, std::span<const std::byte> token) {
  if (token.size() != kEchoTokenSize) return;

  std::array<std::byte, 1 + kEchoTokenSize> payload{};
  payload[0] = kEchoReply;
  std::copy(token.begin(), token.end(), payload.begin() + 1);
  send_control(peer, payload);
}

void Runtime::note_echo_reply(PeerId peer, std::span<const std::byte> token) {
  if (token.size() != kEchoTokenSize) return;

  std::uint64_t stamp = 0;
  for (const auto byte : token) {
    stamp = (stamp << 8) | static_cast<std::uint64_t>(byte);
  }

  const auto now = std::chrono::steady_clock::now();
  const auto sent_at = std::chrono::microseconds{stamp};
  const auto elapsed =
      std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()) - sent_at;

  if (elapsed.count() <= 0 || elapsed > kMaximumPlausibleRtt) return;

  last_rtt_ = elapsed;
  const auto now_rtt = std::chrono::steady_clock::now();
  if (min_rtt_.count() <= 0 || elapsed <= min_rtt_ || now_rtt - min_rtt_at_ > std::chrono::seconds{10}) {
    min_rtt_ = elapsed;
    min_rtt_at_ = now_rtt;
  }
  static_cast<void>(peer);
}

bool Runtime::rtt_inflated() const noexcept {
  if (min_rtt_.count() <= 0 || last_rtt_.count() <= 0) return false;
  const auto limit = min_rtt_ * 2 + std::chrono::milliseconds{2};
  return last_rtt_ > limit;
}

std::uint64_t Runtime::read_socket_drops() const noexcept {
#if defined(__linux__) && defined(SO_MEMINFO)
  std::array<std::uint32_t, SK_MEMINFO_VARS> info{};
  socklen_t length = sizeof(info);
  if (::getsockopt(transport_.descriptor(), SOL_SOCKET, SO_MEMINFO, info.data(), &length) != 0) {
    return socket_drops_;
  }
  if (length < sizeof(std::uint32_t) * (SK_MEMINFO_DROPS + 1)) return socket_drops_;
  return info[SK_MEMINFO_DROPS];
#else
  return socket_drops_;
#endif
}

void Runtime::service_tcp_carrier(Instant now) {
  if (active_kind_ != TransportKind::tcp_tls) return;

  const auto was_ready = tcp_ready_;

  auto* tcp_carrier = dynamic_cast<TcpCarrier*>(carrier_);

  if (tcp_listener_.listening() && !tcp_.connected() &&
      tcp_.state() != TcpState::connecting) {
    auto incoming = tcp_listener_.accept();
    if (incoming && incoming->has_value()) {
      tcp_ = std::move(**incoming);
      tcp_.set_mark(fwmark_);
      tcp_accepted_at_ = now;
    }
  }

  while (tcp_listener_.listening() && tcp_carrier != nullptr) {
    auto incoming = tcp_listener_.accept();
    if (!incoming || !incoming->has_value()) break;
    auto conn = std::move(**incoming);
    conn.set_mark(fwmark_);
    if (tcp_carrier->wants_more()) {
      tcp_carrier->adopt(std::move(conn));
    }
  }

  if (tcp_listener_.listening() && tcp_.connected() && tcp_accepted_at_ != Instant{} &&
      now - tcp_accepted_at_ > std::chrono::seconds{15}) {
    bool any_received = false;
    for (PeerId peer = 1; peer <= peer_count_; ++peer) {
      auto session = sessions_.find_by_peer(peer);
      if (session != nullptr && session->has_received()) {
        any_received = true;
        break;
      }
    }
    if (!any_received) {
      tcp_.close();
      tcp_accepted_at_ = Instant{};
      tcp_ready_ = false;
    }
  }

  if (tcp_carrier == nullptr) return;

  tcp_carrier->poll(now);
  tcp_ready_ = tcp_carrier->ready();

  if (reality_cover_valid_ && tcp_.reality_rejected()) {
    auto prelude = tcp_.take_fallback_prelude();
    auto client = tcp_.release_socket();
    tcp_accepted_at_ = Instant{};
    tcp_ready_ = false;
    if (client.valid()) {
      FallbackProxy proxy;
      if (proxy.start(std::move(client), reality_cover_, prelude)) {
        fallbacks_.push_back(std::move(proxy));
      }
    }
  }

  if (tcp_ready_ && !was_ready) {
    static_cast<void>(dial_configured_peers());
  }
}


void Runtime::service_fallbacks() {
  for (auto& proxy : fallbacks_) proxy.pump();
  std::erase_if(fallbacks_, [](const FallbackProxy& p) { return !p.active(); });
}

void Runtime::service_quic_carrier() {
  if (active_kind_ != TransportKind::quic) return;

  auto* quic_carrier = dynamic_cast<QuicCarrier*>(carrier_);
  if (quic_carrier == nullptr) return;

  const auto was_ready = quic_ready_;
  quic_carrier->poll();
  quic_ready_ = quic_carrier->ready();

  if (quic_ready_ && !was_ready) {
    static_cast<void>(dial_configured_peers());
  }
}

void Runtime::apply_congestion_control(Instant now) {
  if (!congestion_enabled_ || worker_ == nullptr || !worker_->queueing_enabled()) return;
  if (now - last_congestion_sample_ < kCongestionSampleInterval) return;

  if (last_rtt_.count() <= 0) return;

  const auto interval = last_congestion_sample_ == Instant{}
                            ? kCongestionSampleInterval
                            : now - last_congestion_sample_;
  last_congestion_sample_ = now;

  const auto sent = worker_->bytes_sent();
  const auto dropped = worker_->bytes_dropped();
  const DeliverySample sample{
      .rtt = last_rtt_,
      .bytes_delivered = sent > last_bytes_sent_ ? sent - last_bytes_sent_ : 0,
      .bytes_lost = dropped > last_bytes_dropped_ ? dropped - last_bytes_dropped_ : 0,
      .interval = interval};
  last_bytes_sent_ = sent;
  last_bytes_dropped_ = dropped;

  congestion_.observe(sample, now);
  worker_->set_pacing_rate(congestion_.rate_bytes_per_second());
}

void Runtime::evaluate_transport_paths(Instant now) {
  if (!automatic_fallback_) return;

  if (switched_at_ != Instant{} && now - switched_at_ < kTransportSettleTime) return;

  if (now - last_path_check_ < kTransportCheckInterval) return;
  last_path_check_ = now;

  if (active_kind_ == TransportKind::tcp_tls && tcp_carrier_ != nullptr &&
      !tcp_carrier_->ready()) {
    return;
  }
  if (active_kind_ == TransportKind::quic && quic_carrier_ != nullptr &&
      !quic_carrier_->ready()) {
    return;
  }

  const auto& transport = carrier_->stats();
  const auto errors = transport.tx_errors + transport.rx_errors;
  const auto new_errors = errors > last_tx_errors_ ? errors - last_tx_errors_ : 0;
  last_tx_errors_ = errors;

  bool hearing = false;
  for (PeerId peer = 1; peer <= peer_count_; ++peer) {
    auto session = sessions_.find_by_peer(peer);
    if (session == nullptr || !session->has_received()) continue;
    if (now - session->last_received() < kTransportSilenceTimeout) {
      hearing = true;
      break;
    }
  }

  const auto& control = control_->stats();
  const auto attempted = control.handshakes_started;
  const auto retries = control.retries;
  const auto new_retries = retries > last_retries_ ? retries - last_retries_ : 0;
  last_retries_ = retries;

  if (new_retries > 0 && !hearing) {
    ++consecutive_stalls_;
  } else {
    consecutive_stalls_ = 0;
  }
  const auto stalled = consecutive_stalls_ >= kStallsBeforeFallback;

  const auto failing = stalled || new_errors > 0;
  const auto working = !failing;
  if (!failing && !hearing) return;

  const auto rtt_microseconds = static_cast<double>(
      std::chrono::duration_cast<std::chrono::microseconds>(last_rtt_).count());

  const PathSample sample{.rtt_microseconds = rtt_microseconds,
                          .loss_fraction = working ? 0.0 : 1.0,
                          .transport_errors = new_errors,
                          .reachable = working};
  paths_.observe(active_kind_, sample);

  if (attempted == 0 && new_errors == 0 && new_retries == 0) return;
  if (working && new_errors == 0) return;

  if (!paths_.evaluate(now)) return;

  const auto chosen = paths_.active();
  if (chosen == active_kind_) return;

  Carrier* next = nullptr;
  switch (chosen) {
    case TransportKind::udp: next = udp_carrier_.get(); break;
    case TransportKind::tcp_tls: next = tcp_carrier_.get(); break;
    case TransportKind::quic: next = quic_carrier_.get(); break;
    case TransportKind::icmp: next = icmp_carrier_.get(); break;
  }
  if (next == nullptr) return;

  carrier_ = next;
  active_kind_ = chosen;
  worker_->set_carrier(*next);
  last_tx_errors_ = 0;
  last_retries_ = control_->stats().retries;
  switched_at_ = now;

  std::fprintf(stderr, "transport: switched to %s\n",
               std::string{transport_kind_name(chosen)}.c_str());

  std::fflush(stderr);

  for (PeerId peer = 1; peer <= peer_count_; ++peer) {
    auto session = sessions_.find_by_peer(peer);
    if (session != nullptr) sessions_.remove(session->local_key_id());
  }
  static_cast<void>(dial_configured_peers());
}

void Runtime::request_session(PeerId peer) {
  if (control_ == nullptr || control_->has_pending(peer)) return;
  if (!control_->dial_endpoint(peer).has_value()) return;
  const auto outgoing = control_->start_handshake(peer, std::chrono::steady_clock::now());
  if (outgoing) send_outgoing(*outgoing);
}

void Runtime::redial_dead_peers(Instant now) {
  if (now - last_liveness_sweep_ < kHandshakeTimeout) return;
  last_liveness_sweep_ = now;

  for (PeerId peer = 1; peer <= peer_count_; ++peer) {
    const auto* configured = control_->find_peer(peer);
    if (configured == nullptr) continue;
    const bool dials = configured->endpoint.has_value();

    auto session = sessions_.find_by_peer(peer);
    if (session != nullptr) {
      const auto silent = session->has_received() &&
                          now - session->last_received() >= kDeadPeerTimeout;
      if (!silent && !session->expired(now)) continue;

      sessions_.remove(session->local_key_id());
      timers_.cancel(TimerKind::rekey, peer);
      timers_.cancel(TimerKind::keepalive, peer);
    }

    if (!dials || control_->has_pending(peer)) continue;
    const auto outgoing = control_->start_handshake(peer, now);
    if (outgoing) send_outgoing(*outgoing);
  }
}

void Runtime::report_loss(Instant now) {
  if (!fec_configured_ || now - last_loss_report_ < std::chrono::seconds{1}) return;
  last_loss_report_ = now;
  const auto drops = read_socket_drops();
  const auto local_drops = static_cast<std::uint32_t>(drops - socket_drops_);
  socket_drops_ = drops;
  for (PeerId peer = 1; peer <= peer_count_; ++peer) {
    auto session = sessions_.find_by_peer(peer);
    if (session == nullptr) continue;
    send_keepalive(peer);
    const auto loss = session->take_loss_sample();
    if (!loss) continue;
    const auto local = loss->expected == 0
                           ? 0.0
                           : static_cast<double>(local_drops) / static_cast<double>(loss->expected);
    const auto permille = [&](double value) {
      return static_cast<unsigned>(std::clamp(value - local, 0.0, 1.0) * 1000.0 + 0.5);
    };
    const auto raw = permille(loss->raw);
    const auto residual = permille(loss->residual);
    const std::array<std::byte, kLossReportSize> payload{
        kLossReport, static_cast<std::byte>((raw >> 8U) & 0xFFU),
        static_cast<std::byte>(raw & 0xFFU), static_cast<std::byte>((residual >> 8U) & 0xFFU),
        static_cast<std::byte>(residual & 0xFFU)};
    send_control(peer, payload);
  }
}

void Runtime::wait_for_work(Instant now) {
#if defined(__linux__)
  std::vector<pollfd> watched;
  watched.reserve(5);
  const auto watch = [&](int descriptor) {
    if (descriptor >= 0) watched.push_back(pollfd{.fd = descriptor, .events = POLLIN, .revents = 0});
  };
  watch(tun_.descriptor());
  watch(transport_.descriptor());
  if (icmp_transport_.started()) watch(icmp_transport_.descriptor());
  if (tcp_.connected()) {
    watch(tcp_.descriptor());
    if (tcp_.has_pending_output()) watched.back().events |= POLLOUT;
  }
  if (auto* tcp_carrier = dynamic_cast<TcpCarrier*>(carrier_); tcp_carrier != nullptr) {
    tcp_carrier->for_each_descriptor([&](int descriptor) {
      if (descriptor != tcp_.descriptor()) watch(descriptor);
    });
  }
  for (const auto& proxy : fallbacks_) {
    if (!proxy.active()) continue;
    if (proxy.client_fd() >= 0) {
      watched.push_back(pollfd{.fd = proxy.client_fd(), .events = POLLIN, .revents = 0});
      if (proxy.wants_client_write()) watched.back().events |= POLLOUT;
    }
    if (proxy.cover_fd() >= 0) {
      watched.push_back(pollfd{.fd = proxy.cover_fd(), .events = POLLIN, .revents = 0});
      if (proxy.wants_cover_write()) watched.back().events |= POLLOUT;
    }
  }
  if (tcp_listener_.listening()) {
    auto* tcp_carrier = dynamic_cast<TcpCarrier*>(carrier_);
    const bool want = !tcp_.connected() || (tcp_carrier != nullptr && tcp_carrier->wants_more());
    if (want) watch(tcp_listener_.descriptor());
  }
  if (metrics_.listening()) watch(metrics_.descriptor());

  auto timeout = std::chrono::milliseconds{50};
  if (!timers_.empty()) {
    const auto until = std::chrono::duration_cast<std::chrono::milliseconds>(timers_.next_due() - now);
    timeout = std::clamp(until, std::chrono::milliseconds{0}, timeout);
  }
  if (worker_->queueing_enabled() && !worker_->scheduler().empty()) {
    timeout = std::min(timeout, std::chrono::milliseconds{1});
  }
  if (worker_->fec_pending()) {
    timeout = std::min(timeout, std::chrono::duration_cast<std::chrono::milliseconds>(kFecFlushInterval));
  }
  static_cast<void>(::poll(watched.data(), static_cast<nfds_t>(watched.size()),
                           static_cast<int>(timeout.count())));
#else
  static_cast<void>(now);
  std::this_thread::sleep_for(std::chrono::milliseconds{1});
#endif
}

void Runtime::service_timers(Instant now) {
  const auto events = timers_.expire(now);
  if (events.empty()) return;

  for (const auto& outgoing : control_->on_timers(events, now)) {
    send_outgoing(outgoing);
  }
  for (const auto peer : control_->take_expired_keepalives()) {
    send_keepalive(peer);
  }
}

bool Runtime::dispatch_control(const Endpoint& source, std::span<const std::byte> datagram) {
  if (!looks_like_handshake(datagram)) return false;

  handled_control_ = true;
  const auto now = std::chrono::steady_clock::now();
  const auto reply = control_->handle_datagram(source, datagram, now);

  if (reply && reply->has_value()) send_outgoing(**reply);

  for (const auto peer : control_->take_expired_keepalives()) {
    send_keepalive(peer);
  }
  return true;
}

void Runtime::run() {
  running_.store(true, std::memory_order_relaxed);

  while (running_.load(std::memory_order_relaxed)) {
    const auto now = std::chrono::steady_clock::now();

    service_timers(now);

    const auto inbound = worker_->pump_udp_to_tun();
    const auto outbound = worker_->pump_tun_to_udp();
    const auto flushed = worker_->flush(now);
    static_cast<void>(worker_->send_chaff(now));
    const auto worked = inbound > 0 || outbound > 0 || flushed > 0 || handled_control_;
    handled_control_ = false;

    control_->evaluate_load(control_->pending(), ControlPlane::kMaximumPending, now);
    sessions_.expire_retired(now);
    redial_dead_peers(now);
    service_tcp_carrier(now);
    service_fallbacks();
    service_quic_carrier();
    apply_congestion_control(now);
    report_loss(now);
    evaluate_transport_paths(now);

    if (reload_requested_.exchange(false, std::memory_order_relaxed)) {
      const auto applied = reload(config_path_);
      if (applied) {
        std::fprintf(stderr, "reload: %zu peers\n", *applied);
      } else {
        std::fprintf(stderr, "reload refused: %s%s%s\n",
                     std::string{runtime_error_message(applied.error().error)}.c_str(),
                     applied.error().detail.empty() ? "" : ": ",
                     applied.error().detail.c_str());
      }
    }

    if (metrics_.listening()) {
      const MetricsSnapshot snapshot{.worker = &worker_->stats(),
                                     .control = &control_->stats(),
                                     .tun = &tun_.stats(),
                                     .transport = &carrier_->stats(),
                                     .sessions = sessions_.size(),
                                     .peers = peer_count_};
      static_cast<void>(metrics_.poll(snapshot));
    }

    if (!worked) wait_for_work(now);
  }
}

const WorkerStats& Runtime::stats() const {
  static const WorkerStats empty{};
  return worker_ ? worker_->stats() : empty;
}

const ControlStats& Runtime::control_stats() const {
  static const ControlStats empty{};
  return control_ ? control_->stats() : empty;
}

FecMode Runtime::fec_mode() const {
  return worker_ ? worker_->fec_mode() : FecMode::off;
}

const FecStats& Runtime::fec_encode_stats() const {
  static const FecStats empty{};
  return worker_ ? worker_->fec_stats() : empty;
}

const FecStats& Runtime::fec_decode_stats() const {
  static const FecStats empty{};
  return worker_ ? worker_->fec_decode_stats() : empty;
}
}
