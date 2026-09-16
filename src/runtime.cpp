#include "norr/runtime.hpp"

#include <array>
#include <chrono>
#include <fstream>
#include <optional>
#include <thread>

#include "norr/address.hpp"
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

  if (config.transport == TransportMode::tcp_tls) {
    return std::unexpected(Diagnostic{RuntimeError::option_not_implemented,
                                      "transport.mode: TLS now protects the TCP carrier, but no "
                                      "TCP listener or carrier selection exists, so a peer cannot "
                                      "answer"});
  }
  if (config.transport == TransportMode::quic) {
    return std::unexpected(
        Diagnostic{RuntimeError::option_not_implemented,
                   "transport.mode: the QUIC carrier is not a working tunnel transport yet. "
                   "Norr's own handshake still goes out on the raw socket the QUIC connection "
                   "owns, and there is no QUIC listener, so a peer cannot answer"});
  }
  if (config.fec != FecMode::off) {
    return std::unexpected(Diagnostic{RuntimeError::option_not_implemented,
                                      "fec.mode: the encoder exists but has no wire framing in the "
                                      "datapath; set fec.mode = \"off\""});
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

  if (const auto opened = tun_.open(config.tun_name, true, false); !opened) {
    return std::unexpected(Diagnostic{RuntimeError::tun_failed,
                                      std::string{tun_error_message(opened.error())}});
  }

  if (config.network.mtu != kAutomaticMtu) {
    if (const auto applied = tun_.set_mtu(config.network.mtu); !applied) {
      return std::unexpected(Diagnostic{RuntimeError::tun_failed,
                                        "network.mtu: " +
                                            std::string{tun_error_message(applied.error())}});
    }
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

  control_ = std::make_unique<ControlPlane>(local_static_, sessions_, timers_);

  for (const auto& text : config.network.addresses) {
    const auto prefix = parse_prefix(text);
    if (!prefix) {
      return std::unexpected(Diagnostic{RuntimeError::peer_prefix_malformed, text});
    }
    if (const auto added = routes_.add_local(*prefix); !added) {
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

  carrier_ = std::make_unique<UdpCarrier>(transport_);
  active_kind_ = TransportKind::udp;

  worker_ = std::make_unique<Worker>(tun_, *carrier_, routes_, sessions_);

  if (config.qos_enabled) {
    worker_->enable_queueing(static_cast<double>(config.qos_rate_bytes),
                             config.qos_burst_bytes, std::chrono::steady_clock::now());
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

  // Refuse what cannot change without recreating the device or the socket.
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
  if (config->fec != FecMode::off) {
    return std::unexpected(Diagnostic{RuntimeError::option_not_implemented,
                                      "fec.mode is not implemented"});
  }

  // Decode everything before changing anything, so a malformed file leaves the
  // running configuration untouched.
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

  // A peer is identified by its static key, not by its position in the file,
  // so one that is still present keeps its id and its live session.
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
  static_cast<void>(transport_.send_batch(batch));
}

void Runtime::send_keepalive(PeerId peer) {
  auto* session = sessions_.find_by_peer(peer);
  if (session == nullptr || !session->endpoint().has_value()) return;

  std::array<std::byte, kPacketHeaderSize + kAeadTagSize> frame{};
  const auto sealed = session->seal(FrameType::control, {}, frame);
  if (!sealed) return;

  const OutboundDatagram datagram{.destination = *session->endpoint(),
                                  .payload = std::span{frame}.first(*sealed)};
  const std::array<OutboundDatagram, 1> batch{datagram};
  static_cast<void>(carrier_->send_batch(batch));
}

void Runtime::redial_dead_peers(Instant now) {
  if (now - last_liveness_sweep_ < kKeepaliveInterval) return;
  last_liveness_sweep_ = now;

  for (PeerId peer = 1; peer <= peer_count_; ++peer) {
    const auto* configured = control_->find_peer(peer);
    if (configured == nullptr || !configured->endpoint.has_value()) continue;

    auto* session = sessions_.find_by_peer(peer);
    if (session == nullptr) continue;

    const auto silent = session->has_received() &&
                        now - session->last_received() >= kDeadPeerTimeout;
    if (!silent && !session->expired(now)) continue;

    sessions_.remove(session->local_key_id());
    timers_.cancel(TimerKind::rekey, peer);
    timers_.cancel(TimerKind::keepalive, peer);

    const auto outgoing = control_->start_handshake(peer, now);
    if (outgoing) send_outgoing(*outgoing);
  }
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
    const auto worked = inbound > 0 || outbound > 0 || flushed > 0 || handled_control_;
    handled_control_ = false;

    control_->evaluate_load(control_->pending(), ControlPlane::kMaximumPending, now);
    sessions_.expire_retired(now);
    redial_dead_peers(now);

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

    if (!worked) std::this_thread::sleep_for(std::chrono::microseconds(200));
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

}
