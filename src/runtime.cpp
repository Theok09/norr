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

  if (config.transport == TransportMode::quic) {
    // QUIC carries a connection between two endpoints, like TCP: one peer per
    // carrier. The node with a configured endpoint dials, the other answers.
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
    // TCP carries a stream between exactly two endpoints, so the carrier binds
    // to one peer. A node with a configured endpoint dials; one without listens.
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
    if (!tls_available()) {
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
    carrier_ = tcp_carrier_.get();
    active_kind_ = TransportKind::tcp_tls;
  } else {
    udp_carrier_ = std::make_unique<UdpCarrier>(transport_);
    carrier_ = udp_carrier_.get();
    active_kind_ = TransportKind::udp;
  }

  // "auto" builds every carrier this configuration and build can support, so a
  // path that stops working can be abandoned for one that still does. A named
  // mode builds only that one: an operator who asked for QUIC did not ask to
  // be moved off it.
  if (config.transport == TransportMode::automatic && peer_count_ == 1) {
    const auto* partner = control_->find_peer(1);

    // A connection-oriented carrier needs one side to dial and the other to
    // answer. Both sides of an automatic pair usually know each other's
    // endpoint, so the endpoint cannot decide which is which - the role does.
    // Without this both nodes dial and neither listens, and the fallback
    // carriers never connect at all.
    const bool dials = config.role == NodeRole::client;
    const auto far = partner != nullptr && partner->endpoint.has_value()
                         ? *partner->endpoint
                         : Endpoint{};

    if (partner != nullptr && tls_available()) {
      if (!dials) {
        if (const auto listening = tcp_listener_.listen(*bind_address); !listening) {
          return std::unexpected(
              Diagnostic{RuntimeError::bind_failed,
                         std::string{transport_error_message(listening.error())}});
        }
      }
      tcp_carrier_ = std::make_unique<TcpCarrier>(tcp_, far, dials, partner->preshared);
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
      // add_path makes the first path added the active one, and the fallbacks
      // were added first. The selector has to agree with the carrier actually
      // installed or its very first evaluation reads the wrong path's health.
      paths_.set_active(TransportKind::udp);
      automatic_fallback_ = true;
      last_path_check_ = std::chrono::steady_clock::now();
    }
  }

  worker_ = std::make_unique<Worker>(tun_, *carrier_, routes_, sessions_);

  worker_->set_echo_responder(
      [this](PeerId peer, std::span<const std::byte> token) { answer_echo(peer, token); });
  worker_->set_echo_reply_handler(
      [this](PeerId peer, std::span<const std::byte> token) { note_echo_reply(peer, token); });

  if (config.fec != FecMode::off) {
    worker_->enable_fec(config.fec);
  }

  if (config.qos_enabled) {
    worker_->enable_queueing(static_cast<double>(config.qos_rate_bytes),
                             config.qos_burst_bytes, std::chrono::steady_clock::now());

    // The configured rate is the ceiling an operator asked for, and the
    // starting point. Congestion control moves the actual rate below it when
    // the path says so, and never above it.
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
  if (config->fec != worker_->fec_mode()) {
    return std::unexpected(Diagnostic{RuntimeError::option_not_implemented,
                                      "fec.mode cannot change on reload: the peer would still be "
                                      "framing symbols the old way"});
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

  // Handshakes travel over whichever carrier is active. Writing to the raw UDP
  // socket instead would work only when UDP is the carrier, and silently send
  // into nowhere when it is not.
  static_cast<void>(carrier_->send_batch(batch));
}

void Runtime::send_control(PeerId peer, std::span<const std::byte> payload) {
  auto* session = sessions_.find_by_peer(peer);
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
  // The keepalive doubles as an echo request. A separate probe would be one
  // more thing on the wire measuring itself; this measures the path that
  // traffic actually takes, on a packet that was being sent anyway.
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

  // A token that did not come from this process, or one from before a clock
  // adjustment, would read as a nonsensical round trip. Those are dropped
  // rather than smeared into the estimate.
  if (elapsed.count() <= 0 || elapsed > kMaximumPlausibleRtt) return;

  last_rtt_ = elapsed;
  static_cast<void>(peer);
}

void Runtime::service_tcp_carrier(Instant now) {
  if (active_kind_ != TransportKind::tcp_tls) return;

  const auto was_ready = tcp_ready_;

  if (tcp_listener_.listening() && !tcp_.connected() &&
      tcp_.state() != TcpState::connecting) {
    auto incoming = tcp_listener_.accept();
    if (incoming && incoming->has_value()) {
      tcp_ = std::move(**incoming);
    }
  }

  auto* tcp_carrier = dynamic_cast<TcpCarrier*>(carrier_);
  if (tcp_carrier == nullptr) return;

  tcp_carrier->poll(now);
  tcp_ready_ = tcp_carrier->ready();

  // A TCP carrier has nowhere to send until the connection and its TLS
  // handshake are up, so the Noise handshake waits for that rather than being
  // dialled at startup and silently dropped.
  if (tcp_ready_ && !was_ready) {
    static_cast<void>(dial_configured_peers());
  }
}

void Runtime::service_quic_carrier() {
  if (active_kind_ != TransportKind::quic) return;

  auto* quic_carrier = dynamic_cast<QuicCarrier*>(carrier_);
  if (quic_carrier == nullptr) return;

  const auto was_ready = quic_ready_;
  quic_carrier->poll();
  quic_ready_ = quic_carrier->ready();

  // Nothing can be sent until QUIC itself is established, so the Noise
  // handshake waits for that rather than being dialled into a connection that
  // does not exist yet.
  if (quic_ready_ && !was_ready) {
    static_cast<void>(dial_configured_peers());
  }
}

void Runtime::apply_congestion_control(Instant now) {
  // Congestion control only has anything to act on when the datapath is
  // shaping. Without a queue there is no rate to lower and nothing to pace.
  if (!congestion_enabled_ || worker_ == nullptr || !worker_->queueing_enabled()) return;
  if (now - last_congestion_sample_ < kCongestionSampleInterval) return;

  // A round trip is the input the controller cannot do without: it separates
  // a queue that is filling from a path that is merely busy. Until the first
  // echo completes there is nothing honest to feed it.
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

  // A carrier that was just selected has not had time to connect: TCP has a
  // handshake and so does TLS, and QUIC has both. Judging it before it can
  // finish means abandoning it mid-handshake and moving to the next one, which
  // never settles anywhere. Nothing is evaluated during that window.
  if (switched_at_ != Instant{} && now - switched_at_ < kTransportSettleTime) return;

  if (now - last_path_check_ < kTransportCheckInterval) return;
  last_path_check_ = now;

  // A connection-oriented carrier that has not finished connecting is not
  // failing. TCP is still in connect or TLS, QUIC still in its handshake, and
  // neither can carry a Noise handshake yet. Judging them here would abandon
  // each one while it was still coming up.
  if (active_kind_ == TransportKind::tcp_tls && tcp_carrier_ != nullptr &&
      !tcp_carrier_->ready()) {
    return;
  }
  if (active_kind_ == TransportKind::quic && quic_carrier_ != nullptr &&
      !quic_carrier_->ready()) {
    return;
  }

  // Health comes from what the datapath already observes: whether a session is
  // still hearing from its peer, and whether the carrier is failing to send.
  // Inventing a probe would measure the probe.
  const auto& transport = carrier_->stats();
  const auto errors = transport.tx_errors + transport.rx_errors;
  const auto new_errors = errors > last_tx_errors_ ? errors - last_tx_errors_ : 0;
  last_tx_errors_ = errors;

  bool hearing = false;
  for (PeerId peer = 1; peer <= peer_count_; ++peer) {
    auto* session = sessions_.find_by_peer(peer);
    if (session == nullptr || !session->has_received()) continue;
    if (now - session->last_received() < kTransportSilenceTimeout) {
      hearing = true;
      break;
    }
  }

  // Retries are the other failure signal. A started handshake that never
  // completes looks identical to one still in flight, and dead-peer detection
  // removes the session before the started/completed gap ever opens - so the
  // count of retransmitted initiations is what actually distinguishes a
  // blocked path from an idle one.
  const auto& control = control_->stats();
  const auto attempted = control.handshakes_started;
  const auto retries = control.retries;
  const auto new_retries = retries > last_retries_ ? retries - last_retries_ : 0;
  last_retries_ = retries;
  const auto stalled = new_retries > 0;

  // Silence on its own is not failure: a tunnel with nothing to carry is
  // quiet, and condemning it would move a perfectly good carrier. A path is
  // judged broken only when something is actively failing on it - initiations
  // being retransmitted, or the carrier refusing to send. This is what keeps
  // an idle spoke from falling back off a working UDP path.
  const auto failing = stalled || new_errors > 0;
  const auto working = !failing;
  if (!failing && !hearing) return;
  // A path with no completed echo yet reports zero, which the thresholds treat
  // as the best possible RTT. That is the right reading for a path that has
  // not been measured: it is judged on whether it is carrying traffic, not on
  // a latency nobody has observed.
  const auto rtt_microseconds = static_cast<double>(
      std::chrono::duration_cast<std::chrono::microseconds>(last_rtt_).count());

  const PathSample sample{.rtt_microseconds = rtt_microseconds,
                          .loss_fraction = working ? 0.0 : 1.0,
                          .transport_errors = new_errors,
                          .reachable = working};
  paths_.observe(active_kind_, sample);

  // Nothing has been tried yet: a carrier with no traffic at all is not
  // failing, it is idle.
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
  // A fallback is the one event an operator is watching for, and stderr to a
  // file is block buffered: without this it is not visible until exit.
  std::fflush(stderr);

  // The peer is reached over a different carrier now, so the session it had is
  // useless: a new handshake establishes one over the path that works.
  for (PeerId peer = 1; peer <= peer_count_; ++peer) {
    auto* session = sessions_.find_by_peer(peer);
    if (session != nullptr) sessions_.remove(session->local_key_id());
  }
  static_cast<void>(dial_configured_peers());
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
    service_tcp_carrier(now);
    service_quic_carrier();
    apply_congestion_control(now);
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
