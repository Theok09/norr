// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#include "norr/quic_transport.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>

#include "norr/crypto.hpp"

#if defined(NORR_HAVE_NGTCP2)
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>
#endif

namespace norr {
bool quic_available() noexcept {
#if defined(NORR_HAVE_NGTCP2)
  return true;
#else
  return false;
#endif
}

#if defined(NORR_HAVE_NGTCP2)

std::string_view quic_backend_version() noexcept {
  const auto* info = ngtcp2_version(0);
  return info != nullptr ? info->version_str : "unknown";
}

#else

std::string_view quic_backend_version() noexcept { return "none"; }

#endif

std::expected<std::unique_ptr<QuicConnection>, QuicError> make_quic_connection() {
#if defined(NORR_HAVE_NGTCP2)
  return std::make_unique<Ngtcp2Connection>();
#else
  return std::unexpected(QuicError::unsupported);
#endif
}

#if defined(NORR_HAVE_NGTCP2)

namespace {
constexpr std::size_t kMinimumInitialDatagram = 1200;

constexpr std::string_view kAlpn = "norr/1";

constexpr std::uint64_t kDatagramFrameOverhead = 9;

constexpr std::uint64_t kQuicPacketOverhead = 48;

[[nodiscard]] ngtcp2_tstamp now_timestamp() noexcept {
  const auto now = std::chrono::steady_clock::now().time_since_epoch();
  return static_cast<ngtcp2_tstamp>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(now).count());
}

void fill_sockaddr(const Endpoint& endpoint, sockaddr_storage& storage, socklen_t& length) {
  std::memset(&storage, 0, sizeof(storage));
  const auto octets = endpoint.address().bytes();

  if (endpoint.family() == AddressFamily::ipv4) {
    auto* address = reinterpret_cast<sockaddr_in*>(&storage);
    address->sin_family = AF_INET;
    address->sin_port = htons(endpoint.port());
    std::memcpy(&address->sin_addr.s_addr, octets.data(), 4);
    length = sizeof(sockaddr_in);
    return;
  }
  auto* address = reinterpret_cast<sockaddr_in6*>(&storage);
  address->sin6_family = AF_INET6;
  address->sin6_port = htons(endpoint.port());
  std::memcpy(address->sin6_addr.s6_addr, octets.data(), 16);
  length = sizeof(sockaddr_in6);
}

void random_cid(ngtcp2_cid& cid, std::size_t length) {
  cid.datalen = length;
  static_cast<void>(random_bytes(
      std::span<std::byte>{reinterpret_cast<std::byte*>(cid.data), length}));
}

[[nodiscard]] bool install_raw_public_key(gnutls_certificate_credentials_t credentials) {
  gnutls_x509_privkey_t x509_key{};
  if (gnutls_x509_privkey_init(&x509_key) < 0) return false;

  bool ok = false;
  gnutls_datum_t private_der{};
  gnutls_datum_t spki{};
  gnutls_privkey_t abstract{};
  gnutls_pubkey_t pubkey{};

  if (gnutls_x509_privkey_generate(x509_key, GNUTLS_PK_EDDSA_ED25519,
                                   GNUTLS_CURVE_TO_BITS(GNUTLS_ECC_CURVE_ED25519), 0) >= 0 &&

      gnutls_x509_privkey_export2_pkcs8(x509_key, GNUTLS_X509_FMT_DER, nullptr, 0,
                                        &private_der) >= 0 &&
      gnutls_privkey_init(&abstract) >= 0 &&
      gnutls_privkey_import_x509(abstract, x509_key, 0) >= 0 &&
      gnutls_pubkey_init(&pubkey) >= 0 &&
      gnutls_pubkey_import_privkey(pubkey, abstract, GNUTLS_KEY_DIGITAL_SIGNATURE, 0) >= 0 &&
      gnutls_pubkey_export2(pubkey, GNUTLS_X509_FMT_DER, &spki) >= 0) {
    ok = gnutls_certificate_set_rawpk_key_mem(credentials, &spki, &private_der,
                                              GNUTLS_X509_FMT_DER, nullptr,
                                              GNUTLS_KEY_DIGITAL_SIGNATURE, nullptr, 0, 0) >= 0;
  }

  if (spki.data != nullptr) gnutls_free(spki.data);
  if (private_der.data != nullptr) gnutls_free(private_der.data);
  if (pubkey != nullptr) gnutls_pubkey_deinit(pubkey);
  if (abstract != nullptr) gnutls_privkey_deinit(abstract);
  gnutls_x509_privkey_deinit(x509_key);
  return ok;
}

}

struct Ngtcp2Connection::Impl {
  static constexpr std::size_t kMaximumQueuedDatagrams = 256;
  static constexpr std::size_t kMaximumPendingPackets = 256;

  ngtcp2_conn* conn{};
  gnutls_session_t tls{};
  gnutls_certificate_credentials_t credentials{};
  ngtcp2_crypto_conn_ref conn_ref{};

  sockaddr_storage local_address{};
  socklen_t local_length{};
  sockaddr_storage remote_address{};
  socklen_t remote_length{};

  bool handshake_done{};

  std::vector<std::byte> scratch = std::vector<std::byte>(kMinimumInitialDatagram * 2);

  std::vector<std::vector<std::byte>> pending;

  std::vector<std::byte> held;
  std::vector<std::vector<std::byte>> received;
  std::vector<std::vector<std::byte>> ready;
  QuicStats stats{};

  ~Impl() {
    if (conn != nullptr) ngtcp2_conn_del(conn);
    if (tls != nullptr) gnutls_deinit(tls);
    if (credentials != nullptr) gnutls_certificate_free_credentials(credentials);
  }
};

namespace {
ngtcp2_conn* conn_ref_callback(ngtcp2_crypto_conn_ref* ref) {
  return static_cast<Ngtcp2Connection::Impl*>(ref->user_data)->conn;
}

int on_handshake_completed(ngtcp2_conn*, void* user_data) {
  static_cast<Ngtcp2Connection::Impl*>(user_data)->handshake_done = true;
  return 0;
}

int on_receive_datagram(ngtcp2_conn*, uint32_t, const uint8_t* data, size_t datalen,
                        void* user_data) {
  auto* impl = static_cast<Ngtcp2Connection::Impl*>(user_data);

  if (impl->received.size() >= Ngtcp2Connection::Impl::kMaximumQueuedDatagrams) {
    ++impl->stats.datagrams_dropped;
    return 0;
  }

  const auto* bytes = reinterpret_cast<const std::byte*>(data);
  impl->received.emplace_back(bytes, bytes + datalen);
  ++impl->stats.datagrams_received;
  impl->stats.bytes_received += datalen;
  return 0;
}

void rand_callback(uint8_t* dest, size_t destlen, const ngtcp2_rand_ctx*) {
  static_cast<void>(random_bytes(
      std::span<std::byte>{reinterpret_cast<std::byte*>(dest), destlen}));
}

int get_new_connection_id(ngtcp2_conn*, ngtcp2_cid* cid, uint8_t* token, size_t cidlen,
                          void*) {
  random_cid(*cid, cidlen);
  static_cast<void>(random_bytes(
      std::span<std::byte>{reinterpret_cast<std::byte*>(token), NGTCP2_STATELESS_RESET_TOKENLEN}));
  return 0;
}

void fill_callbacks(ngtcp2_callbacks& callbacks) {
  std::memset(&callbacks, 0, sizeof(callbacks));
  callbacks.client_initial = ngtcp2_crypto_client_initial_cb;
  callbacks.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
  callbacks.handshake_completed = on_handshake_completed;
  callbacks.encrypt = ngtcp2_crypto_encrypt_cb;
  callbacks.decrypt = ngtcp2_crypto_decrypt_cb;
  callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb;
  callbacks.recv_retry = ngtcp2_crypto_recv_retry_cb;
  callbacks.update_key = ngtcp2_crypto_update_key_cb;
  callbacks.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
  callbacks.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
  callbacks.get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb;
  callbacks.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
  callbacks.recv_datagram = on_receive_datagram;
  callbacks.rand = rand_callback;
  callbacks.get_new_connection_id = get_new_connection_id;
}

}

Ngtcp2Connection::Ngtcp2Connection() : impl_(std::make_unique<Impl>()) {}
Ngtcp2Connection::~Ngtcp2Connection() = default;

std::expected<void, QuicError> Ngtcp2Connection::connect(const Endpoint& peer) {
  if (impl_->conn != nullptr) return std::unexpected(QuicError::already_connected);

  if (gnutls_init(&impl_->tls, GNUTLS_CLIENT | GNUTLS_ENABLE_RAWPK) < 0) {
    return std::unexpected(QuicError::handshake_failed);
  }
  if (gnutls_certificate_allocate_credentials(&impl_->credentials) < 0) {
    return std::unexpected(QuicError::handshake_failed);
  }
  if (gnutls_credentials_set(impl_->tls, GNUTLS_CRD_CERTIFICATE, impl_->credentials) < 0) {
    return std::unexpected(QuicError::handshake_failed);
  }

  impl_->conn_ref.get_conn = conn_ref_callback;
  impl_->conn_ref.user_data = impl_.get();
  gnutls_session_set_ptr(impl_->tls, &impl_->conn_ref);

  if (ngtcp2_crypto_gnutls_configure_client_session(impl_->tls) != 0) {
    return std::unexpected(QuicError::handshake_failed);
  }

  if (!install_raw_public_key(impl_->credentials)) {
    return std::unexpected(QuicError::handshake_failed);
  }

  if (gnutls_priority_set_direct(impl_->tls,
                                 "NORMAL:-VERS-ALL:+VERS-TLS1.3:+CTYPE-CLI-RAWPK:+CTYPE-SRV-RAWPK:"
                                 "%DISABLE_TLS13_COMPAT_MODE",
                                 nullptr) < 0) {
    return std::unexpected(QuicError::handshake_failed);
  }

  const gnutls_datum_t alpn{
      .data = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(kAlpn.data())),
      .size = static_cast<unsigned>(kAlpn.size()),
  };
  if (gnutls_alpn_set_protocols(impl_->tls, &alpn, 1, GNUTLS_ALPN_MANDATORY) < 0) {
    return std::unexpected(QuicError::handshake_failed);
  }

  const auto host = peer.address().to_string();
  static_cast<void>(gnutls_server_name_set(impl_->tls, GNUTLS_NAME_DNS, host.data(), host.size()));

  ngtcp2_cid scid{};
  ngtcp2_cid dcid{};
  random_cid(scid, 16);
  random_cid(dcid, 16);

  Endpoint local{peer.address(), 0};
  fill_sockaddr(local, impl_->local_address, impl_->local_length);
  fill_sockaddr(peer, impl_->remote_address, impl_->remote_length);

  ngtcp2_path path{};
  path.local.addr = reinterpret_cast<ngtcp2_sockaddr*>(&impl_->local_address);
  path.local.addrlen = impl_->local_length;
  path.remote.addr = reinterpret_cast<ngtcp2_sockaddr*>(&impl_->remote_address);
  path.remote.addrlen = impl_->remote_length;

  ngtcp2_settings settings{};
  ngtcp2_settings_default(&settings);
  settings.initial_ts = now_timestamp();

  ngtcp2_transport_params params{};
  ngtcp2_transport_params_default(&params);

  params.max_datagram_frame_size = kMaxDatagramFrame;
  params.initial_max_data = 1024 * 1024;

  ngtcp2_callbacks callbacks{};
  fill_callbacks(callbacks);

  const auto result = ngtcp2_conn_client_new(&impl_->conn, &dcid, &scid, &path,
                                             NGTCP2_PROTO_VER_V1, &callbacks, &settings, &params,
                                             nullptr, impl_.get());
  if (result != 0) return std::unexpected(QuicError::handshake_failed);

  ngtcp2_conn_set_tls_native_handle(impl_->conn, impl_->tls);
  ++impl_->stats.handshakes;
  return {};
}

bool Ngtcp2Connection::established() const noexcept { return impl_->handshake_done; }

void Ngtcp2Connection::close() noexcept {
  if (impl_->conn != nullptr) {
    ngtcp2_conn_del(impl_->conn);
    impl_->conn = nullptr;
  }
  impl_->handshake_done = false;
}

std::size_t Ngtcp2Connection::max_datagram_size() const noexcept {
  if (impl_->conn == nullptr) return 0;

  const auto* remote = ngtcp2_conn_get_remote_transport_params(impl_->conn);
  if (remote == nullptr || remote->max_datagram_frame_size == 0) return 0;

  const auto overhead = kDatagramFrameOverhead + kQuicPacketOverhead;

  const auto advertised = remote->max_datagram_frame_size;
  const auto by_peer = advertised > overhead ? advertised - overhead : 0;

  const auto path_limit = ngtcp2_conn_get_max_tx_udp_payload_size(impl_->conn);
  const auto by_path = path_limit > overhead ? path_limit - overhead : 0;

  return std::min(static_cast<std::size_t>(by_peer), static_cast<std::size_t>(by_path));
}

const QuicStats& Ngtcp2Connection::stats() const noexcept { return impl_->stats; }

std::expected<std::size_t, QuicError> Ngtcp2Connection::send_datagram(
    std::span<const std::byte> payload) {
  if (impl_->conn == nullptr) return std::unexpected(QuicError::not_connected);
  if (!impl_->handshake_done) return std::unexpected(QuicError::not_connected);

  const auto limit = max_datagram_size();
  if (limit == 0 || payload.size() > limit) {
    ++impl_->stats.datagrams_dropped;
    return std::unexpected(QuicError::datagram_too_large);
  }

  if (impl_->pending.size() >= Impl::kMaximumPendingPackets) {
    ++impl_->stats.datagrams_dropped;
    return std::unexpected(QuicError::send_failed);
  }

  ngtcp2_vec vec{};
  vec.base = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(payload.data()));
  vec.len = payload.size();

  ngtcp2_path_storage path{};
  ngtcp2_path_storage_zero(&path);
  int accepted = 0;

  const auto written = ngtcp2_conn_writev_datagram(
      impl_->conn, &path.path, nullptr, reinterpret_cast<uint8_t*>(impl_->scratch.data()),
      impl_->scratch.size(), &accepted, NGTCP2_WRITE_DATAGRAM_FLAG_NONE, 0, &vec, 1,
      now_timestamp());

  if (written < 0) return std::unexpected(QuicError::send_failed);
  if (accepted == 0) return std::unexpected(QuicError::send_failed);

  impl_->pending.emplace_back(impl_->scratch.begin(),
                              impl_->scratch.begin() + static_cast<std::ptrdiff_t>(written));

  ++impl_->stats.datagrams_sent;
  impl_->stats.bytes_sent += payload.size();
  return payload.size();
}

std::expected<void, QuicError> Ngtcp2Connection::feed(std::span<const std::byte> datagram) {
  if (impl_->conn == nullptr) return std::unexpected(QuicError::not_connected);

  ngtcp2_path path{};
  path.local.addr = reinterpret_cast<ngtcp2_sockaddr*>(&impl_->local_address);
  path.local.addrlen = impl_->local_length;
  path.remote.addr = reinterpret_cast<ngtcp2_sockaddr*>(&impl_->remote_address);
  path.remote.addrlen = impl_->remote_length;

  ngtcp2_pkt_info info{};
  const auto result = ngtcp2_conn_read_pkt(
      impl_->conn, &path, &info, reinterpret_cast<const uint8_t*>(datagram.data()),
      datagram.size(), now_timestamp());

  if (result != 0) {
    std::fprintf(stderr, "norr: ngtcp2 read_pkt failed: %s\n",
                 ngtcp2_strerror(static_cast<int>(result)));
    return std::unexpected(QuicError::receive_failed);
  }
  return {};
}

std::span<const std::byte> Ngtcp2Connection::next_outgoing() {
  if (impl_->conn == nullptr) return {};

  if (!impl_->pending.empty()) {
    impl_->held = std::move(impl_->pending.front());
    impl_->pending.erase(impl_->pending.begin());
    return std::span<const std::byte>{impl_->held};
  }

  ngtcp2_path_storage path{};
  ngtcp2_path_storage_zero(&path);
  ngtcp2_pkt_info info{};

  const auto written = ngtcp2_conn_write_pkt(
      impl_->conn, &path.path, &info, reinterpret_cast<uint8_t*>(impl_->scratch.data()),
      impl_->scratch.size(), now_timestamp());

  if (written < 0) {
    std::fprintf(stderr, "norr: ngtcp2 write_pkt failed: %s\n",
                 ngtcp2_strerror(static_cast<int>(written)));
    return {};
  }
  if (written == 0) return {};
  return std::span<const std::byte>{impl_->scratch.data(), static_cast<std::size_t>(written)};
}

std::expected<std::size_t, QuicError> Ngtcp2Connection::receive_datagrams(
    std::span<std::span<const std::byte>> out) {
  if (impl_->conn == nullptr) return std::unexpected(QuicError::not_connected);
  if (out.empty() || impl_->received.empty()) return std::size_t{0};

  const auto count = std::min(out.size(), impl_->received.size());
  impl_->ready.assign(std::make_move_iterator(impl_->received.begin()),
                      std::make_move_iterator(impl_->received.begin() +
                                              static_cast<std::ptrdiff_t>(count)));
  impl_->received.erase(impl_->received.begin(),
                        impl_->received.begin() + static_cast<std::ptrdiff_t>(count));

  for (std::size_t index = 0; index < count; ++index) out[index] = impl_->ready[index];
  return count;
}

std::expected<void, QuicError> Ngtcp2Connection::accept(const Endpoint& local,
                                                        const Endpoint& peer,
                                                        std::span<const std::byte> initial) {
  if (impl_->conn != nullptr) return std::unexpected(QuicError::already_connected);

  ngtcp2_pkt_hd header{};
  const auto parsed = ngtcp2_accept(&header,
                                    reinterpret_cast<const uint8_t*>(initial.data()),
                                    initial.size());
  if (parsed != 0) return std::unexpected(QuicError::handshake_failed);

  if (gnutls_init(&impl_->tls, GNUTLS_SERVER | GNUTLS_ENABLE_RAWPK) < 0) {
    return std::unexpected(QuicError::handshake_failed);
  }
  if (gnutls_certificate_allocate_credentials(&impl_->credentials) < 0) {
    return std::unexpected(QuicError::handshake_failed);
  }
  if (gnutls_credentials_set(impl_->tls, GNUTLS_CRD_CERTIFICATE, impl_->credentials) < 0) {
    return std::unexpected(QuicError::handshake_failed);
  }

  impl_->conn_ref.get_conn = conn_ref_callback;
  impl_->conn_ref.user_data = impl_.get();
  gnutls_session_set_ptr(impl_->tls, &impl_->conn_ref);

  if (ngtcp2_crypto_gnutls_configure_server_session(impl_->tls) != 0) {
    return std::unexpected(QuicError::handshake_failed);
  }

  if (!install_raw_public_key(impl_->credentials)) {
    return std::unexpected(QuicError::handshake_failed);
  }

  if (gnutls_priority_set_direct(impl_->tls,
                                 "NORMAL:-VERS-ALL:+VERS-TLS1.3:+CTYPE-CLI-RAWPK:+CTYPE-SRV-RAWPK:"
                                 "%DISABLE_TLS13_COMPAT_MODE",
                                 nullptr) < 0) {
    return std::unexpected(QuicError::handshake_failed);
  }

  const gnutls_datum_t alpn{
      .data = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(kAlpn.data())),
      .size = static_cast<unsigned>(kAlpn.size()),
  };
  if (gnutls_alpn_set_protocols(impl_->tls, &alpn, 1, GNUTLS_ALPN_MANDATORY) < 0) {
    return std::unexpected(QuicError::handshake_failed);
  }

  fill_sockaddr(local, impl_->local_address, impl_->local_length);
  fill_sockaddr(peer, impl_->remote_address, impl_->remote_length);

  ngtcp2_path path{};
  path.local.addr = reinterpret_cast<ngtcp2_sockaddr*>(&impl_->local_address);
  path.local.addrlen = impl_->local_length;
  path.remote.addr = reinterpret_cast<ngtcp2_sockaddr*>(&impl_->remote_address);
  path.remote.addrlen = impl_->remote_length;

  ngtcp2_settings settings{};
  ngtcp2_settings_default(&settings);
  settings.initial_ts = now_timestamp();

  ngtcp2_transport_params params{};
  ngtcp2_transport_params_default(&params);
  params.max_datagram_frame_size = kMaxDatagramFrame;
  params.initial_max_data = 1024 * 1024;

  params.original_dcid = header.dcid;

  ngtcp2_callbacks callbacks{};
  fill_callbacks(callbacks);

  callbacks.client_initial = nullptr;
  callbacks.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;

  const auto result = ngtcp2_conn_server_new(&impl_->conn, &header.scid, &header.dcid, &path,
                                             header.version, &callbacks, &settings, &params,
                                             nullptr, impl_.get());
  if (result != 0) return std::unexpected(QuicError::handshake_failed);

  ngtcp2_conn_set_tls_native_handle(impl_->conn, impl_->tls);

  ++impl_->stats.handshakes;

  return feed(initial);
}

#endif

std::expected<void, QuicError> LoopbackQuicConnection::connect(const Endpoint& peer) {
  if (established_) return std::unexpected(QuicError::already_connected);
  peer_ = peer;
  established_ = true;
  ++stats_.handshakes;
  return {};
}

void LoopbackQuicConnection::close() noexcept {
  established_ = false;
  inbox_.clear();
  ready_.clear();
}

std::expected<std::size_t, QuicError> LoopbackQuicConnection::send_datagram(
    std::span<const std::byte> payload) {
  if (!established_) return std::unexpected(QuicError::not_connected);

  if (payload.size() > kMaxDatagram) {
    ++stats_.datagrams_dropped;
    return std::unexpected(QuicError::datagram_too_large);
  }

  ++stats_.datagrams_sent;
  stats_.bytes_sent += payload.size();
  return payload.size();
}

void LoopbackQuicConnection::deliver(std::span<const std::byte> payload) {
  if (!established_) return;
  inbox_.emplace_back(payload.begin(), payload.end());
}

std::expected<std::size_t, QuicError> LoopbackQuicConnection::receive_datagrams(
    std::span<std::span<const std::byte>> out) {
  if (!established_) return std::unexpected(QuicError::not_connected);
  if (out.empty() || inbox_.empty()) return std::size_t{0};

  const auto count = std::min(out.size(), inbox_.size());

  ready_.assign(std::make_move_iterator(inbox_.begin()),
                std::make_move_iterator(inbox_.begin() + static_cast<std::ptrdiff_t>(count)));
  inbox_.erase(inbox_.begin(), inbox_.begin() + static_cast<std::ptrdiff_t>(count));

  for (std::size_t index = 0; index < count; ++index) {
    out[index] = ready_[index];
    stats_.bytes_received += ready_[index].size();
  }
  stats_.datagrams_received += count;
  return count;
}

}
