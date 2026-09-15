#include "norr/tls.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>

#if defined(NORR_HAVE_GNUTLS)
#include <gnutls/gnutls.h>
#endif

namespace norr {
#if !defined(NORR_HAVE_GNUTLS)

struct TlsSession::Impl {};

bool tls_available() noexcept { return false; }

TlsSession::TlsSession() = default;
TlsSession::~TlsSession() = default;
TlsSession::TlsSession(TlsSession&&) noexcept = default;
TlsSession& TlsSession::operator=(TlsSession&&) noexcept = default;

std::expected<void, TlsError> TlsSession::start(int, TlsRole, std::string_view,
                                                std::span<const std::byte>) {
  return std::unexpected(TlsError::unsupported);
}

std::expected<bool, TlsError> TlsSession::handshake() {
  return std::unexpected(TlsError::unsupported);
}

std::expected<std::size_t, TlsError> TlsSession::send(std::span<const std::byte>) {
  return std::unexpected(TlsError::unsupported);
}

std::expected<std::size_t, TlsError> TlsSession::receive(std::span<std::byte>) {
  return std::unexpected(TlsError::unsupported);
}

void TlsSession::close() noexcept {}

std::string TlsSession::description() const { return "no TLS backend"; }

#else

namespace {
constexpr const char* kPriority = "NORMAL:-VERS-ALL:+VERS-TLS1.3:+ECDHE-PSK:+PSK";

constexpr std::size_t kMinimumPskBytes = 16;

}

struct TlsSession::Impl {
  gnutls_session_t session{};
  gnutls_psk_client_credentials_t client_credentials{};
  gnutls_psk_server_credentials_t server_credentials{};
  std::string identity;
  std::vector<std::byte> key;
  bool initialised{};

  ~Impl() {
    if (session != nullptr) gnutls_deinit(session);
    if (client_credentials != nullptr) gnutls_psk_free_client_credentials(client_credentials);
    if (server_credentials != nullptr) gnutls_psk_free_server_credentials(server_credentials);
  }
};

bool tls_available() noexcept { return true; }

TlsSession::TlsSession() = default;
TlsSession::~TlsSession() = default;
TlsSession::TlsSession(TlsSession&&) noexcept = default;
TlsSession& TlsSession::operator=(TlsSession&&) noexcept = default;

namespace {
int psk_server_callback(gnutls_session_t session, const char* username, gnutls_datum_t* key) {
  auto* impl = static_cast<TlsSession::Impl*>(gnutls_session_get_ptr(session));
  if (impl == nullptr || username == nullptr) return -1;
  if (impl->identity != username) return -1;

  key->size = static_cast<unsigned>(impl->key.size());
  key->data = static_cast<unsigned char*>(gnutls_malloc(key->size));
  if (key->data == nullptr) return -1;
  std::memcpy(key->data, impl->key.data(), impl->key.size());
  return 0;
}

}

std::expected<void, TlsError> TlsSession::start(int descriptor, TlsRole role,
                                                std::string_view identity,
                                                std::span<const std::byte> preshared_key) {
  if (identity.empty()) return std::unexpected(TlsError::bad_parameters);
  if (preshared_key.size() < kMinimumPskBytes) return std::unexpected(TlsError::bad_parameters);

  auto impl = std::make_unique<Impl>();
  impl->identity.assign(identity);
  impl->key.assign(preshared_key.begin(), preshared_key.end());

  const auto flags = role == TlsRole::client ? GNUTLS_CLIENT : GNUTLS_SERVER;
  if (gnutls_init(&impl->session, static_cast<unsigned>(flags) | GNUTLS_NONBLOCK) < 0) {
    return std::unexpected(TlsError::initialisation_failed);
  }

  const char* priority_error = nullptr;
  const auto priority = gnutls_priority_set_direct(impl->session, kPriority, &priority_error);
  if (priority < 0) {
    std::fprintf(stderr, "norr: TLS priority rejected (%s) near \"%s\"\n",
                 gnutls_strerror(priority), priority_error != nullptr ? priority_error : "?");
    return std::unexpected(TlsError::initialisation_failed);
  }

  if (role == TlsRole::client) {
    if (gnutls_psk_allocate_client_credentials(&impl->client_credentials) < 0) {
      return std::unexpected(TlsError::initialisation_failed);
    }
    const gnutls_datum_t key{
        .data = reinterpret_cast<unsigned char*>(impl->key.data()),
        .size = static_cast<unsigned>(impl->key.size()),
    };
    if (gnutls_psk_set_client_credentials(impl->client_credentials, impl->identity.c_str(), &key,
                                          GNUTLS_PSK_KEY_RAW) < 0) {
      return std::unexpected(TlsError::initialisation_failed);
    }
    if (gnutls_credentials_set(impl->session, GNUTLS_CRD_PSK, impl->client_credentials) < 0) {
      return std::unexpected(TlsError::initialisation_failed);
    }
  } else {
    if (gnutls_psk_allocate_server_credentials(&impl->server_credentials) < 0) {
      return std::unexpected(TlsError::initialisation_failed);
    }
    gnutls_psk_set_server_credentials_function(impl->server_credentials, psk_server_callback);
    if (gnutls_credentials_set(impl->session, GNUTLS_CRD_PSK, impl->server_credentials) < 0) {
      return std::unexpected(TlsError::initialisation_failed);
    }
  }

  gnutls_session_set_ptr(impl->session, impl.get());
  gnutls_transport_set_int(impl->session, descriptor);

  impl->initialised = true;
  impl_ = std::move(impl);
  established_ = false;
  return {};
}

std::expected<bool, TlsError> TlsSession::handshake() {
  if (impl_ == nullptr || !impl_->initialised) return std::unexpected(TlsError::unsupported);
  if (established_) return true;

  const auto result = gnutls_handshake(impl_->session);
  if (result == GNUTLS_E_SUCCESS) {
    established_ = true;
    return true;
  }

  if (result == GNUTLS_E_AGAIN || result == GNUTLS_E_INTERRUPTED) {
    return false;
  }
  return std::unexpected(TlsError::handshake_failed);
}

std::expected<std::size_t, TlsError> TlsSession::send(std::span<const std::byte> data) {
  if (!established_) return std::unexpected(TlsError::handshake_pending);

  const auto result = gnutls_record_send(impl_->session, data.data(), data.size());
  if (result >= 0) return static_cast<std::size_t>(result);
  if (result == GNUTLS_E_AGAIN || result == GNUTLS_E_INTERRUPTED) return std::size_t{0};
  return std::unexpected(TlsError::send_failed);
}

std::expected<std::size_t, TlsError> TlsSession::receive(std::span<std::byte> out) {
  if (!established_) return std::unexpected(TlsError::handshake_pending);

  const auto result = gnutls_record_recv(impl_->session, out.data(), out.size());
  if (result > 0) return static_cast<std::size_t>(result);
  if (result == 0) return std::unexpected(TlsError::closed);
  if (result == GNUTLS_E_AGAIN || result == GNUTLS_E_INTERRUPTED) return std::size_t{0};
  return std::unexpected(TlsError::receive_failed);
}

void TlsSession::close() noexcept {
  if (impl_ != nullptr && established_) {
    static_cast<void>(gnutls_bye(impl_->session, GNUTLS_SHUT_WR));
  }
  established_ = false;
  impl_.reset();
}

std::string TlsSession::description() const {
  if (impl_ == nullptr || !established_) return "not established";

  const auto* version = gnutls_protocol_get_name(gnutls_protocol_get_version(impl_->session));
  const auto* cipher = gnutls_cipher_get_name(gnutls_cipher_get(impl_->session));
  std::string out;
  out += version != nullptr ? version : "unknown";
  out += " ";
  out += cipher != nullptr ? cipher : "unknown";
  return out;
}

#endif

}
