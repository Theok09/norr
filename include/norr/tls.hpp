// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <string_view>
#include <vector>

#include "norr/noise.hpp"

namespace norr {
enum class TlsError {
  unsupported,
  initialisation_failed,
  handshake_failed,
  handshake_pending,
  closed,
  send_failed,
  receive_failed,
  bad_parameters,
};

[[nodiscard]] constexpr std::string_view tls_error_message(TlsError error) noexcept {
  switch (error) {
    case TlsError::unsupported: return "TLS backend not compiled in";
    case TlsError::initialisation_failed: return "TLS initialisation failed";
    case TlsError::handshake_failed: return "TLS handshake failed";
    case TlsError::handshake_pending: return "TLS handshake still in progress";
    case TlsError::closed: return "TLS session closed";
    case TlsError::send_failed: return "TLS send failed";
    case TlsError::receive_failed: return "TLS receive failed";
    case TlsError::bad_parameters: return "invalid TLS parameters";
  }
  return "unknown TLS error";
}

enum class TlsRole { client, server };

[[nodiscard]] bool tls_available() noexcept;

class TlsSession {
 public:

  TlsSession();
  ~TlsSession();

  TlsSession(const TlsSession&) = delete;
  TlsSession& operator=(const TlsSession&) = delete;
  TlsSession(TlsSession&&) noexcept;
  TlsSession& operator=(TlsSession&&) noexcept;

  [[nodiscard]] std::expected<void, TlsError> start(int descriptor, TlsRole role,
                                                    std::string_view identity,
                                                    std::span<const std::byte> preshared_key);

  [[nodiscard]] std::expected<bool, TlsError> handshake();

  [[nodiscard]] bool established() const noexcept { return established_; }

  [[nodiscard]] std::expected<std::size_t, TlsError> send(std::span<const std::byte> data);
  [[nodiscard]] std::expected<std::size_t, TlsError> receive(std::span<std::byte> out);

  void close() noexcept;

  [[nodiscard]] std::string description() const;

  struct Impl;

 private:
  std::unique_ptr<Impl> impl_;
  bool established_{};
};

}
