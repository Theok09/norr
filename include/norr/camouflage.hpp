// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "norr/reality.hpp"

namespace norr {
inline constexpr std::size_t kTlsRecordHeaderSize = 5;
inline constexpr std::size_t kTlsMaxRecordPayload = 16384;
inline constexpr std::size_t kTlsRandomSize = 32;
inline constexpr std::size_t kTlsSessionIdSize = 32;

enum class TlsRecordType : std::uint8_t {
  change_cipher_spec = 20,
  alert = 21,
  handshake = 22,
  application_data = 23,
};

enum class CamouflageError {
  need_more,
  malformed,
  oversized,
  buffer_too_small,
};

[[nodiscard]] constexpr std::string_view camouflage_error_message(
    CamouflageError error) noexcept {
  switch (error) {
    case CamouflageError::need_more: return "incomplete record";
    case CamouflageError::malformed: return "malformed TLS record";
    case CamouflageError::oversized: return "record exceeds TLS limit";
    case CamouflageError::buffer_too_small: return "output buffer too small";
  }
  return "unknown camouflage error";
}

struct TlsRecordView {
  TlsRecordType type{};
  std::span<const std::byte> payload;
  std::size_t consumed{};
};

[[nodiscard]] std::size_t write_record_header(TlsRecordType type, std::size_t length,
                                              std::span<std::byte> out) noexcept;

[[nodiscard]] std::expected<TlsRecordView, CamouflageError> parse_record(
    std::span<const std::byte> bytes) noexcept;

[[nodiscard]] std::vector<std::byte> build_client_hello(
    std::string_view server_name, std::span<const std::byte> key_share = {},
    std::span<const std::byte> session_id = {});

[[nodiscard]] std::vector<std::byte> build_server_hello(
    std::span<const std::byte> session_id = {});

[[nodiscard]] std::vector<std::byte> build_change_cipher_spec();

[[nodiscard]] bool looks_like_client_hello(std::span<const std::byte> bytes) noexcept;

class CamouflageFramer {
 public:
  enum class Role { client, server };

  explicit CamouflageFramer(Role role, std::string server_name = "www.microsoft.com") noexcept
      : role_(role), server_name_(std::move(server_name)) {}

  void configure_reality_client(const PublicKey& server_public,
                                const RealityShortId& short_id) {
    reality_enabled_ = true;
    reality_server_public_ = server_public;
    reality_short_id_ = short_id;
  }

  void configure_reality_server(const PrivateKey& server_private,
                                std::uint64_t window_seconds = 120) {
    reality_enabled_ = true;
    reality_server_private_ = server_private;
    reality_window_ = window_seconds;
  }

  [[nodiscard]] bool reality_enabled() const noexcept { return reality_enabled_; }
  [[nodiscard]] bool reality_authenticated() const noexcept { return reality_authenticated_; }
  [[nodiscard]] bool reality_rejected() const noexcept { return reality_rejected_; }

  [[nodiscard]] std::vector<std::byte> open();

  [[nodiscard]] bool handshake_done() const noexcept { return handshake_done_; }

  [[nodiscard]] std::vector<std::byte> wrap(std::span<const std::byte> payload) const;

  void feed(std::span<const std::byte> bytes);

  [[nodiscard]] std::expected<std::span<const std::byte>, CamouflageError> next_payload();

  [[nodiscard]] std::vector<std::byte> take_handshake_reply();

  [[nodiscard]] bool violated() const noexcept { return violated_; }

 private:
  void compact();

  Role role_;
  std::string server_name_;
  bool opened_{};
  bool handshake_done_{};
  bool sent_reply_{};
  bool violated_{};
  std::vector<std::byte> inbox_;
  std::size_t consumed_{};
  std::vector<std::byte> scratch_;
  std::vector<std::byte> pending_reply_;

  bool reality_enabled_{};
  bool reality_authenticated_{};
  bool reality_rejected_{};
  PublicKey reality_server_public_{};
  PrivateKey reality_server_private_{};
  RealityShortId reality_short_id_{};
  KeyPair reality_ephemeral_{};
  std::uint64_t reality_window_{120};
};
}
