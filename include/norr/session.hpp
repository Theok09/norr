// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <mutex>
#include <optional>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "norr/crypto.hpp"
#include "norr/endpoint.hpp"
#include "norr/nonce.hpp"
#include "norr/packet.hpp"
#include "norr/replay_window.hpp"
#include "norr/timers.hpp"
#include "norr/routing.hpp"

namespace norr {
enum class SessionError {
  unknown_peer,
  unknown_key_id,
  not_established,
  counter_exhausted,
  replayed,
  too_old,
  authentication_failed,
  buffer_too_small,
  key_id_exhausted,
  too_many_sessions,
  generation_mismatch,
};

[[nodiscard]] constexpr std::string_view session_error_message(SessionError error) noexcept {
  switch (error) {
    case SessionError::unknown_peer: return "unknown peer";
    case SessionError::unknown_key_id: return "no session for key id";
    case SessionError::not_established: return "session not established";
    case SessionError::counter_exhausted: return "send counter exhausted; rekey required";
    case SessionError::replayed: return "packet already seen";
    case SessionError::too_old: return "packet counter below the replay window";
    case SessionError::authentication_failed: return "authentication failed";
    case SessionError::buffer_too_small: return "output buffer too small";
    case SessionError::key_id_exhausted: return "no free key id";
    case SessionError::too_many_sessions: return "session limit reached";
    case SessionError::generation_mismatch: return "key generation mismatch";
  }
  return "unknown session error";
}

struct SessionStats {
  std::uint64_t sent{};
  std::uint64_t received{};
  std::uint64_t replay_drops{};
  std::uint64_t auth_failures{};
  std::uint64_t too_old_drops{};
};

class Session {
 public:
  Session(PeerId peer, std::uint16_t local_key_id, std::uint16_t remote_key_id,
          TrafficKeys send_keys, TrafficKeys receive_keys) noexcept;

  Session(const Session&) = delete;
  Session& operator=(const Session&) = delete;
  Session(Session&&) noexcept = default;
  Session& operator=(Session&&) noexcept = default;

  [[nodiscard]] PeerId peer() const noexcept { return peer_; }

  [[nodiscard]] std::uint16_t local_key_id() const noexcept { return local_key_id_; }

  [[nodiscard]] std::uint16_t remote_key_id() const noexcept { return remote_key_id_; }

  [[nodiscard]] KeyGeneration generation() const noexcept { return send_keys_.generation(); }

  [[nodiscard]] const std::optional<Endpoint>& endpoint() const noexcept { return endpoint_; }

  void note_authenticated_endpoint(const Endpoint& endpoint) { endpoint_ = endpoint; }

  [[nodiscard]] std::expected<std::size_t, SessionError> seal(FrameType type,
                                                              std::span<const std::byte> plaintext,
                                                              std::span<std::byte> out);

  [[nodiscard]] std::expected<std::size_t, SessionError> open(const PacketView& view,
                                                              std::span<const std::byte> packet,
                                                              std::span<std::byte> out);

  [[nodiscard]] const SessionStats& stats() const noexcept { return stats_; }

  [[nodiscard]] Instant last_received() const noexcept { return last_received_; }

  [[nodiscard]] bool has_received() const noexcept { return stats_.received > 0; }

  [[nodiscard]] Instant established_at() const noexcept { return established_at_; }

  [[nodiscard]] bool needs_rekey(Instant now) const noexcept {
    return stats_.sent >= kRekeyAfterMessages || now - established_at_ >= kRekeyAfter;
  }

  [[nodiscard]] bool expired(Instant now) const noexcept {
    return stats_.sent >= kRejectAfterMessages || now - established_at_ >= kSessionExpiry;
  }

 private:
  PeerId peer_{kNoPeer};
  std::uint16_t local_key_id_{};
  std::uint16_t remote_key_id_{};
  TrafficKeys send_keys_;
  TrafficKeys receive_keys_;
  PacketCounter send_counter_;
  ReplayWindow replay_;
  std::optional<Endpoint> endpoint_;
  Instant last_received_{};
  Instant established_at_{std::chrono::steady_clock::now()};
  SessionStats stats_{};

  std::unique_ptr<std::mutex> guard_{std::make_unique<std::mutex>()};
};

class SessionTable {
 public:

  static constexpr std::size_t kMaximumSessions = 1024;

  [[nodiscard]] std::expected<std::uint16_t, SessionError> allocate_key_id();

  [[nodiscard]] std::expected<std::shared_ptr<Session>, SessionError> install(
      PeerId peer, std::uint16_t local_key_id, std::uint16_t remote_key_id,
      TrafficKeys send_keys, TrafficKeys receive_keys);

  [[nodiscard]] std::expected<std::shared_ptr<Session>, SessionError> install(
      PeerId peer, std::uint16_t local_key_id, Session session);

  [[nodiscard]] std::shared_ptr<Session> find_by_key_id(std::uint16_t key_id) noexcept;

  [[nodiscard]] std::shared_ptr<Session> find_by_peer(PeerId peer) noexcept;

  void remove(std::uint16_t local_key_id) noexcept;

  void expire_retired(Instant now) noexcept;

  template <typename Visitor>
  void for_each(Visitor&& visitor) {
    for (auto& [key_id, session] : sessions_) {
      static_cast<void>(key_id);
      if (session) visitor(*session);
    }
  }

  [[nodiscard]] std::size_t size() const noexcept { return sessions_.size(); }

  [[nodiscard]] std::size_t retired() const noexcept { return retired_.size(); }

  [[nodiscard]] std::uint64_t retired_receives() const noexcept { return retired_receives_; }

 private:
  struct Retired {
    std::uint16_t key_id{};
    Instant retired_at{};
  };

  std::unordered_map<std::uint16_t, std::shared_ptr<Session>> sessions_;
  std::unordered_map<PeerId, std::uint16_t> by_peer_;
  std::vector<Retired> retired_;
  std::uint64_t retired_receives_{};
  std::uint16_t next_key_id_{1};
};

}
