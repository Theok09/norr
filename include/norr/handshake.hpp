// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#pragma once

#include <cstdint>
#include <expected>

namespace norr {
enum class HandshakeRole { initiator, responder };
enum class HandshakeState {
  idle,
  init_sent,
  response_received,
  response_sent,
  confirm_sent,
  established,
  rekeying,
  closing,
  closed
};
enum class HandshakeMessage {
  none,
  init,
  response,
  confirm,
  rekey_init,
  rekey_ack,

  cookie_reply
};
enum class HandshakeError {
  invalid_role,
  invalid_transition,
  unauthenticated_message,
  generation_exhausted
};

using KeyGeneration = std::uint32_t;
inline constexpr KeyGeneration kMaximumKeyGeneration = 0xFFFF'FFFFU;

class HandshakeMachine {
 public:
  explicit HandshakeMachine(HandshakeRole role) noexcept : role_(role) {}

  [[nodiscard]] std::expected<HandshakeMessage, HandshakeError> start() noexcept;
  [[nodiscard]] std::expected<HandshakeMessage, HandshakeError> receive(
      HandshakeMessage message, bool authenticated) noexcept;
  [[nodiscard]] std::expected<HandshakeMessage, HandshakeError> send_confirm() noexcept;

  [[nodiscard]] std::expected<HandshakeMessage, HandshakeError> start_rekey() noexcept;

  void close() noexcept { state_ = HandshakeState::closed; }
  void begin_close() noexcept { state_ = HandshakeState::closing; }

  [[nodiscard]] HandshakeState state() const noexcept { return state_; }
  [[nodiscard]] KeyGeneration generation() const noexcept { return generation_; }

 private:
  HandshakeRole role_;
  HandshakeState state_{HandshakeState::idle};
  KeyGeneration generation_{};
};

}
