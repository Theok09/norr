#include "norr/handshake.hpp"

namespace norr {
std::expected<HandshakeMessage, HandshakeError> HandshakeMachine::start() noexcept {
  if (role_ != HandshakeRole::initiator) return std::unexpected(HandshakeError::invalid_role);
  if (state_ != HandshakeState::idle) return std::unexpected(HandshakeError::invalid_transition);
  state_ = HandshakeState::init_sent;
  return HandshakeMessage::init;
}

std::expected<HandshakeMessage, HandshakeError> HandshakeMachine::receive(
    HandshakeMessage message, bool authenticated) noexcept {
  if (!authenticated) return std::unexpected(HandshakeError::unauthenticated_message);

  if (role_ == HandshakeRole::initiator && state_ == HandshakeState::init_sent &&
      message == HandshakeMessage::response) {
    state_ = HandshakeState::response_received;
    return HandshakeMessage::confirm;
  }
  if (role_ == HandshakeRole::responder && state_ == HandshakeState::idle &&
      message == HandshakeMessage::init) {
    state_ = HandshakeState::response_sent;
    return HandshakeMessage::response;
  }
  if (role_ == HandshakeRole::responder && state_ == HandshakeState::response_sent &&
      message == HandshakeMessage::confirm) {
    state_ = HandshakeState::established;
    return HandshakeMessage::none;
  }

  if (role_ == HandshakeRole::initiator && state_ == HandshakeState::confirm_sent &&
      message == HandshakeMessage::none) {
    state_ = HandshakeState::established;
    return HandshakeMessage::none;
  }

  if (state_ == HandshakeState::established && message == HandshakeMessage::rekey_init) {
    if (generation_ == kMaximumKeyGeneration) {
      return std::unexpected(HandshakeError::generation_exhausted);
    }
    state_ = HandshakeState::rekeying;
    return HandshakeMessage::rekey_ack;
  }
  if (state_ == HandshakeState::rekeying && message == HandshakeMessage::rekey_ack) {
    ++generation_;
    state_ = HandshakeState::established;
    return HandshakeMessage::none;
  }
  if (state_ == HandshakeState::rekeying && message == HandshakeMessage::none) {
    ++generation_;
    state_ = HandshakeState::established;
    return HandshakeMessage::none;
  }

  return std::unexpected(HandshakeError::invalid_transition);
}

std::expected<HandshakeMessage, HandshakeError> HandshakeMachine::send_confirm() noexcept {
  if (role_ != HandshakeRole::initiator) return std::unexpected(HandshakeError::invalid_role);
  if (state_ != HandshakeState::response_received) {
    return std::unexpected(HandshakeError::invalid_transition);
  }

  state_ = HandshakeState::confirm_sent;
  return HandshakeMessage::confirm;
}

std::expected<HandshakeMessage, HandshakeError> HandshakeMachine::start_rekey() noexcept {
  if (state_ != HandshakeState::established) {
    return std::unexpected(HandshakeError::invalid_transition);
  }
  if (generation_ == kMaximumKeyGeneration) {
    return std::unexpected(HandshakeError::generation_exhausted);
  }
  state_ = HandshakeState::rekeying;
  return HandshakeMessage::rekey_init;
}

}
