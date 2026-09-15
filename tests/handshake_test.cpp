#include <algorithm>
#include <array>
#include "check.hpp"

#include "norr/capability.hpp"
#include "norr/handshake.hpp"
#include "norr/handshake_frame.hpp"

int main() {
  const norr::CapabilityOffer local{.version = {.major = 1, .minor = 2},
                                    .supported = norr::capability_mask(norr::Capability::ipv6) | norr::capability_mask(norr::Capability::udp_batching),
                                    .required = norr::capability_mask(norr::Capability::ipv6)};
  const norr::CapabilityOffer peer{.version = {.major = 1, .minor = 1},
                                   .supported = norr::capability_mask(norr::Capability::ipv6),
                                   .required = 0};
  const auto negotiated = norr::negotiate_capabilities(local, peer);
  NORR_CHECK(negotiated.has_value() && negotiated->version.minor == 1 && negotiated->enabled == norr::capability_mask(norr::Capability::ipv6));
  const auto incompatible = norr::negotiate_capabilities(local, {.version = {.major = 2, .minor = 0}});
  NORR_CHECK(!incompatible.has_value() && incompatible.error() == norr::NegotiationError::major_version_mismatch);

  constexpr std::array noise_payload{std::byte{0xA1}, std::byte{0xB2}};
  const auto frame = norr::serialize_handshake_frame(norr::HandshakeMessage::init, noise_payload);
  NORR_CHECK(frame.has_value());
  constexpr std::array expected_frame{std::byte{1}, std::byte{1}, std::byte{0}, std::byte{2}, std::byte{0xA1}, std::byte{0xB2}};
  NORR_CHECK(frame->size() == expected_frame.size() && std::ranges::equal(*frame, expected_frame));
  const auto decoded_frame = norr::parse_handshake_frame(*frame);
  NORR_CHECK(decoded_frame.has_value() && decoded_frame->message == norr::HandshakeMessage::init && decoded_frame->noise_message.size() == noise_payload.size());

  // The rekey pair has a wire encoding; the `none` sentinel does not.
  constexpr std::array rekey_payload{std::byte{0xC3}};
  const auto rekey_frame = norr::serialize_handshake_frame(norr::HandshakeMessage::rekey_init, rekey_payload);
  NORR_CHECK(rekey_frame.has_value() && (*rekey_frame)[0] == std::byte{4});
  const auto rekey_decoded = norr::parse_handshake_frame(*rekey_frame);
  NORR_CHECK(rekey_decoded.has_value() && rekey_decoded->message == norr::HandshakeMessage::rekey_init);
  const auto ack_frame = norr::serialize_handshake_frame(norr::HandshakeMessage::rekey_ack, rekey_payload);
  NORR_CHECK(ack_frame.has_value() && (*ack_frame)[0] == std::byte{5});
  NORR_CHECK(!norr::serialize_handshake_frame(norr::HandshakeMessage::none, rekey_payload).has_value());
  constexpr std::array sentinel_on_wire{std::byte{0}, std::byte{1}, std::byte{0}, std::byte{0}};
  NORR_CHECK(!norr::parse_handshake_frame(sentinel_on_wire).has_value());

  norr::HandshakeMachine initiator{norr::HandshakeRole::initiator};
  norr::HandshakeMachine responder{norr::HandshakeRole::responder};

  NORR_CHECK(*initiator.start() == norr::HandshakeMessage::init);
  NORR_CHECK(initiator.state() == norr::HandshakeState::init_sent);
  const auto response = responder.receive(norr::HandshakeMessage::init, true);
  NORR_CHECK(response.has_value() && *response == norr::HandshakeMessage::response);
  const auto confirm_request = initiator.receive(*response, true);
  NORR_CHECK(confirm_request.has_value() && *confirm_request == norr::HandshakeMessage::confirm);

  // CONFIRM_SENT is observable: the initiator has sent CONFIRM but is not yet
  // established, because the responder has not proven it installed the session.
  const auto confirm = initiator.send_confirm();
  NORR_CHECK(confirm.has_value());
  NORR_CHECK(initiator.state() == norr::HandshakeState::confirm_sent);

  const auto accepted = responder.receive(*confirm, true);
  NORR_CHECK(accepted.has_value() && *accepted == norr::HandshakeMessage::none && responder.state() == norr::HandshakeState::established);

  NORR_CHECK(initiator.receive(norr::HandshakeMessage::none, true).has_value());
  NORR_CHECK(initiator.state() == norr::HandshakeState::established);
  NORR_CHECK(initiator.generation() == 0 && responder.generation() == 0);

  // Rekey advances the key generation only once the exchange completes.
  const auto rekey = initiator.start_rekey();
  NORR_CHECK(rekey.has_value() && *rekey == norr::HandshakeMessage::rekey_init);
  NORR_CHECK(initiator.state() == norr::HandshakeState::rekeying);
  NORR_CHECK(initiator.generation() == 0);

  const auto rekey_ack = responder.receive(norr::HandshakeMessage::rekey_init, true);
  NORR_CHECK(rekey_ack.has_value() && *rekey_ack == norr::HandshakeMessage::rekey_ack);
  NORR_CHECK(responder.state() == norr::HandshakeState::rekeying);

  NORR_CHECK(initiator.receive(norr::HandshakeMessage::rekey_ack, true).has_value());
  NORR_CHECK(initiator.state() == norr::HandshakeState::established && initiator.generation() == 1);
  NORR_CHECK(responder.receive(norr::HandshakeMessage::none, true).has_value());
  NORR_CHECK(responder.state() == norr::HandshakeState::established && responder.generation() == 1);

  // A rekey is only valid from ESTABLISHED.
  norr::HandshakeMachine fresh{norr::HandshakeRole::initiator};
  const auto premature = fresh.start_rekey();
  NORR_CHECK(!premature.has_value() && premature.error() == norr::HandshakeError::invalid_transition);

  // Unauthenticated messages never move the state machine.
  norr::HandshakeMachine rejected{norr::HandshakeRole::responder};
  const auto unauthenticated = rejected.receive(norr::HandshakeMessage::init, false);
  NORR_CHECK(!unauthenticated.has_value());
  NORR_CHECK(unauthenticated.error() == norr::HandshakeError::unauthenticated_message);
  NORR_CHECK(rejected.state() == norr::HandshakeState::idle);

  // Lifecycle terminals.
  norr::HandshakeMachine closing{norr::HandshakeRole::responder};
  closing.begin_close();
  NORR_CHECK(closing.state() == norr::HandshakeState::closing);
  closing.close();
  NORR_CHECK(closing.state() == norr::HandshakeState::closed);
  NORR_CHECK(!closing.receive(norr::HandshakeMessage::init, true).has_value());
}
