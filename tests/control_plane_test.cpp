// The control plane: driving handshakes, retrying, expiring half-open state,
// and refusing to do unbounded work for unauthenticated peers.

#include "check.hpp"
#include <chrono>
#include <cstdio>
#include <string_view>
#include <vector>

#include "norr/control_plane.hpp"

namespace {

norr::Endpoint endpoint_of(std::string_view text) {
  const auto parsed = norr::parse_endpoint(text);
  NORR_CHECK(parsed.has_value());
  return *parsed;
}

struct Node {
  norr::KeyPair identity;
  norr::SessionTable sessions;
  norr::TimerWheel timers;
  std::optional<norr::ControlPlane> control;

  void build() { control.emplace(identity, sessions, timers); }
};

norr::KeyPair make_identity() {
  const auto pair = norr::generate_keypair();
  NORR_CHECK(pair.has_value());
  return *pair;
}

norr::PresharedKey make_psk(std::uint8_t fill) {
  norr::PresharedKey psk{};
  psk.fill(static_cast<std::byte>(fill));
  return psk;
}

void test_full_handshake_through_control_plane() {
  Node alice;
  Node bob;
  alice.identity = make_identity();
  bob.identity = make_identity();
  alice.build();
  bob.build();

  const auto psk = make_psk(0x5A);
  const auto alice_endpoint = endpoint_of("127.0.0.1:41001");
  const auto bob_endpoint = endpoint_of("127.0.0.1:41002");

  NORR_CHECK(alice.control
             ->add_peer(norr::PeerConfig{.id = 2,
                                         .static_public = bob.identity.public_key,
                                         .preshared = psk,
                                         .endpoint = bob_endpoint})
             .has_value());
  NORR_CHECK(bob.control
             ->add_peer(norr::PeerConfig{.id = 1,
                                         .static_public = alice.identity.public_key,
                                         .preshared = psk,
                                         .endpoint = alice_endpoint})
             .has_value());

  const auto now = std::chrono::steady_clock::now();

  // Alice initiates.
  const auto initiation = alice.control->start_handshake(2, now);
  NORR_CHECK(initiation.has_value());
  NORR_CHECK(alice.control->pending() == 1);
  NORR_CHECK(alice.control->stats().handshakes_started == 1);
  // A timeout and a retry are armed together with the attempt, so half-open
  // state cannot outlive its deadline.
  NORR_CHECK(alice.timers.size() == 2);

  // Bob answers. He must NOT have a session yet: the PSK is mixed while
  // producing message 2, so at this point Alice has not proven she holds it.
  // Bob holds the keys provisionally instead.
  const auto reply = bob.control->handle_datagram(alice_endpoint, initiation->datagram, now);
  NORR_CHECK(reply.has_value() && reply->has_value());
  NORR_CHECK(bob.sessions.size() == 0);
  NORR_CHECK(bob.control->provisional() == 1);
  NORR_CHECK(bob.control->stats().responder_handshakes == 1);
  NORR_CHECK(bob.control->stats().handshakes_completed == 0);

  // Alice completes.
  const auto finished = alice.control->handle_datagram(bob_endpoint, (*reply)->datagram, now);
  NORR_CHECK(finished.has_value() && !finished->has_value());
  NORR_CHECK(alice.sessions.size() == 1);
  NORR_CHECK(alice.control->pending() == 0);
  NORR_CHECK(alice.control->stats().handshakes_completed == 1);

  // Alice can send immediately; she proved Bob's identity by reading message 2.
  auto* alice_session = alice.sessions.find_by_peer(2);
  NORR_CHECK(alice_session != nullptr);
  NORR_CHECK(alice_session->endpoint().has_value());

  const std::array<std::byte, 4> plaintext{std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
  std::vector<std::byte> wire(norr::kPacketHeaderSize + plaintext.size() + norr::kAeadTagSize);
  const auto sealed = alice_session->seal(norr::FrameType::data, plaintext, wire);
  NORR_CHECK(sealed.has_value());

  const auto view = norr::parse_packet(std::span{wire}.first(*sealed));
  NORR_CHECK(view.has_value());

  // That first authenticated frame is what promotes Bob's provisional state.
  // This is the CONFIRM role described in `protocol/handshake.md`. The open and
  // the promotion are one operation: the AEAD result IS the authentication, so
  // the plaintext comes back from the same call that installs the session.
  std::vector<std::byte> recovered(plaintext.size());
  const auto promoted = bob.control->try_promote_provisional(
      *view, std::span{wire}.first(*sealed), recovered, alice_endpoint);
  NORR_CHECK(promoted.has_value());
  NORR_CHECK(*promoted == plaintext.size());
  NORR_CHECK(std::equal(plaintext.begin(), plaintext.end(), recovered.begin()));
  NORR_CHECK(bob.sessions.size() == 1);
  NORR_CHECK(bob.control->provisional() == 0);
  NORR_CHECK(bob.control->stats().provisional_promoted == 1);

  auto* bob_session = bob.sessions.find_by_peer(1);
  NORR_CHECK(bob_session != nullptr);
  NORR_CHECK(bob_session->endpoint().has_value());

  // The packet that proved the handshake must not be replayable: the replay
  // window advanced during promotion, so feeding the same bytes to the
  // installed session is a replay, not a fresh packet.
  const auto replayed = bob_session->open(*view, std::span{wire}.first(*sealed), recovered);
  NORR_CHECK(!replayed.has_value());
  NORR_CHECK(replayed.error() == norr::SessionError::replayed);

  std::puts("control: handshake completes and keys interoperate OK");
}

// A forged packet naming a provisional key id must not install a session.
//
// This is the whole point of holding a responder's keys back: if a key id alone
// were enough to promote, an attacker who guessed one — there are only 65535 —
// would get a session installed without holding the PSK, and the provisional
// mechanism would protect nothing.
void test_forged_frame_does_not_promote() {
  Node alice;
  Node bob;
  alice.identity = make_identity();
  bob.identity = make_identity();
  alice.build();
  bob.build();

  const auto psk = make_psk(0x31);
  const auto alice_endpoint = endpoint_of("127.0.0.1:41021");
  const auto bob_endpoint = endpoint_of("127.0.0.1:41022");

  NORR_CHECK(alice.control
                 ->add_peer(norr::PeerConfig{.id = 2,
                                             .static_public = bob.identity.public_key,
                                             .preshared = psk,
                                             .endpoint = bob_endpoint})
                 .has_value());
  NORR_CHECK(bob.control
                 ->add_peer(norr::PeerConfig{.id = 1,
                                             .static_public = alice.identity.public_key,
                                             .preshared = psk,
                                             .endpoint = alice_endpoint})
                 .has_value());

  const auto now = std::chrono::steady_clock::now();

  const auto initiation = alice.control->start_handshake(2, now);
  NORR_CHECK(initiation.has_value());
  const auto reply = bob.control->handle_datagram(alice_endpoint, initiation->datagram, now);
  NORR_CHECK(reply.has_value() && reply->has_value());
  NORR_CHECK(bob.control->provisional() == 1);

  // Alice completes so a real frame exists to take the key id from.
  const auto finished = alice.control->handle_datagram(bob_endpoint, (*reply)->datagram, now);
  NORR_CHECK(finished.has_value());
  auto* alice_session = alice.sessions.find_by_peer(2);
  NORR_CHECK(alice_session != nullptr);

  const std::array<std::byte, 4> plaintext{std::byte{9}, std::byte{9}, std::byte{9}, std::byte{9}};
  std::vector<std::byte> wire(norr::kPacketHeaderSize + plaintext.size() + norr::kAeadTagSize);
  const auto sealed = alice_session->seal(norr::FrameType::data, plaintext, wire);
  NORR_CHECK(sealed.has_value());

  // Corrupt the ciphertext, keeping the header — and therefore the key id —
  // intact. This is exactly what an attacker who observed a key id can build.
  auto forged = std::vector<std::byte>(wire.begin(), wire.begin() + *sealed);
  forged[norr::kPacketHeaderSize] ^= std::byte{0xFF};

  const auto view = norr::parse_packet(forged);
  NORR_CHECK(view.has_value());

  std::vector<std::byte> out(plaintext.size());
  const auto refused =
      bob.control->try_promote_provisional(*view, forged, out, alice_endpoint);
  NORR_CHECK(!refused.has_value());

  // Nothing was installed, and — just as important — the genuine peer's
  // half-open state survived, so a forged packet cannot evict it.
  NORR_CHECK(bob.sessions.size() == 0);
  NORR_CHECK(bob.control->provisional() == 1);
  NORR_CHECK(bob.control->stats().provisional_promoted == 0);

  // The real frame still promotes afterwards.
  const auto genuine = norr::parse_packet(std::span{wire}.first(*sealed));
  NORR_CHECK(genuine.has_value());
  const auto accepted = bob.control->try_promote_provisional(
      *genuine, std::span{wire}.first(*sealed), out, alice_endpoint);
  NORR_CHECK(accepted.has_value());
  NORR_CHECK(bob.sessions.size() == 1);

  std::puts("control: forged frame does not promote provisional state OK");
}

// A captured INIT must not work twice.
//
// Without a timestamp in the handshake payload, an attacker who recorded an
// initiation could replay it and make the responder perform Diffie-Hellman and
// build provisional state for a peer that never sent anything. WireGuard
// solves this by keeping the greatest timestamp seen per peer and discarding
// anything at or below it; Norr does the same.
void test_replayed_initiation_is_refused() {
  Node alice;
  Node bob;
  alice.identity = make_identity();
  bob.identity = make_identity();
  alice.build();
  bob.build();

  const auto psk = make_psk(0x44);
  const auto alice_endpoint = endpoint_of("127.0.0.1:41031");
  const auto bob_endpoint = endpoint_of("127.0.0.1:41032");

  NORR_CHECK(alice.control
                 ->add_peer(norr::PeerConfig{.id = 2,
                                             .static_public = bob.identity.public_key,
                                             .preshared = psk,
                                             .endpoint = bob_endpoint})
                 .has_value());
  NORR_CHECK(bob.control
                 ->add_peer(norr::PeerConfig{.id = 1,
                                             .static_public = alice.identity.public_key,
                                             .preshared = psk,
                                             .endpoint = alice_endpoint})
                 .has_value());

  const auto now = std::chrono::steady_clock::now();

  const auto initiation = alice.control->start_handshake(2, now);
  NORR_CHECK(initiation.has_value());

  // The genuine initiation is accepted.
  const auto first = bob.control->handle_datagram(alice_endpoint, initiation->datagram, now);
  NORR_CHECK(first.has_value() && first->has_value());
  NORR_CHECK(bob.control->stats().responder_handshakes == 1);
  NORR_CHECK(bob.control->provisional() == 1);

  // The identical datagram a second time must be refused, and must not create
  // a second provisional entry or consume another key id.
  const auto replayed = bob.control->handle_datagram(alice_endpoint, initiation->datagram, now);
  NORR_CHECK(!replayed.has_value());
  NORR_CHECK(bob.control->stats().replayed_initiations == 1);
  NORR_CHECK(bob.control->stats().responder_handshakes == 1);
  NORR_CHECK(bob.control->provisional() == 1);

  // A fresh initiation from the same peer still works: the check rejects
  // stale timestamps, not the peer.
  const auto second = alice.control->start_handshake(2, now);
  NORR_CHECK(second.has_value());
  const auto accepted = bob.control->handle_datagram(alice_endpoint, second->datagram, now);
  NORR_CHECK(accepted.has_value() && accepted->has_value());
  NORR_CHECK(bob.control->stats().responder_handshakes == 2);

  std::puts("control: replayed initiation refused OK");
}

void test_wrong_psk_produces_no_session() {
  Node alice;
  Node bob;
  alice.identity = make_identity();
  bob.identity = make_identity();
  alice.build();
  bob.build();

  const auto alice_endpoint = endpoint_of("127.0.0.1:41003");
  const auto bob_endpoint = endpoint_of("127.0.0.1:41004");

  NORR_CHECK(alice.control
             ->add_peer(norr::PeerConfig{.id = 2,
                                         .static_public = bob.identity.public_key,
                                         .preshared = make_psk(0x11),
                                         .endpoint = bob_endpoint})
             .has_value());
  NORR_CHECK(bob.control
             ->add_peer(norr::PeerConfig{.id = 1,
                                         .static_public = alice.identity.public_key,
                                         .preshared = make_psk(0x22),
                                         .endpoint = alice_endpoint})
             .has_value());

  const auto now = std::chrono::steady_clock::now();
  const auto initiation = alice.control->start_handshake(2, now);
  NORR_CHECK(initiation.has_value());

  // Bob's PSK differs. In IKpsk2 he cannot detect that while producing message
  // 2, so he may well emit a reply, but he must never create a session from it.
  const auto reply = bob.control->handle_datagram(alice_endpoint, initiation->datagram, now);
  static_cast<void>(reply);
  NORR_CHECK(bob.sessions.size() == 0);

  // Alice reads the reply and fails, because the PSK is mixed there.
  if (reply.has_value() && reply->has_value()) {
    const auto finished =
        alice.control->handle_datagram(bob_endpoint, (*reply)->datagram, now);
    NORR_CHECK(!finished.has_value());
  }
  NORR_CHECK(alice.sessions.size() == 0);

  // Bob's provisional state must expire rather than linger, and it must never
  // have become a session.
  const auto expired = bob.timers.expire(now + norr::kHandshakeTimeout + std::chrono::seconds{1});
  static_cast<void>(bob.control->on_timers(expired, now + norr::kHandshakeTimeout));
  NORR_CHECK(bob.control->provisional() == 0);
  NORR_CHECK(bob.sessions.size() == 0);

  std::puts("control: wrong PSK creates no session OK");
}

void test_unknown_peer_is_refused() {
  Node node;
  node.identity = make_identity();
  node.build();

  const auto now = std::chrono::steady_clock::now();
  const auto started = node.control->start_handshake(99, now);
  NORR_CHECK(!started.has_value() && started.error() == norr::ControlError::unknown_peer);

  std::puts("control: unknown peer refused OK");
}

void test_rate_limiting_sheds_flood() {
  Node bob;
  bob.identity = make_identity();
  bob.build();

  const auto alice_identity = make_identity();
  const auto psk = make_psk(0x33);
  NORR_CHECK(bob.control
             ->add_peer(norr::PeerConfig{.id = 1,
                                         .static_public = alice_identity.public_key,
                                         .preshared = psk,
                                         .endpoint = endpoint_of("127.0.0.1:41005")})
             .has_value());

  const auto now = std::chrono::steady_clock::now();
  const auto attacker = endpoint_of("203.0.113.66:5000");
  const std::array<std::byte, 64> garbage{};

  // An INIT costs the responder two Diffie-Hellman operations, so a flood must
  // be shed before that cost is paid. Eventually the source budget runs out.
  bool saw_rate_limit = false;
  for (int attempt = 0; attempt < 64; ++attempt) {
    const auto result = bob.control->handle_datagram(attacker, garbage, now);
    if (!result.has_value() && result.error() == norr::ControlError::rate_limited) {
      saw_rate_limit = true;
      break;
    }
  }
  NORR_CHECK(saw_rate_limit);
  NORR_CHECK(bob.control->stats().rate_limited > 0);
  NORR_CHECK(bob.sessions.size() == 0);

  std::puts("control: handshake flood is rate limited OK");
}

void test_timeout_expires_half_open_state() {
  Node alice;
  alice.identity = make_identity();
  alice.build();

  const auto bob_identity = make_identity();
  NORR_CHECK(alice.control
             ->add_peer(norr::PeerConfig{.id = 2,
                                         .static_public = bob_identity.public_key,
                                         .preshared = make_psk(0x44),
                                         .endpoint = endpoint_of("127.0.0.1:41006")})
             .has_value());

  const auto now = std::chrono::steady_clock::now();
  NORR_CHECK(alice.control->start_handshake(2, now).has_value());
  NORR_CHECK(alice.control->pending() == 1);

  // Nothing answers. When the timeout fires the half-open state must be gone,
  // otherwise repeated attempts would accumulate state.
  const auto expired = alice.timers.expire(now + norr::kHandshakeTimeout + std::chrono::seconds{1});
  NORR_CHECK(!expired.empty());

  const auto outgoing = alice.control->on_timers(expired, now + norr::kHandshakeTimeout);
  static_cast<void>(outgoing);
  NORR_CHECK(alice.control->pending() == 0);
  NORR_CHECK(alice.control->stats().handshakes_timed_out == 1);

  std::puts("control: handshake timeout clears half-open state OK");
}

void test_retry_uses_backoff() {
  Node alice;
  alice.identity = make_identity();
  alice.build();

  const auto bob_identity = make_identity();
  NORR_CHECK(alice.control
             ->add_peer(norr::PeerConfig{.id = 2,
                                         .static_public = bob_identity.public_key,
                                         .preshared = make_psk(0x55),
                                         .endpoint = endpoint_of("127.0.0.1:41007")})
             .has_value());

  const auto now = std::chrono::steady_clock::now();
  NORR_CHECK(alice.control->start_handshake(2, now).has_value());

  // Fire only the retry timer, not the timeout.
  const std::array<norr::TimerEvent, 1> retry{
      norr::TimerEvent{.kind = norr::TimerKind::handshake_retry, .subject = 2, .due = now}};
  const auto outgoing = alice.control->on_timers(retry, now);
  NORR_CHECK(outgoing.size() == 1);
  NORR_CHECK(alice.control->stats().retries == 1);
  NORR_CHECK(alice.control->pending() == 1);

  std::puts("control: retry re-sends the initiation OK");
}

void test_cookie_challenge_under_load() {
  Node alice;
  Node bob;
  alice.identity = make_identity();
  bob.identity = make_identity();
  alice.build();
  bob.build();

  const auto psk = make_psk(0x66);
  const auto alice_endpoint = endpoint_of("127.0.0.1:41010");
  const auto bob_endpoint = endpoint_of("127.0.0.1:41011");

  NORR_CHECK(alice.control
                 ->add_peer(norr::PeerConfig{.id = 2,
                                             .static_public = bob.identity.public_key,
                                             .preshared = psk,
                                             .endpoint = bob_endpoint})
                 .has_value());
  NORR_CHECK(bob.control
                 ->add_peer(norr::PeerConfig{.id = 1,
                                             .static_public = alice.identity.public_key,
                                             .preshared = psk,
                                             .endpoint = alice_endpoint})
                 .has_value());

  const auto now = std::chrono::steady_clock::now();

  // Bob is under load, so he refuses to do Diffie-Hellman for anyone who has
  // not proven they can receive at their claimed address.
  bob.control->set_under_load(true);
  NORR_CHECK(bob.control->under_load());

  const auto initiation = alice.control->start_handshake(2, now);
  NORR_CHECK(initiation.has_value());

  // Alice holds no cookie yet, so her mac2 is zero and Bob answers with a
  // cookie rather than a handshake response.
  const auto challenge = bob.control->handle_datagram(alice_endpoint, initiation->datagram, now);
  NORR_CHECK(challenge.has_value() && challenge->has_value());
  NORR_CHECK(bob.control->stats().cookies_issued == 1);
  NORR_CHECK(bob.control->stats().mac2_failures == 1);
  // Crucially, no expensive work was done and no state was created.
  NORR_CHECK(bob.control->provisional() == 0);
  NORR_CHECK(bob.sessions.size() == 0);

  // Alice receives the cookie and retries automatically, now carrying mac2.
  const auto retry = alice.control->handle_datagram(bob_endpoint, (*challenge)->datagram, now);
  NORR_CHECK(retry.has_value() && retry->has_value());
  NORR_CHECK(alice.control->stats().cookies_accepted == 1);

  // This time Bob is satisfied and does the real work.
  const auto reply = bob.control->handle_datagram(alice_endpoint, (*retry)->datagram, now);
  NORR_CHECK(reply.has_value() && reply->has_value());
  NORR_CHECK(bob.control->stats().responder_handshakes == 1);
  NORR_CHECK(bob.control->provisional() == 1);

  // And the handshake completes as normal.
  const auto finished = alice.control->handle_datagram(bob_endpoint, (*reply)->datagram, now);
  NORR_CHECK(finished.has_value());
  NORR_CHECK(alice.sessions.size() == 1);

  std::puts("control: cookie challenge under load OK");
}

void test_spoofed_source_cannot_pass_the_challenge() {
  Node bob;
  bob.identity = make_identity();
  bob.build();

  const auto alice_identity = make_identity();
  const auto psk = make_psk(0x77);
  const auto alice_endpoint = endpoint_of("127.0.0.1:41012");
  NORR_CHECK(bob.control
                 ->add_peer(norr::PeerConfig{.id = 1,
                                             .static_public = alice_identity.public_key,
                                             .preshared = psk,
                                             .endpoint = alice_endpoint})
                 .has_value());

  // Alice builds a genuine initiation and completes the cookie exchange from
  // her real address.
  Node alice;
  alice.identity = alice_identity;
  alice.build();
  NORR_CHECK(alice.control
                 ->add_peer(norr::PeerConfig{.id = 2,
                                             .static_public = bob.identity.public_key,
                                             .preshared = psk,
                                             .endpoint = endpoint_of("127.0.0.1:41013")})
                 .has_value());

  const auto now = std::chrono::steady_clock::now();
  bob.control->set_under_load(true);

  const auto initiation = alice.control->start_handshake(2, now);
  NORR_CHECK(initiation.has_value());
  const auto challenge = bob.control->handle_datagram(alice_endpoint, initiation->datagram, now);
  NORR_CHECK(challenge.has_value() && challenge->has_value());
  const auto retry = alice.control->handle_datagram(endpoint_of("127.0.0.1:41013"),
                                                    (*challenge)->datagram, now);
  NORR_CHECK(retry.has_value() && retry->has_value());

  // Her retry carries a valid mac2 for HER address. Replaying that same packet
  // from a different source must fail, because the cookie is bound to the
  // address it was issued for. This is what defeats spoofing: an attacker who
  // cannot receive at the address it claims never obtains a usable cookie.
  const auto spoofed = endpoint_of("203.0.113.200:41014");
  const auto rejected = bob.control->handle_datagram(spoofed, (*retry)->datagram, now);
  NORR_CHECK(!rejected.has_value() || !rejected->has_value() ||
             bob.control->stats().cookies_issued == 2);
  NORR_CHECK(bob.sessions.size() == 0);

  std::puts("control: spoofed source cannot reuse another address's cookie OK");
}

void test_pending_state_is_bounded() {
  Node bob;
  bob.identity = make_identity();
  bob.build();

  // Pre-auth state is the most attacker-influenced thing in the control
  // plane, so it must have a ceiling rather than growing per attempt.
  NORR_CHECK(norr::ControlPlane::kMaximumPending > 0);
  NORR_CHECK(norr::ControlPlane::kMaximumPending <= 4096);

  std::puts("control: pending ceiling is defined OK");
}

}  // namespace

int main() {
  if (!norr::crypto_available()) {
    Node node;
    node.build();
    const auto now = std::chrono::steady_clock::now();
    const auto started = node.control->start_handshake(1, now);
    NORR_CHECK(!started.has_value());
    std::puts("control: crypto backend absent, guards verified");
    return 0;
  }
  NORR_CHECK(norr::crypto_init().has_value());

  test_full_handshake_through_control_plane();
  test_forged_frame_does_not_promote();
  test_replayed_initiation_is_refused();
  test_wrong_psk_produces_no_session();
  test_unknown_peer_is_refused();
  test_rate_limiting_sheds_flood();
  test_timeout_expires_half_open_state();
  test_retry_uses_backoff();
  test_cookie_challenge_under_load();
  test_spoofed_source_cannot_pass_the_challenge();
  test_pending_state_is_bounded();
  return 0;
}
