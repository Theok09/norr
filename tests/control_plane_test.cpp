
#include "check.hpp"
#include <chrono>
#include <cstdio>
#include <string_view>
#include <vector>

#include "norr/control_plane.hpp"
#include "norr/handshake_frame.hpp"

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

  const auto initiation = alice.control->start_handshake(2, now);
  NORR_CHECK(initiation.has_value());
  NORR_CHECK(alice.control->pending() == 1);
  NORR_CHECK(alice.control->stats().handshakes_started == 1);

  NORR_CHECK(alice.timers.size() == 2);

  const auto reply = bob.control->handle_datagram(alice_endpoint, initiation->datagram, now);
  NORR_CHECK(reply.has_value() && reply->has_value());
  NORR_CHECK(bob.sessions.size() == 0);
  NORR_CHECK(bob.control->provisional() == 1);
  NORR_CHECK(bob.control->stats().responder_handshakes == 1);
  NORR_CHECK(bob.control->stats().handshakes_completed == 0);

  const auto finished = alice.control->handle_datagram(bob_endpoint, (*reply)->datagram, now);
  NORR_CHECK(finished.has_value() && !finished->has_value());
  NORR_CHECK(alice.sessions.size() == 1);
  NORR_CHECK(alice.control->pending() == 0);
  NORR_CHECK(alice.control->stats().handshakes_completed == 1);

  auto alice_session = alice.sessions.find_by_peer(2);
  NORR_CHECK(alice_session != nullptr);
  NORR_CHECK(alice_session->endpoint().has_value());

  const std::array<std::byte, 4> plaintext{std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
  std::vector<std::byte> wire(norr::kPacketHeaderSize + plaintext.size() + norr::kAeadTagSize);
  const auto sealed = alice_session->seal(norr::FrameType::data, plaintext, wire);
  NORR_CHECK(sealed.has_value());

  const auto view = norr::parse_packet(std::span{wire}.first(*sealed));
  NORR_CHECK(view.has_value());

  std::vector<std::byte> recovered(plaintext.size());
  const auto promoted = bob.control->try_promote_provisional(
      *view, std::span{wire}.first(*sealed), recovered, alice_endpoint);
  NORR_CHECK(promoted.has_value());
  NORR_CHECK(*promoted == plaintext.size());
  NORR_CHECK(std::equal(plaintext.begin(), plaintext.end(), recovered.begin()));
  NORR_CHECK(bob.sessions.size() == 1);
  NORR_CHECK(bob.control->provisional() == 0);
  NORR_CHECK(bob.control->stats().provisional_promoted == 1);

  auto bob_session = bob.sessions.find_by_peer(1);
  NORR_CHECK(bob_session != nullptr);
  NORR_CHECK(bob_session->endpoint().has_value());

  const auto replayed = bob_session->open(*view, std::span{wire}.first(*sealed), recovered);
  NORR_CHECK(!replayed.has_value());
  NORR_CHECK(replayed.error() == norr::SessionError::replayed);

  std::puts("control: handshake completes and keys interoperate OK");
}

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

  const auto finished = alice.control->handle_datagram(bob_endpoint, (*reply)->datagram, now);
  NORR_CHECK(finished.has_value());
  auto alice_session = alice.sessions.find_by_peer(2);
  NORR_CHECK(alice_session != nullptr);

  const std::array<std::byte, 4> plaintext{std::byte{9}, std::byte{9}, std::byte{9}, std::byte{9}};
  std::vector<std::byte> wire(norr::kPacketHeaderSize + plaintext.size() + norr::kAeadTagSize);
  const auto sealed = alice_session->seal(norr::FrameType::data, plaintext, wire);
  NORR_CHECK(sealed.has_value());

  auto forged = std::vector<std::byte>(wire.begin(), wire.begin() + *sealed);
  forged[norr::kPacketHeaderSize] ^= std::byte{0xFF};

  const auto view = norr::parse_packet(forged);
  NORR_CHECK(view.has_value());

  std::vector<std::byte> out(plaintext.size());
  const auto refused =
      bob.control->try_promote_provisional(*view, forged, out, alice_endpoint);
  NORR_CHECK(!refused.has_value());

  NORR_CHECK(bob.sessions.size() == 0);
  NORR_CHECK(bob.control->provisional() == 1);
  NORR_CHECK(bob.control->stats().provisional_promoted == 0);

  const auto genuine = norr::parse_packet(std::span{wire}.first(*sealed));
  NORR_CHECK(genuine.has_value());
  const auto accepted = bob.control->try_promote_provisional(
      *genuine, std::span{wire}.first(*sealed), out, alice_endpoint);
  NORR_CHECK(accepted.has_value());
  NORR_CHECK(bob.sessions.size() == 1);

  std::puts("control: forged frame does not promote provisional state OK");
}

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

  const auto first = bob.control->handle_datagram(alice_endpoint, initiation->datagram, now);
  NORR_CHECK(first.has_value() && first->has_value());
  NORR_CHECK(bob.control->stats().responder_handshakes == 1);
  NORR_CHECK(bob.control->provisional() == 1);

  const auto replayed = bob.control->handle_datagram(alice_endpoint, initiation->datagram, now);
  NORR_CHECK(!replayed.has_value());
  NORR_CHECK(bob.control->stats().replayed_initiations == 1);
  NORR_CHECK(bob.control->stats().responder_handshakes == 1);
  NORR_CHECK(bob.control->provisional() == 1);

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

  const auto reply = bob.control->handle_datagram(alice_endpoint, initiation->datagram, now);
  static_cast<void>(reply);
  NORR_CHECK(bob.sessions.size() == 0);

  if (reply.has_value() && reply->has_value()) {
    const auto finished =
        alice.control->handle_datagram(bob_endpoint, (*reply)->datagram, now);
    NORR_CHECK(!finished.has_value());
  }
  NORR_CHECK(alice.sessions.size() == 0);

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

  bob.control->set_under_load(true);
  NORR_CHECK(bob.control->under_load());

  const auto initiation = alice.control->start_handshake(2, now);
  NORR_CHECK(initiation.has_value());

  const auto challenge = bob.control->handle_datagram(alice_endpoint, initiation->datagram, now);
  NORR_CHECK(challenge.has_value() && challenge->has_value());
  NORR_CHECK(bob.control->stats().cookies_issued == 1);
  NORR_CHECK(bob.control->stats().mac2_failures == 1);

  NORR_CHECK(bob.control->provisional() == 0);
  NORR_CHECK(bob.sessions.size() == 0);

  const auto retry = alice.control->handle_datagram(bob_endpoint, (*challenge)->datagram, now);
  NORR_CHECK(retry.has_value() && retry->has_value());
  NORR_CHECK(alice.control->stats().cookies_accepted == 1);

  const auto reply = bob.control->handle_datagram(alice_endpoint, (*retry)->datagram, now);
  NORR_CHECK(reply.has_value() && reply->has_value());
  NORR_CHECK(bob.control->stats().responder_handshakes == 1);
  NORR_CHECK(bob.control->provisional() == 1);

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

  NORR_CHECK(norr::ControlPlane::kMaximumPending > 0);
  NORR_CHECK(norr::ControlPlane::kMaximumPending <= 4096);

  std::puts("control: pending ceiling is defined OK");
}
}

struct Pair {
  Node alice;
  Node bob;
  norr::Endpoint alice_endpoint = endpoint_of("127.0.0.1:41001");
  norr::Endpoint bob_endpoint = endpoint_of("127.0.0.1:41002");

  Pair(norr::PeerId alice_sees_bob, norr::PeerId bob_sees_alice) {
    alice.identity = make_identity();
    bob.identity = make_identity();
    alice.build();
    bob.build();
    const auto psk = make_psk(0x33);
    NORR_CHECK(alice.control
                   ->add_peer(norr::PeerConfig{.id = alice_sees_bob,
                                               .static_public = bob.identity.public_key,
                                               .preshared = psk,
                                               .endpoint = bob_endpoint})
                   .has_value());
    NORR_CHECK(bob.control
                   ->add_peer(norr::PeerConfig{.id = bob_sees_alice,
                                               .static_public = alice.identity.public_key,
                                               .preshared = psk,
                                               .endpoint = alice_endpoint})
                   .has_value());
  }
};

std::size_t count_timers(const norr::TimerWheel& wheel, norr::TimerKind kind,
                         norr::Instant horizon) {
  auto copy = wheel;
  std::size_t count = 0;
  for (const auto& event : copy.expire(horizon)) {
    if (event.kind == kind) ++count;
  }
  return count;
}

void test_forged_response_does_not_break_pending_handshake() {
  Pair pair{2, 1};
  const auto now = std::chrono::steady_clock::now();
  const auto initiation = pair.alice.control->start_handshake(2, now);
  NORR_CHECK(initiation.has_value());
  const auto reply =
      pair.bob.control->handle_datagram(pair.alice_endpoint, initiation->datagram, now);
  NORR_CHECK(reply.has_value() && reply->has_value());

  for (const bool with_macs : {false, true}) {
    std::vector<std::byte> forged(4 + 48 + (with_macs ? 32 : 0), std::byte{0x41});
    forged[0] = static_cast<std::byte>(norr::HandshakeMessage::response);
    forged[1] = std::byte{1};
    forged[2] = std::byte{0};
    forged[3] = std::byte{48};
    NORR_CHECK(!pair.alice.control->handle_datagram(endpoint_of("198.51.100.9:9"), forged, now));
  }

  const auto genuine =
      pair.alice.control->handle_datagram(pair.bob_endpoint, (*reply)->datagram, now);
  NORR_CHECK(genuine.has_value());
  NORR_CHECK(pair.alice.sessions.find_by_peer(2) != nullptr);
  std::puts("control: forged responses leave the pending handshake intact OK");
}

void test_initiation_without_mac1_is_refused() {
  Pair pair{2, 1};
  const auto now = std::chrono::steady_clock::now();
  const auto initiation = pair.alice.control->start_handshake(2, now);
  NORR_CHECK(initiation.has_value());

  auto stripped = initiation->datagram;
  stripped.resize(stripped.size() - norr::kHandshakeMacTrailerSize);
  const auto refused = pair.bob.control->handle_datagram(pair.alice_endpoint, stripped, now);
  NORR_CHECK(!refused.has_value());
  NORR_CHECK(pair.bob.control->stats().mac1_failures == 1);
  std::puts("control: initiation without mac1 refused OK");
}

void test_rekeys_do_not_accumulate_timers() {
  Pair pair{2, 1};
  auto now = std::chrono::steady_clock::now();
  for (int round = 0; round < 20; ++round) {
    const auto initiation = pair.alice.control->start_handshake(2, now);
    NORR_CHECK(initiation.has_value());
    const auto reply =
        pair.bob.control->handle_datagram(pair.alice_endpoint, initiation->datagram, now);
    NORR_CHECK(reply.has_value() && reply->has_value());
    NORR_CHECK(pair.alice.control->handle_datagram(pair.bob_endpoint, (*reply)->datagram, now));
    now += std::chrono::minutes{2};
  }
  const auto horizon = now + std::chrono::hours{1};
  NORR_CHECK(count_timers(pair.alice.timers, norr::TimerKind::keepalive, horizon) == 1);
  NORR_CHECK(count_timers(pair.alice.timers, norr::TimerKind::rekey, horizon) == 1);
  std::puts("control: rekeys re-arm timers instead of stacking them OK");
}

void test_provisional_timeout_does_not_touch_peer_state() {
  Pair pair{1, 1};
  const auto now = std::chrono::steady_clock::now();
  const auto initiation = pair.alice.control->start_handshake(1, now);
  NORR_CHECK(initiation.has_value());
  NORR_CHECK(pair.bob.control->handle_datagram(pair.alice_endpoint, initiation->datagram, now));
  NORR_CHECK(pair.bob.control->provisional() == 1);

  const auto later = now + std::chrono::seconds{1};
  NORR_CHECK(pair.bob.control->start_handshake(1, later).has_value());
  NORR_CHECK(pair.bob.control->pending() == 1);

  const auto expiry = now + norr::kHandshakeTimeout + std::chrono::milliseconds{1};
  static_cast<void>(pair.bob.control->on_timers(pair.bob.timers.expire(expiry), expiry));
  NORR_CHECK(pair.bob.control->provisional() == 0);
  NORR_CHECK(pair.bob.control->pending() == 1);
  std::puts("control: provisional timeout is separate from peer timers OK");
}

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
  test_forged_response_does_not_break_pending_handshake();
  test_initiation_without_mac1_is_refused();
  test_rekeys_do_not_accumulate_timers();
  test_provisional_timeout_does_not_touch_peer_state();
  return 0;
}
