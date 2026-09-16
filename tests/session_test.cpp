// Session state: sealing, opening, replay commitment and the key-id tables.
//
// The AEAD half needs the crypto backend. Where it is absent the table and
// lookup behaviour is still exercised, because none of that depends on it.

#include <array>
#include "check.hpp"
#include <cstddef>
#include <cstdio>
#include <span>
#include <string_view>
#include <vector>

#include "norr/session.hpp"

namespace {

std::vector<std::byte> as_bytes(std::string_view text) {
  std::vector<std::byte> bytes;
  bytes.reserve(text.size());
  for (const char character : text) {
    bytes.push_back(static_cast<std::byte>(static_cast<unsigned char>(character)));
  }
  return bytes;
}

norr::TrafficKeys make_keys(std::string_view secret_text, norr::KeyDirection direction,
                            norr::KeyGeneration generation = 0) {
  const auto secret = as_bytes(secret_text);
  const auto key = norr::derive_traffic_key(secret, norr::kDataLabel, direction, generation);
  NORR_CHECK(key.has_value());
  return norr::TrafficKeys{*key, generation};
}

// Builds the two halves of one logical session: what the initiator sends with
// is what the responder receives with.
struct Pair {
  norr::Session initiator;
  norr::Session responder;
};

Pair make_pair(std::string_view secret) {
  return Pair{
      .initiator = norr::Session{1, 0x1111, 0x2222,
                                 make_keys(secret, norr::KeyDirection::initiator_to_responder),
                                 make_keys(secret, norr::KeyDirection::responder_to_initiator)},
      .responder = norr::Session{2, 0x2222, 0x1111,
                                 make_keys(secret, norr::KeyDirection::responder_to_initiator),
                                 make_keys(secret, norr::KeyDirection::initiator_to_responder)},
  };
}

void test_table_without_crypto() {
  norr::SessionTable table;

  // Key id zero is reserved for pre-session frames and must never be handed out.
  for (int attempt = 0; attempt < 32; ++attempt) {
    const auto key_id = table.allocate_key_id();
    NORR_CHECK(key_id.has_value() && *key_id != norr::kPreSessionKeyId);
  }

  const auto first = table.install(1, 0x0010, 0x0020, make_keys("s", norr::KeyDirection::initiator_to_responder),
                                   make_keys("s", norr::KeyDirection::responder_to_initiator));
  NORR_CHECK(first.has_value());
  NORR_CHECK(table.size() == 1);

  // Both lookups must reach the same session.
  NORR_CHECK(table.find_by_key_id(0x0010) != nullptr);
  NORR_CHECK(table.find_by_peer(1) != nullptr);
  NORR_CHECK(table.find_by_key_id(0x0010) == table.find_by_peer(1));
  NORR_CHECK(table.find_by_key_id(0x0011) == nullptr);
  NORR_CHECK(table.find_by_peer(2) == nullptr);

  // Installing a new session for the same peer moves the send mapping but
  // keeps the old key id receivable for a grace period, so packets already in
  // flight under it are not dropped. Erasing immediately was a real bug: a
  // long-lived tunnel lost a burst of packets at every rekey.
  const auto second = table.install(1, 0x0030, 0x0040, make_keys("t", norr::KeyDirection::initiator_to_responder),
                                    make_keys("t", norr::KeyDirection::responder_to_initiator));
  NORR_CHECK(second.has_value());
  NORR_CHECK(table.size() == 2);
  NORR_CHECK(table.retired() == 1);
  NORR_CHECK(table.find_by_key_id(0x0010) != nullptr);
  NORR_CHECK(table.find_by_key_id(0x0030) != nullptr);
  NORR_CHECK(table.find_by_peer(1) == table.find_by_key_id(0x0030));

  // After the window the old key is gone.
  table.expire_retired(std::chrono::steady_clock::now() + norr::kRetireAfter +
                       std::chrono::seconds{1});
  NORR_CHECK(table.find_by_key_id(0x0010) == nullptr);
  NORR_CHECK(table.size() == 1);

  // Peer zero is not a peer, and key id zero is not installable.
  NORR_CHECK(!table.install(norr::kNoPeer, 0x0050, 0x0060, make_keys("u", norr::KeyDirection::initiator_to_responder),
                        make_keys("u", norr::KeyDirection::responder_to_initiator))
              .has_value());
  NORR_CHECK(!table.install(3, norr::kPreSessionKeyId, 0x0060,
                        make_keys("u", norr::KeyDirection::initiator_to_responder),
                        make_keys("u", norr::KeyDirection::responder_to_initiator))
              .has_value());

  table.remove(0x0030);
  NORR_CHECK(table.size() == 0);
  NORR_CHECK(table.find_by_peer(1) == nullptr);
  // Removing something absent is harmless.
  table.remove(0x0030);

  std::puts("session: table and key-id allocation OK");
}

#if defined(NORR_HAVE_LIBSODIUM)

void test_roundtrip() {
  auto pair = make_pair("shared handshake secret");

  const auto plaintext = as_bytes("an inner IP packet");
  std::vector<std::byte> wire(norr::kPacketHeaderSize + plaintext.size() + norr::kAeadTagSize);

  const auto sealed = pair.initiator.seal(norr::FrameType::data, plaintext, wire);
  NORR_CHECK(sealed.has_value() && *sealed == wire.size());

  // The header must be parseable and must carry the peer's key id.
  const auto view = norr::parse_packet(std::span{wire}.first(*sealed));
  NORR_CHECK(view.has_value());
  NORR_CHECK(view->header.key_id == 0x2222);
  NORR_CHECK(view->header.type == norr::FrameType::data);
  NORR_CHECK(view->header.counter == 0);

  std::vector<std::byte> recovered(plaintext.size());
  const auto opened = pair.responder.open(*view, std::span{wire}.first(*sealed), recovered);
  NORR_CHECK(opened.has_value() && *opened == plaintext.size());
  NORR_CHECK(std::equal(plaintext.begin(), plaintext.end(), recovered.begin()));
  NORR_CHECK(pair.responder.stats().received == 1);

  std::puts("session: seal/open round-trip OK");
}

void test_replay_is_committed_after_authentication() {
  auto pair = make_pair("replay secret");
  const auto plaintext = as_bytes("payload");

  std::vector<std::byte> wire(norr::kPacketHeaderSize + plaintext.size() + norr::kAeadTagSize);
  const auto sealed = pair.initiator.seal(norr::FrameType::data, plaintext, wire);
  NORR_CHECK(sealed.has_value());
  const auto packet = std::span{wire}.first(*sealed);
  const auto view = norr::parse_packet(packet);
  NORR_CHECK(view.has_value());

  std::vector<std::byte> out(plaintext.size());
  NORR_CHECK(pair.responder.open(*view, packet, out).has_value());

  // The same packet a second time must be refused as a replay.
  const auto replayed = pair.responder.open(*view, packet, out);
  NORR_CHECK(!replayed.has_value() && replayed.error() == norr::SessionError::replayed);
  NORR_CHECK(pair.responder.stats().replay_drops == 1);

  // A forged packet must not consume the counter. Corrupt the ciphertext of a
  // fresh packet, present it, then present the genuine one: the genuine packet
  // must still be accepted, which is only true if the window was committed
  // after authentication rather than before.
  std::vector<std::byte> genuine(norr::kPacketHeaderSize + plaintext.size() + norr::kAeadTagSize);
  NORR_CHECK(pair.initiator.seal(norr::FrameType::data, plaintext, genuine).has_value());

  auto forged = genuine;
  forged.back() ^= std::byte{0xFF};
  const auto forged_view = norr::parse_packet(forged);
  NORR_CHECK(forged_view.has_value());
  const auto rejected = pair.responder.open(*forged_view, forged, out);
  NORR_CHECK(!rejected.has_value() && rejected.error() == norr::SessionError::authentication_failed);
  NORR_CHECK(pair.responder.stats().auth_failures == 1);

  const auto genuine_view = norr::parse_packet(genuine);
  NORR_CHECK(genuine_view.has_value());
  const auto accepted = pair.responder.open(*genuine_view, genuine, out);
  NORR_CHECK(accepted.has_value());

  std::puts("session: replay committed only after authentication OK");
}

void test_header_is_authenticated() {
  auto pair = make_pair("aad secret");
  const auto plaintext = as_bytes("bound to header");

  std::vector<std::byte> wire(norr::kPacketHeaderSize + plaintext.size() + norr::kAeadTagSize);
  const auto sealed = pair.initiator.seal(norr::FrameType::data, plaintext, wire);
  NORR_CHECK(sealed.has_value());

  // Flipping a header bit must break authentication: the whole header is AAD.
  auto tampered = wire;
  tampered[2] ^= std::byte{0x01};  // key id
  const auto view = norr::parse_packet(tampered);
  if (view.has_value()) {
    std::vector<std::byte> out(plaintext.size());
    const auto result = pair.responder.open(*view, tampered, out);
    NORR_CHECK(!result.has_value() && result.error() == norr::SessionError::authentication_failed);
  }

  std::puts("session: header authenticated as AAD OK");
}

void test_directionality() {
  auto pair = make_pair("direction secret");
  const auto plaintext = as_bytes("one way");

  std::vector<std::byte> wire(norr::kPacketHeaderSize + plaintext.size() + norr::kAeadTagSize);
  NORR_CHECK(pair.initiator.seal(norr::FrameType::data, plaintext, wire).has_value());
  const auto view = norr::parse_packet(wire);
  NORR_CHECK(view.has_value());

  // The initiator must not be able to open its own packet: send and receive
  // keys are separate nonce domains.
  std::vector<std::byte> out(plaintext.size());
  const auto self = pair.initiator.open(*view, wire, out);
  NORR_CHECK(!self.has_value() && self.error() == norr::SessionError::authentication_failed);

  std::puts("session: directional keys OK");
}

void test_counter_advances() {
  auto pair = make_pair("counter secret");
  const auto plaintext = as_bytes("x");

  for (std::uint64_t expected = 0; expected < 5; ++expected) {
    std::vector<std::byte> wire(norr::kPacketHeaderSize + plaintext.size() + norr::kAeadTagSize);
    NORR_CHECK(pair.initiator.seal(norr::FrameType::data, plaintext, wire).has_value());
    const auto view = norr::parse_packet(wire);
    NORR_CHECK(view.has_value() && view->header.counter == expected);

    std::vector<std::byte> out(plaintext.size());
    NORR_CHECK(pair.responder.open(*view, wire, out).has_value());
  }
  NORR_CHECK(pair.initiator.stats().sent == 5);

  std::puts("session: counter advances per packet OK");
}

void test_out_of_order_within_window() {
  auto pair = make_pair("reorder secret");
  const auto plaintext = as_bytes("reordered");

  // Seal several packets, then deliver them backwards. All must be accepted,
  // because reordering is normal on a real path.
  std::vector<std::vector<std::byte>> packets;
  for (int index = 0; index < 8; ++index) {
    std::vector<std::byte> wire(norr::kPacketHeaderSize + plaintext.size() + norr::kAeadTagSize);
    NORR_CHECK(pair.initiator.seal(norr::FrameType::data, plaintext, wire).has_value());
    packets.push_back(std::move(wire));
  }

  std::vector<std::byte> out(plaintext.size());
  for (auto packet = packets.rbegin(); packet != packets.rend(); ++packet) {
    const auto view = norr::parse_packet(*packet);
    NORR_CHECK(view.has_value());
    NORR_CHECK(pair.responder.open(*view, *packet, out).has_value());
  }
  NORR_CHECK(pair.responder.stats().received == packets.size());

  std::puts("session: out-of-order delivery within the window OK");
}

void test_buffer_bounds() {
  auto pair = make_pair("bounds secret");
  const auto plaintext = as_bytes("needs room");

  // One byte short of header + ciphertext + tag must be refused, not written
  // past.
  std::vector<std::byte> tight(norr::kPacketHeaderSize + plaintext.size() + norr::kAeadTagSize - 1);
  const auto refused = pair.initiator.seal(norr::FrameType::data, plaintext, tight);
  NORR_CHECK(!refused.has_value() && refused.error() == norr::SessionError::buffer_too_small);

  std::puts("session: buffer bounds enforced OK");
}

void test_endpoint_tracking() {
  auto pair = make_pair("endpoint secret");
  NORR_CHECK(!pair.responder.endpoint().has_value());

  const auto parsed = norr::parse_endpoint("203.0.113.9:51880");
  NORR_CHECK(parsed.has_value());
  pair.responder.note_authenticated_endpoint(*parsed);
  NORR_CHECK(pair.responder.endpoint().has_value());
  NORR_CHECK(*pair.responder.endpoint() == *parsed);

  // Roaming: a later authenticated packet from elsewhere updates the endpoint
  // without changing peer identity.
  const auto moved = norr::parse_endpoint("198.51.100.4:41000");
  NORR_CHECK(moved.has_value());
  pair.responder.note_authenticated_endpoint(*moved);
  NORR_CHECK(*pair.responder.endpoint() == *moved);
  NORR_CHECK(pair.responder.peer() == 2);

  std::puts("session: endpoint roaming OK");
}

#endif  // NORR_HAVE_LIBSODIUM

}  // namespace

// A rekey must not drop packets that were already in flight under the old key.
//
// Without a retention window the replacement session evicts its predecessor the
// instant it is installed, and every packet still on the wire arrives naming a
// key id that no longer exists. Over a long-lived tunnel that is a burst of
// lost packets every rekey interval, which a soak test sees and a unit test
// that only checks the happy path does not.
void test_rekey_retains_the_previous_session() {
  norr::SessionTable table;

  const auto old_keys = [] {
    return norr::TrafficKeys{
        *norr::derive_traffic_key(as_bytes("generation-zero"), norr::kDataLabel,
                                  norr::KeyDirection::initiator_to_responder, 0),
        0};
  };

  const auto installed = table.install(1, 0x0010, 0x0020, old_keys(), old_keys());
  NORR_CHECK(installed.has_value());
  NORR_CHECK(table.size() == 1);
  NORR_CHECK(table.retired() == 0);

  // Seal a packet under the old session, as a peer would have done just before
  // the rekey landed.
  const std::array<std::byte, 8> payload{std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4},
                                         std::byte{5}, std::byte{6}, std::byte{7}, std::byte{8}};
  std::vector<std::byte> wire(norr::kPacketHeaderSize + payload.size() + norr::kAeadTagSize);
  const auto sealed = (*installed)->seal(norr::FrameType::data, payload, wire);
  NORR_CHECK(sealed.has_value());

  // Rekey: a second session for the same peer, under a new key id.
  const auto replacement = table.install(1, 0x0030, 0x0040, old_keys(), old_keys());
  NORR_CHECK(replacement.has_value());

  // The new session is what outbound traffic uses.
  auto* by_peer = table.find_by_peer(1);
  NORR_CHECK(by_peer != nullptr);
  NORR_CHECK(by_peer->local_key_id() == 0x0030);

  // The old one is retired, not erased: the in-flight packet still finds it.
  NORR_CHECK(table.retired() == 1);
  auto* old_session = table.find_by_key_id(0x0010);
  NORR_CHECK(old_session != nullptr);
  NORR_CHECK(table.retired_receives() == 1);

  const auto view = norr::parse_packet(std::span{wire}.first(*sealed));
  NORR_CHECK(view.has_value());
  std::vector<std::byte> recovered(payload.size());
  const auto opened = old_session->open(*view, std::span{wire}.first(*sealed), recovered);
  NORR_CHECK(opened.has_value());
  NORR_CHECK(std::equal(payload.begin(), payload.end(), recovered.begin()));

  // Once the window passes the old key is gone, so a replayed packet from
  // before the rekey cannot be accepted indefinitely.
  table.expire_retired(std::chrono::steady_clock::now() + norr::kRetireAfter +
                       std::chrono::seconds{1});
  NORR_CHECK(table.retired() == 0);
  NORR_CHECK(table.find_by_key_id(0x0010) == nullptr);

  // The replacement survived the expiry.
  NORR_CHECK(table.find_by_peer(1) != nullptr);
  NORR_CHECK(table.find_by_key_id(0x0030) != nullptr);

  std::puts("session: rekey retains the previous session for in-flight packets OK");
}

// Removing the current session must not strand the peer mapping on a retired
// key id, which would make the peer unreachable rather than merely rekeyed.
void test_remove_does_not_disturb_the_active_mapping() {
  norr::SessionTable table;
  const auto keys = [] {
    return norr::TrafficKeys{
        *norr::derive_traffic_key(as_bytes("remove"), norr::kDataLabel,
                                  norr::KeyDirection::initiator_to_responder, 0),
        0};
  };

  NORR_CHECK(table.install(1, 0x0010, 0x0020, keys(), keys()).has_value());
  NORR_CHECK(table.install(1, 0x0030, 0x0040, keys(), keys()).has_value());
  NORR_CHECK(table.retired() == 1);

  // Removing the retired key must leave the active session addressable.
  table.remove(0x0010);
  NORR_CHECK(table.retired() == 0);
  auto* active = table.find_by_peer(1);
  NORR_CHECK(active != nullptr);
  NORR_CHECK(active->local_key_id() == 0x0030);

  std::puts("session: removing a retired key leaves the active session OK");
}

// WireGuard's timer state machine bounds a session by messages as well as by
// time: REKEY_AFTER_MESSAGES at 2^60 and REJECT_AFTER_MESSAGES at
// 2^64 - 2^13 - 1. Norr uses the same values, because the reason is the same:
// a counter that reaches its maximum would repeat a nonce under one key.
void test_message_and_time_limits_match_the_reference() {
  NORR_CHECK(norr::kRekeyAfterMessages == (1ULL << 60U));
  NORR_CHECK(norr::kRejectAfterMessages == 18'446'744'073'709'543'423ULL);

  // Rekey must come first, or a session would be refused before it was ever
  // replaced.
  NORR_CHECK(norr::kRekeyAfterMessages < norr::kRejectAfterMessages);
  NORR_CHECK(norr::kRekeyAfter < norr::kSessionExpiry);

  // The reject ceiling must stay below the counter's own maximum so the
  // session is retired before the nonce space runs out.
  NORR_CHECK(norr::kRejectAfterMessages < UINT64_MAX);

  std::puts("session: message and time limits match the reference OK");
}

int main() {
  if (norr::crypto_available()) {
    NORR_CHECK(norr::crypto_init().has_value());
  }

  test_table_without_crypto();

#if defined(NORR_HAVE_LIBSODIUM)
  test_roundtrip();
  test_replay_is_committed_after_authentication();
  test_header_is_authenticated();
  test_directionality();
  test_counter_advances();
  test_out_of_order_within_window();
  test_buffer_bounds();
  test_endpoint_tracking();
  test_message_and_time_limits_match_the_reference();
  test_rekey_retains_the_previous_session();
  test_remove_does_not_disturb_the_active_mapping();
#else
  std::puts("session: crypto backend absent, AEAD paths skipped");
#endif
  return 0;
}
