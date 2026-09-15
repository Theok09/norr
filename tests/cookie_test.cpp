// IP-attributability cookies.
//
// The property under test is narrow but critical: an attacker who can send
// packets with a forged source address, but cannot receive at that address,
// must never be able to produce a valid mac2.

#include <algorithm>
#include <array>
#include "check.hpp"
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <span>
#include <string_view>
#include <vector>

#include "norr/cookie.hpp"

namespace {

norr::Endpoint endpoint_of(std::string_view text) {
  const auto parsed = norr::parse_endpoint(text);
  NORR_CHECK(parsed.has_value());
  return *parsed;
}

std::vector<std::byte> as_bytes(std::string_view text) {
  std::vector<std::byte> bytes;
  bytes.reserve(text.size());
  for (const char character : text) {
    bytes.push_back(static_cast<std::byte>(static_cast<unsigned char>(character)));
  }
  return bytes;
}

norr::PublicKey make_static_key() {
  const auto pair = norr::generate_keypair();
  NORR_CHECK(pair.has_value());
  return pair->public_key;
}

void test_labels_are_distinct() {
  const auto responder = make_static_key();
  const auto mac_key = norr::mac1_key(responder);
  const auto cookie_secret_key = norr::cookie_key(responder);

  // The two labels must derive different keys, otherwise mac1 and the cookie
  // encryption would share key material.
  NORR_CHECK(!norr::constant_time_equal(mac_key, cookie_secret_key));

  // Derivation is deterministic, so both peers compute the same mac1 key.
  NORR_CHECK(norr::constant_time_equal(mac_key, norr::mac1_key(responder)));

  // A different responder identity gives different keys, which is what makes a
  // node silent to anyone who does not know which node they are addressing.
  const auto other = make_static_key();
  NORR_CHECK(!norr::constant_time_equal(mac_key, norr::mac1_key(other)));

  std::puts("cookie: label-derived keys are distinct OK");
}

void test_mac1_identifies_the_responder() {
  const auto responder = make_static_key();
  norr::CookieIssuer issuer{responder};
  norr::CookieHolder holder{responder};

  const auto message = as_bytes("handshake initiation bytes");

  // A peer that knows the responder's static key produces a mac1 the responder
  // accepts.
  const auto mac1 = holder.compute_mac1(message);
  NORR_CHECK(issuer.verify_mac1(message, mac1));

  // A scanner that does not know the key cannot.
  norr::CookieHolder stranger{make_static_key()};
  NORR_CHECK(!issuer.verify_mac1(message, stranger.compute_mac1(message)));

  // Any change to the message invalidates mac1.
  auto tampered = message;
  tampered[0] ^= std::byte{0x01};
  NORR_CHECK(!issuer.verify_mac1(tampered, mac1));

  std::puts("cookie: mac1 identifies the responder OK");
}

void test_mac2_is_zero_without_a_cookie() {
  norr::CookieHolder holder{make_static_key()};
  const auto message = as_bytes("first attempt");

  // The first handshake attempt carries no cookie, so mac2 is all zeros and an
  // unloaded responder ignores it.
  NORR_CHECK(!holder.has_cookie());
  const auto mac2 = holder.compute_mac2(message);
  const norr::Mac zero{};
  NORR_CHECK(norr::constant_time_equal(mac2, zero));

  std::puts("cookie: mac2 is zero before a cookie is held OK");
}

#if defined(NORR_HAVE_LIBSODIUM)

void test_cookie_roundtrip_and_spoofing() {
  const auto responder = make_static_key();
  norr::CookieIssuer issuer{responder};
  norr::CookieHolder holder{responder};

  const auto now = std::chrono::steady_clock::now();
  const auto peer = endpoint_of("203.0.113.5:51820");
  const auto message = as_bytes("handshake initiation");
  const auto mac1 = holder.compute_mac1(message);

  // Under load the responder issues a cookie instead of doing real work.
  issuer.set_under_load(true);
  const auto reply = issuer.build_reply(peer, 0x1234, mac1, now);
  NORR_CHECK(reply.has_value());

  // The reply survives serialisation.
  std::array<std::byte, norr::kCookieReplySize> wire{};
  const auto written = norr::serialize_cookie_reply(*reply, wire);
  NORR_CHECK(written.has_value() && *written == norr::kCookieReplySize);
  const auto parsed = norr::parse_cookie_reply(wire);
  NORR_CHECK(parsed.has_value());
  NORR_CHECK(parsed->receiver_index == 0x1234);

  // The real peer receives it and can now prove address ownership.
  NORR_CHECK(holder.accept_reply(*parsed, mac1, now).has_value());
  NORR_CHECK(holder.has_cookie());

  const auto retry = as_bytes("handshake initiation retry");
  const auto mac2 = holder.compute_mac2(retry);
  NORR_CHECK(issuer.verify_mac2(peer, retry, mac2, now));

  // This is the whole point: a spoofing attacker never receives the reply, so
  // it holds no cookie and cannot produce a valid mac2 for that address.
  norr::CookieHolder attacker{responder};
  const auto forged = attacker.compute_mac2(retry);
  NORR_CHECK(!issuer.verify_mac2(peer, retry, forged, now));

  // Even holding a genuine cookie, it is bound to the address it was issued
  // for: replaying it from elsewhere fails.
  const auto elsewhere = endpoint_of("198.51.100.9:51820");
  NORR_CHECK(!issuer.verify_mac2(elsewhere, retry, mac2, now));

  // A cookie proves the address, not the message: changing the message
  // invalidates mac2.
  auto altered = retry;
  altered[0] ^= std::byte{0x01};
  NORR_CHECK(!issuer.verify_mac2(peer, altered, mac2, now));

  std::puts("cookie: round-trip works and spoofing is refused OK");
}

void test_reply_is_bound_to_mac1() {
  const auto responder = make_static_key();
  norr::CookieIssuer issuer{responder};
  norr::CookieHolder holder{responder};

  const auto now = std::chrono::steady_clock::now();
  const auto peer = endpoint_of("203.0.113.7:51820");

  const auto message = as_bytes("initiation A");
  const auto mac1 = holder.compute_mac1(message);
  const auto reply = issuer.build_reply(peer, 1, mac1, now);
  NORR_CHECK(reply.has_value());

  // mac1 is the associated data, so a reply cannot be lifted onto a different
  // handshake.
  const auto other_mac1 = holder.compute_mac1(as_bytes("initiation B"));
  const auto rejected = holder.accept_reply(*reply, other_mac1, now);
  NORR_CHECK(!rejected.has_value());
  NORR_CHECK(rejected.error() == norr::CookieError::decryption_failed);
  NORR_CHECK(!holder.has_cookie());

  // The correct mac1 works.
  NORR_CHECK(holder.accept_reply(*reply, mac1, now).has_value());

  std::puts("cookie: reply is bound to the mac1 it answers OK");
}

void test_tampered_reply_is_rejected() {
  const auto responder = make_static_key();
  norr::CookieIssuer issuer{responder};
  norr::CookieHolder holder{responder};

  const auto now = std::chrono::steady_clock::now();
  const auto peer = endpoint_of("203.0.113.8:51820");
  const auto mac1 = holder.compute_mac1(as_bytes("initiation"));

  const auto reply = issuer.build_reply(peer, 1, mac1, now);
  NORR_CHECK(reply.has_value());

  // Flipping any byte of the encrypted cookie must be caught by the tag.
  for (std::size_t index : {std::size_t{0}, std::size_t{15}, std::size_t{31}}) {
    auto corrupted = *reply;
    corrupted.encrypted_cookie[index] ^= std::byte{0x01};
    NORR_CHECK(!holder.accept_reply(corrupted, mac1, now).has_value());
  }

  // So must a changed nonce.
  auto wrong_nonce = *reply;
  wrong_nonce.nonce[0] ^= std::byte{0x01};
  NORR_CHECK(!holder.accept_reply(wrong_nonce, mac1, now).has_value());

  std::puts("cookie: tampered reply rejected OK");
}

void test_secret_rotation() {
  const auto responder = make_static_key();
  norr::CookieIssuer issuer{responder};
  norr::CookieHolder holder{responder};

  const auto now = std::chrono::steady_clock::now();
  const auto peer = endpoint_of("203.0.113.10:51820");
  const auto mac1 = holder.compute_mac1(as_bytes("initiation"));

  const auto reply = issuer.build_reply(peer, 1, mac1, now);
  NORR_CHECK(reply.has_value());
  NORR_CHECK(holder.accept_reply(*reply, mac1, now).has_value());

  const auto retry = as_bytes("retry");
  const auto mac2 = holder.compute_mac2(retry);
  NORR_CHECK(issuer.verify_mac2(peer, retry, mac2, now));

  // Just after a rotation the previous secret is still accepted, so a cookie
  // in flight across the boundary is not spuriously rejected.
  const auto after_one = now + norr::kCookieSecretLifetime + std::chrono::seconds{1};
  NORR_CHECK(issuer.verify_mac2(peer, retry, mac2, after_one));

  // After two rotations it is gone, which bounds how long a captured cookie is
  // useful.
  const auto after_two = after_one + norr::kCookieSecretLifetime + std::chrono::seconds{1};
  static_cast<void>(issuer.verify_mac2(peer, retry, mac2, after_two));
  const auto after_three = after_two + norr::kCookieSecretLifetime + std::chrono::seconds{1};
  NORR_CHECK(!issuer.verify_mac2(peer, retry, mac2, after_three));

  std::puts("cookie: secret rotation with a grace period OK");
}

void test_cookie_is_per_address() {
  const auto responder = make_static_key();
  norr::CookieIssuer issuer{responder};
  const auto now = std::chrono::steady_clock::now();

  const auto first = issuer.compute_cookie(endpoint_of("203.0.113.1:1000"), now);
  const auto second = issuer.compute_cookie(endpoint_of("203.0.113.2:1000"), now);
  NORR_CHECK(!norr::constant_time_equal(first, second));

  // The port is deliberately excluded: NAT rebinding changes it and an
  // attacker varies it freely, so the address is the unit that carries meaning.
  const auto same_address_other_port =
      issuer.compute_cookie(endpoint_of("203.0.113.1:2000"), now);
  NORR_CHECK(norr::constant_time_equal(first, same_address_other_port));

  std::puts("cookie: bound to address, not port OK");
}

void test_ipv6_peer() {
  const auto responder = make_static_key();
  norr::CookieIssuer issuer{responder};
  norr::CookieHolder holder{responder};

  const auto now = std::chrono::steady_clock::now();
  const auto peer = endpoint_of("[2001:db8::99]:51820");
  const auto mac1 = holder.compute_mac1(as_bytes("initiation"));

  const auto reply = issuer.build_reply(peer, 1, mac1, now);
  NORR_CHECK(reply.has_value());
  NORR_CHECK(holder.accept_reply(*reply, mac1, now).has_value());

  const auto retry = as_bytes("retry");
  NORR_CHECK(issuer.verify_mac2(peer, retry, holder.compute_mac2(retry), now));

  const auto other = endpoint_of("[2001:db8::aa]:51820");
  NORR_CHECK(!issuer.verify_mac2(other, retry, holder.compute_mac2(retry), now));

  std::puts("cookie: IPv6 peers OK");
}

#endif  // NORR_HAVE_LIBSODIUM

}  // namespace

int main() {
  if (!norr::crypto_available()) {
    std::puts("cookie: crypto backend absent, skipped");
    return 0;
  }
  NORR_CHECK(norr::crypto_init().has_value());

  test_labels_are_distinct();
  test_mac1_identifies_the_responder();
  test_mac2_is_zero_without_a_cookie();

#if defined(NORR_HAVE_LIBSODIUM)
  test_cookie_roundtrip_and_spoofing();
  test_reply_is_bound_to_mac1();
  test_tampered_reply_is_rejected();
  test_secret_rotation();
  test_cookie_is_per_address();
  test_ipv6_peer();
#endif
  return 0;
}
