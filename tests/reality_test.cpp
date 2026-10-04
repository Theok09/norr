#include <algorithm>
#include <array>
#include <cstdio>
#include <span>

#include "check.hpp"
#include "norr/crypto.hpp"
#include "norr/reality.hpp"

namespace {
norr::RealityShortId make_short_id(std::byte fill) {
  norr::RealityShortId id{};
  std::fill(id.begin(), id.end(), fill);
  return id;
}

void test_authenticated_roundtrip() {
  const auto server = norr::generate_keypair();
  NORR_CHECK(server.has_value());
  const auto id = make_short_id(std::byte{0x7A});
  const std::uint64_t now = 1'760'000'000;

  const auto hello = norr::reality_client_hello(server->public_key, id, now);
  NORR_CHECK(hello.has_value());

  const auto result = norr::reality_server_verify(
      server->private_key, hello->ephemeral.public_key, hello->session_id, now + 5, 30);
  NORR_CHECK(result.authenticated);
  NORR_CHECK(result.timestamp == now);
  NORR_CHECK(std::equal(id.begin(), id.end(), result.short_id.begin()));
  std::puts("reality: authenticated client round-trips OK");
}

void test_wrong_server_key_fails() {
  const auto server = norr::generate_keypair();
  const auto other = norr::generate_keypair();
  NORR_CHECK(server.has_value() && other.has_value());
  const auto id = make_short_id(std::byte{0x01});
  const std::uint64_t now = 1'760'000'000;

  const auto hello = norr::reality_client_hello(server->public_key, id, now);
  NORR_CHECK(hello.has_value());

  const auto result = norr::reality_server_verify(
      other->private_key, hello->ephemeral.public_key, hello->session_id, now, 30);
  NORR_CHECK(!result.authenticated);
  std::puts("reality: wrong server key is rejected (fallback) OK");
}

void test_stale_timestamp_fails() {
  const auto server = norr::generate_keypair();
  NORR_CHECK(server.has_value());
  const auto id = make_short_id(std::byte{0x02});
  const std::uint64_t now = 1'760'000'000;

  const auto hello = norr::reality_client_hello(server->public_key, id, now);
  NORR_CHECK(hello.has_value());

  const auto result = norr::reality_server_verify(
      server->private_key, hello->ephemeral.public_key, hello->session_id, now + 120, 30);
  NORR_CHECK(!result.authenticated);
  std::puts("reality: stale timestamp is rejected OK");
}

void test_tampered_session_id_fails() {
  const auto server = norr::generate_keypair();
  NORR_CHECK(server.has_value());
  const auto id = make_short_id(std::byte{0x03});
  const std::uint64_t now = 1'760'000'000;

  auto hello = norr::reality_client_hello(server->public_key, id, now);
  NORR_CHECK(hello.has_value());
  hello->session_id[0] ^= std::byte{0xFF};

  const auto result = norr::reality_server_verify(
      server->private_key, hello->ephemeral.public_key, hello->session_id, now, 30);
  NORR_CHECK(!result.authenticated);
  std::puts("reality: tampered session id is rejected OK");
}

void test_session_id_looks_random() {
  const auto server = norr::generate_keypair();
  NORR_CHECK(server.has_value());
  const auto id = make_short_id(std::byte{0x04});
  const std::uint64_t now = 1'760'000'000;

  const auto a = norr::reality_client_hello(server->public_key, id, now);
  const auto b = norr::reality_client_hello(server->public_key, id, now);
  NORR_CHECK(a.has_value() && b.has_value());
  NORR_CHECK(!std::equal(a->session_id.begin(), a->session_id.end(), b->session_id.begin()));
  std::puts("reality: session id differs per handshake (ephemeral) OK");
}
void test_server_auth_roundtrip() {
  const auto server = norr::generate_keypair();
  NORR_CHECK(server.has_value());
  const auto id = make_short_id(std::byte{0x05});

  const auto hello = norr::reality_client_hello(server->public_key, id, 1'760'000'000);
  NORR_CHECK(hello.has_value());

  const auto server_share = norr::generate_keypair();
  NORR_CHECK(server_share.has_value());

  const auto tag = norr::reality_server_auth(server->private_key, hello->ephemeral.public_key,
                                             server_share->public_key);
  NORR_CHECK(tag.has_value());
  NORR_CHECK(norr::reality_verify_server_auth(hello->ephemeral.private_key, server->public_key,
                                              server_share->public_key, *tag));
  std::puts("reality: server proves possession of its private key OK");
}

void test_server_auth_rejects_impostor() {
  const auto server = norr::generate_keypair();
  const auto impostor = norr::generate_keypair();
  NORR_CHECK(server.has_value() && impostor.has_value());
  const auto id = make_short_id(std::byte{0x06});

  const auto hello = norr::reality_client_hello(server->public_key, id, 1'760'000'000);
  NORR_CHECK(hello.has_value());

  const auto server_share = norr::generate_keypair();
  NORR_CHECK(server_share.has_value());

  // An active man in the middle sees the ClientHello and answers it, but holds
  // the wrong private key. Without this check it would be indistinguishable
  // from the real server.
  const auto forged = norr::reality_server_auth(impostor->private_key,
                                                hello->ephemeral.public_key,
                                                server_share->public_key);
  NORR_CHECK(forged.has_value());
  NORR_CHECK(!norr::reality_verify_server_auth(hello->ephemeral.private_key, server->public_key,
                                               server_share->public_key, *forged));
  std::puts("reality: an impostor server is rejected OK");
}

void test_server_auth_binds_key_share() {
  const auto server = norr::generate_keypair();
  NORR_CHECK(server.has_value());
  const auto id = make_short_id(std::byte{0x07});

  const auto hello = norr::reality_client_hello(server->public_key, id, 1'760'000'000);
  NORR_CHECK(hello.has_value());

  const auto share_a = norr::generate_keypair();
  const auto share_b = norr::generate_keypair();
  NORR_CHECK(share_a.has_value() && share_b.has_value());

  const auto tag = norr::reality_server_auth(server->private_key, hello->ephemeral.public_key,
                                             share_a->public_key);
  NORR_CHECK(tag.has_value());

  // The tag covers the server's key share, so swapping it invalidates the
  // proof. Otherwise a tag captured from one connection would authenticate a
  // different one.
  NORR_CHECK(!norr::reality_verify_server_auth(hello->ephemeral.private_key, server->public_key,
                                               share_b->public_key, *tag));
  std::puts("reality: the proof is bound to the server key share OK");
}
}

int main() {
  NORR_CHECK(norr::crypto_init().has_value());
  test_authenticated_roundtrip();
  test_wrong_server_key_fails();
  test_stale_timestamp_fails();
  test_tampered_session_id_fails();
  test_session_id_looks_random();
  test_server_auth_roundtrip();
  test_server_auth_rejects_impostor();
  test_server_auth_binds_key_share();
  std::puts("all reality auth-core tests passed");
  return 0;
}
