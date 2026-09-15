// TLS 1.3 over TCP with PSK authentication.
//
// Two real sockets, a real handshake. The properties that matter are that
// TLS 1.3 is actually negotiated, that a wrong PSK produces no session, and
// that data crosses encrypted.

#include "check.hpp"
#include <array>
#include <cstdio>
#include <string>
#include <vector>

#include "norr/tcp_transport.hpp"
#include "norr/tls.hpp"

namespace {

std::vector<std::byte> key_of(std::uint8_t fill) {
  return std::vector<std::byte>(32, static_cast<std::byte>(fill));
}

#if defined(__linux__) && defined(NORR_HAVE_GNUTLS)

// Connects a client and server socket pair over loopback.
struct SocketPair {
  norr::TcpListener listener;
  norr::TcpTransport client;
  std::optional<norr::TcpTransport> server;
};

bool make_pair(SocketPair& pair) {
  const auto loopback = norr::parse_address("127.0.0.1");
  NORR_CHECK(loopback.has_value());
  if (!pair.listener.listen(norr::Endpoint{*loopback, 0})) return false;

  const auto port = pair.listener.local_port();
  if (!port) return false;
  if (!pair.client.connect(norr::Endpoint{*loopback, *port})) return false;

  for (int attempt = 0; attempt < 1000 && !pair.client.connected(); ++attempt) {
    static_cast<void>(pair.client.poll_connect());
  }
  if (!pair.client.connected()) return false;

  for (int attempt = 0; attempt < 1000 && !pair.server.has_value(); ++attempt) {
    auto accepted = pair.listener.accept();
    if (!accepted) return false;
    if (accepted->has_value()) pair.server = std::move(**accepted);
  }
  return pair.server.has_value();
}

// Drives both sides of a non-blocking handshake to completion.
bool drive(norr::TlsSession& client, norr::TlsSession& server) {
  for (int attempt = 0; attempt < 5000; ++attempt) {
    const auto client_done = client.handshake();
    const auto server_done = server.handshake();
    if (!client_done || !server_done) return false;
    if (*client_done && *server_done) return true;
  }
  return false;
}

void test_handshake_and_transfer() {
  SocketPair pair;
  NORR_CHECK(make_pair(pair));

  const auto psk = key_of(0x5A);
  norr::TlsSession client;
  norr::TlsSession server;
  NORR_CHECK(client.start(pair.client.descriptor(), norr::TlsRole::client, "norr", psk)
                 .has_value());
  NORR_CHECK(server.start(pair.server->descriptor(), norr::TlsRole::server, "norr", psk)
                 .has_value());

  NORR_CHECK(drive(client, server));
  NORR_CHECK(client.established());
  NORR_CHECK(server.established());

  // TLS 1.3 specifically: an older version would mean the priority string
  // failed to restrict what was offered.
  const auto description = client.description();
  NORR_CHECK(description.find("1.3") != std::string::npos);
  std::printf("tls: negotiated %s\n", description.c_str());

  const std::vector<std::byte> payload(256, std::byte{0xC3});
  std::size_t sent = 0;
  for (int attempt = 0; attempt < 1000 && sent == 0; ++attempt) {
    const auto result = client.send(payload);
    NORR_CHECK(result.has_value());
    sent = *result;
  }
  NORR_CHECK(sent == payload.size());

  std::vector<std::byte> received(payload.size());
  std::size_t got = 0;
  for (int attempt = 0; attempt < 1000 && got == 0; ++attempt) {
    const auto result = server.receive(received);
    NORR_CHECK(result.has_value());
    got = *result;
  }
  NORR_CHECK(got == payload.size());
  NORR_CHECK(std::equal(payload.begin(), payload.end(), received.begin()));

  std::puts("tls: handshake and encrypted transfer OK");
}

void test_mismatched_psk_fails() {
  SocketPair pair;
  NORR_CHECK(make_pair(pair));

  norr::TlsSession client;
  norr::TlsSession server;
  NORR_CHECK(client.start(pair.client.descriptor(), norr::TlsRole::client, "norr", key_of(0x11))
                 .has_value());
  NORR_CHECK(server.start(pair.server->descriptor(), norr::TlsRole::server, "norr", key_of(0x22))
                 .has_value());

  // A wrong PSK must not produce a session. Either side may notice first.
  NORR_CHECK(!drive(client, server));
  NORR_CHECK(!(client.established() && server.established()));

  std::puts("tls: mismatched PSK produces no session OK");
}

void test_mismatched_identity_fails() {
  SocketPair pair;
  NORR_CHECK(make_pair(pair));

  const auto psk = key_of(0x5A);
  norr::TlsSession client;
  norr::TlsSession server;
  NORR_CHECK(client.start(pair.client.descriptor(), norr::TlsRole::client, "alice", psk)
                 .has_value());
  NORR_CHECK(server.start(pair.server->descriptor(), norr::TlsRole::server, "bob", psk)
                 .has_value());

  // The server looks up the key by identity and must refuse an unknown one,
  // even when the key itself would have matched.
  NORR_CHECK(!drive(client, server));

  std::puts("tls: unknown identity refused OK");
}

#endif  // __linux__ && NORR_HAVE_GNUTLS

void test_weak_parameters_refused() {
  if (!norr::tls_available()) return;

  norr::TlsSession session;
  // A short PSK is not key material. Refusing here means a misconfiguration
  // fails loudly rather than producing a brute-forceable session.
  const std::vector<std::byte> tiny(4, std::byte{1});
  const auto short_key = session.start(0, norr::TlsRole::client, "norr", tiny);
  NORR_CHECK(!short_key.has_value());
  NORR_CHECK(short_key.error() == norr::TlsError::bad_parameters);

  const auto no_identity = session.start(0, norr::TlsRole::client, "", key_of(1));
  NORR_CHECK(!no_identity.has_value());

  std::puts("tls: weak parameters refused OK");
}

void test_operations_before_handshake() {
  if (!norr::tls_available()) return;

  norr::TlsSession session;
  NORR_CHECK(!session.established());

  // Sending before the handshake completes must be refused, not queued into
  // an unprotected socket.
  const std::vector<std::byte> payload(16);
  const auto sent = session.send(payload);
  NORR_CHECK(!sent.has_value());

  std::puts("tls: operations before handshake refused OK");
}

}  // namespace

int main() {
  if (!norr::tls_available()) {
    std::puts("tls: backend not compiled in, skipped");
    return 0;
  }

  test_weak_parameters_refused();
  test_operations_before_handshake();

#if defined(__linux__) && defined(NORR_HAVE_GNUTLS)
  test_handshake_and_transfer();
  test_mismatched_psk_fails();
  test_mismatched_identity_fails();
#endif
  return 0;
}
