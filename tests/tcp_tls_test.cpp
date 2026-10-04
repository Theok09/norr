
#include "check.hpp"

#include <array>
#include <cstdio>
#include <cstring>
#include <span>
#include <string>
#include <thread>
#include <vector>

#if defined(__linux__)
#include <sys/socket.h>
#include <unistd.h>
#endif

#include "norr/tcp_transport.hpp"
#include "norr/tls.hpp"

namespace {
norr::PresharedKey make_psk() {
  norr::PresharedKey psk{};
  psk.fill(std::byte{0x7C});
  return psk;
}

#if defined(__linux__)

norr::Endpoint endpoint_of(std::string_view text) {
  const auto parsed = norr::parse_endpoint(text);
  NORR_CHECK(parsed.has_value());
  return *parsed;
}

bool complete_handshake(norr::TcpTransport& client, norr::TcpTransport& server) {
  for (int round = 0; round < 400; ++round) {
    const auto client_done = client.poll_tls();
    const auto server_done = server.poll_tls();
    if (!client_done || !server_done) return false;
    if (client.tls_established() && server.tls_established()) return true;
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
  }
  return false;
}

void test_frames_are_encrypted_end_to_end() {
  if (!norr::tls_available()) {
    std::puts("tcp-tls: no TLS backend, skipped");
    return;
  }

  norr::TcpListener listener;
  if (!listener.listen(endpoint_of("127.0.0.1:19311"))) {
    std::puts("tcp-tls: cannot bind, skipped");
    return;
  }
  const auto port = listener.local_port();
  NORR_CHECK(port.has_value());

  norr::TcpTransport client;
  const auto dial = client.connect(endpoint_of("127.0.0.1:" + std::to_string(*port)));
  NORR_CHECK(dial.has_value());

  std::optional<norr::TcpTransport> accepted;
  for (int attempt = 0; attempt < 200 && !accepted.has_value(); ++attempt) {
    auto incoming = listener.accept();
    NORR_CHECK(incoming.has_value());
    if (incoming->has_value()) accepted = std::move(**incoming);
    else std::this_thread::sleep_for(std::chrono::milliseconds(2));
  }
  NORR_CHECK(accepted.has_value());

  for (int attempt = 0; attempt < 200; ++attempt) {
    const auto connected = client.poll_connect();
    NORR_CHECK(connected.has_value());
    if (*connected) break;
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
  }
  NORR_CHECK(client.connected());

  const auto psk = make_psk();
  NORR_CHECK(client.enable_tls(norr::TlsRole::client, "norr", psk).has_value());
  NORR_CHECK(accepted->enable_tls(norr::TlsRole::server, "norr", psk).has_value());
  NORR_CHECK(client.tls_enabled());
  NORR_CHECK(!client.tls_established());

  NORR_CHECK(complete_handshake(client, *accepted));
  NORR_CHECK(client.tls_established());
  NORR_CHECK(accepted->tls_established());

  const std::vector<std::byte> payload(512, std::byte{0x5E});
  std::size_t put_bytes = 0;
  for (int attempt = 0; attempt < 200 && put_bytes == 0; ++attempt) {
    const auto sent = client.send_frame(payload);
    if (sent) {
      put_bytes = *sent;
      break;
    }
    NORR_CHECK(sent.error() == norr::TransportError::would_block);
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
  }
  NORR_CHECK(put_bytes == payload.size());

  std::array<std::span<const std::byte>, 4> frames{};
  std::size_t received = 0;
  for (int attempt = 0; attempt < 200 && received == 0; ++attempt) {
    const auto got = accepted->receive_frames(frames);
    NORR_CHECK(got.has_value());
    received = *got;
    if (received == 0) std::this_thread::sleep_for(std::chrono::milliseconds(2));
  }
  NORR_CHECK(received == 1);
  NORR_CHECK(frames[0].size() == payload.size());
  NORR_CHECK(std::equal(payload.begin(), payload.end(), frames[0].begin()));

  const std::vector<std::byte> reply(64, std::byte{0xA3});
  bool reply_sent = false;
  for (int attempt = 0; attempt < 200 && !reply_sent; ++attempt) {
    const auto put = accepted->send_frame(reply);
    if (put) {
      reply_sent = true;
      break;
    }
    NORR_CHECK(put.error() == norr::TransportError::would_block);
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
  }
  NORR_CHECK(reply_sent);

  received = 0;
  for (int attempt = 0; attempt < 200 && received == 0; ++attempt) {
    const auto got = client.receive_frames(frames);
    NORR_CHECK(got.has_value());
    received = *got;
    if (received == 0) std::this_thread::sleep_for(std::chrono::milliseconds(2));
  }
  NORR_CHECK(received == 1);
  NORR_CHECK(frames[0].size() == reply.size());
  NORR_CHECK(std::equal(reply.begin(), reply.end(), frames[0].begin()));

  std::puts("tcp-tls: frames traverse the TLS record layer in both directions OK");
}

void test_sending_before_the_handshake_is_refused() {
  if (!norr::tls_available()) return;

  norr::TcpListener listener;
  if (!listener.listen(endpoint_of("127.0.0.1:19312"))) return;
  const auto port = listener.local_port();
  NORR_CHECK(port.has_value());

  norr::TcpTransport client;
  NORR_CHECK(client.connect(endpoint_of("127.0.0.1:" + std::to_string(*port))).has_value());

  std::optional<norr::TcpTransport> accepted;
  for (int attempt = 0; attempt < 200 && !accepted.has_value(); ++attempt) {
    auto incoming = listener.accept();
    NORR_CHECK(incoming.has_value());
    if (incoming->has_value()) accepted = std::move(**incoming);
    else std::this_thread::sleep_for(std::chrono::milliseconds(2));
  }
  NORR_CHECK(accepted.has_value());

  for (int attempt = 0; attempt < 200; ++attempt) {
    const auto connected = client.poll_connect();
    NORR_CHECK(connected.has_value());
    if (*connected) break;
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
  }

  const auto psk = make_psk();
  NORR_CHECK(client.enable_tls(norr::TlsRole::client, "norr", psk).has_value());

  const std::vector<std::byte> payload(32, std::byte{0x11});
  const auto refused = client.send_frame(payload);
  NORR_CHECK(!refused.has_value());

  NORR_CHECK(!client.enable_tls(norr::TlsRole::client, "norr", psk).has_value());

  std::puts("tcp-tls: plaintext frames refused before the handshake OK");
}

#endif
}

int main() {
#if defined(__linux__)
  test_frames_are_encrypted_end_to_end();
  test_sending_before_the_handshake_is_refused();
#else
  std::puts("tcp-tls: Linux only, skipped");
#endif
  return 0;
}
