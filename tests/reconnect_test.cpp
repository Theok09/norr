
#include "check.hpp"
#include <chrono>
#include <cstdio>

#include "norr/tcp_transport.hpp"

namespace {
norr::Endpoint unreachable_peer() {
  const auto parsed = norr::parse_endpoint("127.0.0.1:1");
  NORR_CHECK(parsed.has_value());
  return *parsed;
}

void test_backoff_grows_and_clamps() {
  norr::TcpReconnector reconnector{unreachable_peer()};
  auto now = norr::Instant{};

  NORR_CHECK(reconnector.attempts() == 0);
  NORR_CHECK(reconnector.current_delay() == norr::TcpReconnector::kInitialDelay);

  reconnector.note_disconnected(now);
  NORR_CHECK(reconnector.current_delay() == norr::TcpReconnector::kInitialDelay * 2);

  reconnector.note_disconnected(now);
  NORR_CHECK(reconnector.current_delay() == norr::TcpReconnector::kInitialDelay * 4);

  for (int index = 0; index < 40; ++index) reconnector.note_disconnected(now);
  NORR_CHECK(reconnector.current_delay() == norr::TcpReconnector::kMaximumDelay);

  std::puts("reconnect: backoff grows and clamps OK");
}

void test_stable_connection_resets_backoff() {
  norr::TcpReconnector reconnector{unreachable_peer()};
  const auto now = norr::Instant{};

  for (int index = 0; index < 5; ++index) reconnector.note_disconnected(now);
  NORR_CHECK(reconnector.attempts() == 5);

  reconnector.note_stable();
  NORR_CHECK(reconnector.attempts() == 0);
  NORR_CHECK(reconnector.current_delay() == norr::TcpReconnector::kInitialDelay);

  std::puts("reconnect: stability resets backoff OK");
}

void test_retry_waits_for_the_delay() {
  norr::TcpReconnector reconnector{unreachable_peer()};
  auto now = norr::Instant{};

  reconnector.note_disconnected(now);
  const auto scheduled = reconnector.next_attempt();
  NORR_CHECK(scheduled > now);

  norr::TcpTransport transport;

  reconnector.poll(transport, now);
  NORR_CHECK(transport.state() == norr::TcpState::closed);
  NORR_CHECK(reconnector.attempts() == 1);

  now = scheduled + std::chrono::milliseconds{1};
  reconnector.poll(transport, now);
  NORR_CHECK(reconnector.attempts() >= 1);

  std::puts("reconnect: retry waits for its delay OK");
}

#if defined(__linux__)

void test_reconnects_to_a_live_listener() {
  const auto loopback = norr::parse_address("127.0.0.1");
  NORR_CHECK(loopback.has_value());

  norr::TcpListener listener;
  NORR_CHECK(listener.listen(norr::Endpoint{*loopback, 0}).has_value());
  const auto port = listener.local_port();
  NORR_CHECK(port.has_value());

  norr::TcpReconnector reconnector{norr::Endpoint{*loopback, *port}};
  norr::TcpTransport transport;
  auto now = norr::Instant{};

  for (int attempt = 0; attempt < 1000 && !transport.connected(); ++attempt) {
    reconnector.poll(transport, now);
    now += std::chrono::milliseconds{50};
  }
  NORR_CHECK(transport.connected());

  const auto before = reconnector.attempts();
  reconnector.poll(transport, now);
  NORR_CHECK(transport.connected());
  NORR_CHECK(reconnector.attempts() == before);

  std::puts("reconnect: connects to a live listener OK");
}

void test_failed_state_is_closed_before_retry() {
  norr::TcpReconnector reconnector{unreachable_peer()};
  norr::TcpTransport transport;
  auto now = norr::Instant{};

  for (int index = 0; index < 5; ++index) {
    reconnector.poll(transport, now);
    NORR_CHECK(transport.state() != norr::TcpState::failed);
    now += norr::TcpReconnector::kMaximumDelay;
  }

  std::puts("reconnect: failed connections are closed before retry OK");
}

#endif
}

int main() {
  test_backoff_grows_and_clamps();
  test_stable_connection_resets_backoff();
  test_retry_waits_for_the_delay();

#if defined(__linux__)
  test_reconnects_to_a_live_listener();
  test_failed_state_is_closed_before_retry();
#else
  std::puts("reconnect: not Linux, socket tests skipped");
#endif
  return 0;
}
