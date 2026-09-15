#include "check.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>

#if defined(__linux__)
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include "norr/metrics.hpp"

namespace {

norr::Endpoint endpoint_of(std::string_view text) {
  const auto parsed = norr::parse_endpoint(text);
  NORR_CHECK(parsed.has_value());
  return *parsed;
}

void test_rendering_is_valid_prometheus() {
  norr::WorkerStats worker{};
  worker.tun_to_udp = 17;
  worker.udp_to_tun = 23;
  worker.keepalives_received = 4;
  worker.record_drop(norr::DropReason::no_route);
  worker.record_drop(norr::DropReason::no_route);
  worker.record_drop(norr::DropReason::replayed);

  norr::ControlStats control{};
  control.handshakes_completed = 2;
  control.cookies_issued = 5;

  const norr::MetricsSnapshot snapshot{.worker = &worker,
                                       .control = &control,
                                       .tun = nullptr,
                                       .transport = nullptr,
                                       .sessions = 3,
                                       .peers = 4};

  const auto text = norr::render_prometheus(snapshot);

  NORR_CHECK(text.find("norr_packets_encrypted_total 17") != std::string::npos);
  NORR_CHECK(text.find("norr_packets_decrypted_total 23") != std::string::npos);
  NORR_CHECK(text.find("norr_keepalives_received_total 4") != std::string::npos);
  NORR_CHECK(text.find("norr_packets_dropped_total 3") != std::string::npos);
  NORR_CHECK(text.find("norr_handshakes_completed_total 2") != std::string::npos);
  NORR_CHECK(text.find("norr_cookies_issued_total 5") != std::string::npos);
  NORR_CHECK(text.find("norr_sessions 3") != std::string::npos);
  NORR_CHECK(text.find("norr_peers_configured 4") != std::string::npos);

  // Labelled series carry the reason, so an operator can tell a
  // misconfiguration from an attack without reading the code.
  NORR_CHECK(text.find("reason=\"no route to destination\"} 2") != std::string::npos);
  NORR_CHECK(text.find("reason=\"replayed packet\"} 1") != std::string::npos);

  // Every metric must be preceded by its HELP and TYPE, or a scraper rejects
  // the series.
  NORR_CHECK(text.find("# HELP norr_packets_encrypted_total") != std::string::npos);
  NORR_CHECK(text.find("# TYPE norr_packets_encrypted_total counter") != std::string::npos);
  NORR_CHECK(text.find("# TYPE norr_sessions gauge") != std::string::npos);

  // A null section must be omitted entirely rather than rendered as zeros,
  // which would look like a working interface reporting no traffic.
  NORR_CHECK(text.find("norr_tun_rx_packets_total") == std::string::npos);

  std::puts("metrics: prometheus rendering OK");
}

void test_absent_sections_are_omitted() {
  const norr::MetricsSnapshot empty{};
  const auto text = norr::render_prometheus(empty);

  NORR_CHECK(text.find("norr_packets_encrypted_total") == std::string::npos);
  NORR_CHECK(text.find("norr_handshakes_started_total") == std::string::npos);
  NORR_CHECK(text.find("norr_sessions 0") != std::string::npos);

  std::puts("metrics: absent sections omitted OK");
}

#if defined(__linux__)

void test_server_serves_a_scrape() {
  norr::MetricsServer server;
  if (!server.start(endpoint_of("127.0.0.1:19101"))) {
    std::puts("metrics: cannot bind, skipped");
    return;
  }
  NORR_CHECK(server.listening());

  const auto port = server.local_port();
  NORR_CHECK(port.has_value());
  NORR_CHECK(*port != 0);

  norr::WorkerStats worker{};
  worker.tun_to_udp = 99;
  const norr::MetricsSnapshot snapshot{.worker = &worker,
                                       .control = nullptr,
                                       .tun = nullptr,
                                       .transport = nullptr,
                                       .sessions = 1,
                                       .peers = 1};

  const int client = ::socket(AF_INET, SOCK_STREAM, 0);
  NORR_CHECK(client >= 0);

  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_port = htons(*port);
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  NORR_CHECK(::connect(client, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);

  const std::string request = "GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n";
  NORR_CHECK(::send(client, request.data(), request.size(), 0) ==
             static_cast<ssize_t>(request.size()));

  // The server is polled by the caller's loop, so nothing is served until the
  // application asks it to be.
  NORR_CHECK(server.poll(snapshot) == 1);
  NORR_CHECK(server.requests_served() == 1);

  std::string response;
  char buffer[4096];
  while (true) {
    const auto read_bytes = ::recv(client, buffer, sizeof(buffer), 0);
    if (read_bytes <= 0) break;
    response.append(buffer, static_cast<std::size_t>(read_bytes));
  }
  ::close(client);

  NORR_CHECK(response.starts_with("HTTP/1.1 200 OK"));
  NORR_CHECK(response.find("Content-Type: text/plain") != std::string::npos);
  NORR_CHECK(response.find("norr_packets_encrypted_total 99") != std::string::npos);

  // The advertised length must match the body, or a scraper hangs waiting for
  // bytes that never arrive.
  const auto header_end = response.find("\r\n\r\n");
  NORR_CHECK(header_end != std::string::npos);
  const auto marker = response.find("Content-Length: ");
  NORR_CHECK(marker != std::string::npos);
  const auto declared = std::stoul(response.substr(marker + 16));
  NORR_CHECK(response.size() - (header_end + 4) == declared);

  std::puts("metrics: HTTP scrape served OK");
}

void test_malformed_request_is_refused() {
  norr::MetricsServer server;
  if (!server.start(endpoint_of("127.0.0.1:19102"))) return;
  const auto port = server.local_port();
  NORR_CHECK(port.has_value());

  const norr::MetricsSnapshot snapshot{};

  const int client = ::socket(AF_INET, SOCK_STREAM, 0);
  NORR_CHECK(client >= 0);
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_port = htons(*port);
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  NORR_CHECK(::connect(client, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);

  const std::string junk = "NOTHTTP\r\n\r\n";
  static_cast<void>(::send(client, junk.data(), junk.size(), 0));

  NORR_CHECK(server.poll(snapshot) == 1);
  // Refused requests must not be counted as served.
  NORR_CHECK(server.requests_served() == 0);

  std::string response;
  char buffer[1024];
  while (true) {
    const auto read_bytes = ::recv(client, buffer, sizeof(buffer), 0);
    if (read_bytes <= 0) break;
    response.append(buffer, static_cast<std::size_t>(read_bytes));
  }
  ::close(client);

  NORR_CHECK(response.starts_with("HTTP/1.1 400"));

  std::puts("metrics: malformed request refused OK");
}

void test_starting_twice_is_refused() {
  norr::MetricsServer server;
  if (!server.start(endpoint_of("127.0.0.1:19103"))) return;
  const auto again = server.start(endpoint_of("127.0.0.1:19103"));
  NORR_CHECK(!again.has_value());
  NORR_CHECK(again.error() == norr::MetricsError::already_started);

  server.stop();
  NORR_CHECK(!server.listening());

  std::puts("metrics: double start refused OK");
}

#endif

}  // namespace

int main() {
  test_rendering_is_valid_prometheus();
  test_absent_sections_are_omitted();
#if defined(__linux__)
  test_server_serves_a_scrape();
  test_malformed_request_is_refused();
  test_starting_twice_is_refused();
#endif
  return 0;
}
