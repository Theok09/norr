// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#include "norr/metrics.hpp"

#include <array>
#include <cstring>

#if defined(__linux__)
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace norr {
namespace {
void counter(std::string& out, std::string_view name, std::string_view help,
             std::uint64_t value) {
  out += "# HELP norr_";
  out += name;
  out += ' ';
  out += help;
  out += "\n# TYPE norr_";
  out += name;
  out += " counter\nnorr_";
  out += name;
  out += ' ';
  out += std::to_string(value);
  out += '\n';
}

void gauge(std::string& out, std::string_view name, std::string_view help, std::uint64_t value) {
  out += "# HELP norr_";
  out += name;
  out += ' ';
  out += help;
  out += "\n# TYPE norr_";
  out += name;
  out += " gauge\nnorr_";
  out += name;
  out += ' ';
  out += std::to_string(value);
  out += '\n';
}

void labelled_counter(std::string& out, std::string_view name, std::string_view help,
                      std::string_view label, const WorkerStats& stats) {
  out += "# HELP norr_";
  out += name;
  out += ' ';
  out += help;
  out += "\n# TYPE norr_";
  out += name;
  out += " counter\n";
  for (std::size_t index = 0; index < stats.drop_reasons.size(); ++index) {
    const auto reason = static_cast<DropReason>(index);
    if (reason == DropReason::none) continue;
    out += "norr_";
    out += name;
    out += '{';
    out += label;
    out += "=\"";
    out += drop_reason_message(reason);
    out += "\"} ";
    out += std::to_string(stats.drop_reasons[index]);
    out += '\n';
  }
}

}

std::string render_prometheus(const MetricsSnapshot& snapshot) {
  std::string out;
  out.reserve(4096);

  if (snapshot.worker != nullptr) {
    const auto& worker = *snapshot.worker;
    counter(out, "packets_encrypted_total", "inner packets sealed and sent to a peer",
            worker.tun_to_udp);
    counter(out, "packets_decrypted_total", "peer packets opened and written to the interface",
            worker.udp_to_tun);
    counter(out, "keepalives_received_total", "authenticated control frames carrying no payload",
            worker.keepalives_received);
    counter(out, "packets_dropped_total", "packets dropped for any reason", worker.drops);
    labelled_counter(out, "packets_dropped_by_reason_total", "packets dropped, by reason",
                     "reason", worker);
  }

  if (snapshot.control != nullptr) {
    const auto& control = *snapshot.control;
    counter(out, "handshakes_started_total", "handshakes this node initiated",
            control.handshakes_started);
    counter(out, "handshakes_completed_total", "handshakes that produced a session",
            control.handshakes_completed);
    counter(out, "handshakes_failed_total", "handshakes that failed", control.handshakes_failed);
    counter(out, "handshakes_timed_out_total", "half-open handshakes that expired",
            control.handshakes_timed_out);
    counter(out, "handshake_retries_total", "handshake retransmissions", control.retries);
    counter(out, "handshakes_rate_limited_total", "handshake messages shed before any DH",
            control.rate_limited);
    counter(out, "cookies_issued_total", "cookie challenges issued under load",
            control.cookies_issued);
    counter(out, "cookies_accepted_total", "cookie replies accepted", control.cookies_accepted);
    counter(out, "mac1_failures_total", "handshake messages with a bad mac1",
            control.mac1_failures);
    counter(out, "mac2_failures_total", "handshake messages with a bad mac2",
            control.mac2_failures);
    counter(out, "provisional_promoted_total",
            "responder handshakes proven by an authenticated frame",
            control.provisional_promoted);
  }

  if (snapshot.tun != nullptr) {
    const auto& tun = *snapshot.tun;
    counter(out, "tun_rx_packets_total", "frames read from the interface", tun.rx_frames);
    counter(out, "tun_tx_packets_total", "frames written to the interface", tun.tx_frames);
    counter(out, "tun_rx_bytes_total", "bytes read from the interface", tun.rx_bytes);
    counter(out, "tun_tx_bytes_total", "bytes written to the interface", tun.tx_bytes);
    counter(out, "tun_errors_total", "interface read and write errors",
            tun.rx_errors + tun.tx_errors);
  }

  if (snapshot.transport != nullptr) {
    const auto& transport = *snapshot.transport;
    counter(out, "udp_rx_packets_total", "datagrams received", transport.rx_packets);
    counter(out, "udp_tx_packets_total", "datagrams sent", transport.tx_packets);
    counter(out, "udp_rx_bytes_total", "bytes received", transport.rx_bytes);
    counter(out, "udp_tx_bytes_total", "bytes sent", transport.tx_bytes);
    counter(out, "udp_errors_total", "socket read and write errors",
            transport.rx_errors + transport.tx_errors);
    counter(out, "udp_rx_truncated_total", "datagrams larger than a receive slot",
            transport.rx_truncated);
  }

  gauge(out, "sessions", "established sessions", snapshot.sessions);
  gauge(out, "peers_configured", "peers in the configuration", snapshot.peers);

  return out;
}

MetricsServer::~MetricsServer() { stop(); }

void MetricsServer::stop() noexcept { socket_.reset(); }

#if !defined(__linux__)

std::expected<void, MetricsError> MetricsServer::start(const Endpoint&) {
  return std::unexpected(MetricsError::unsupported_platform);
}

std::expected<std::uint16_t, MetricsError> MetricsServer::local_port() const {
  return std::unexpected(MetricsError::unsupported_platform);
}

std::size_t MetricsServer::poll(const MetricsSnapshot&) { return 0; }

#else

std::expected<void, MetricsError> MetricsServer::start(const Endpoint& bind_address) {
  if (socket_.valid()) return std::unexpected(MetricsError::already_started);

  const auto family = bind_address.family();
  const auto domain = family == AddressFamily::ipv4 ? AF_INET : AF_INET6;

  FileDescriptor listener{::socket(domain, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0)};
  if (!listener.valid()) return std::unexpected(MetricsError::bind_failed);

  const int enable = 1;
  static_cast<void>(
      ::setsockopt(listener.get(), SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)));

  sockaddr_storage storage{};
  socklen_t length = 0;
  const auto octets = bind_address.address().bytes();

  if (family == AddressFamily::ipv4) {
    auto* address = reinterpret_cast<sockaddr_in*>(&storage);
    address->sin_family = AF_INET;
    address->sin_port = htons(bind_address.port());
    std::memcpy(&address->sin_addr.s_addr, octets.data(), 4);
    length = sizeof(sockaddr_in);
  } else {
    auto* address = reinterpret_cast<sockaddr_in6*>(&storage);
    address->sin6_family = AF_INET6;
    address->sin6_port = htons(bind_address.port());
    std::memcpy(address->sin6_addr.s6_addr, octets.data(), 16);
    length = sizeof(sockaddr_in6);
  }

  if (::bind(listener.get(), reinterpret_cast<sockaddr*>(&storage), length) != 0) {
    return std::unexpected(MetricsError::bind_failed);
  }
  if (::listen(listener.get(), 8) != 0) return std::unexpected(MetricsError::bind_failed);

  socket_ = std::move(listener);
  return {};
}

std::expected<std::uint16_t, MetricsError> MetricsServer::local_port() const {
  if (!socket_.valid()) return std::unexpected(MetricsError::bind_failed);
  sockaddr_storage storage{};
  socklen_t length = sizeof(storage);
  if (::getsockname(socket_.get(), reinterpret_cast<sockaddr*>(&storage), &length) != 0) {
    return std::unexpected(MetricsError::bind_failed);
  }
  if (storage.ss_family == AF_INET) {
    return ntohs(reinterpret_cast<const sockaddr_in*>(&storage)->sin_port);
  }
  return ntohs(reinterpret_cast<const sockaddr_in6*>(&storage)->sin6_port);
}

std::size_t MetricsServer::poll(const MetricsSnapshot& snapshot) {
  if (!socket_.valid()) return 0;

  std::size_t handled = 0;
  for (int index = 0; index < 8; ++index) {
    FileDescriptor client{::accept4(socket_.get(), nullptr, nullptr, SOCK_CLOEXEC)};
    if (!client.valid()) break;

    std::array<char, kMaximumRequestBytes> request{};
    const auto read_bytes = ::recv(client.get(), request.data(), request.size() - 1, 0);

    const bool ok = read_bytes > 0 &&
                    std::string_view{request.data(), static_cast<std::size_t>(read_bytes)}
                            .starts_with("GET ");

    std::string response;
    if (ok) {
      const auto body = render_prometheus(snapshot);
      response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\n";
      response += "Content-Length: " + std::to_string(body.size()) + "\r\n";
      response += "Connection: close\r\n\r\n";
      response += body;
      ++served_;
    } else {
      response =
          "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    }

    std::size_t written = 0;
    while (written < response.size()) {
      const auto sent = ::send(client.get(), response.data() + written,
                               response.size() - written, MSG_NOSIGNAL);
      if (sent <= 0) break;
      written += static_cast<std::size_t>(sent);
    }

    ++handled;
  }

  return handled;
}

#endif

}
