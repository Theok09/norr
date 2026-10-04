// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#include "norr/spooftest_cli.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <optional>
#include <string_view>

#include "norr/blake2s.hpp"
#include "norr/spooftest.hpp"

#if defined(__linux__)
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#endif

namespace norr {
namespace {
constexpr std::uint16_t kSpoofPort = 50505;

std::optional<std::uint32_t> parse_v4(std::string_view text) {
  std::uint32_t octets[4] = {0, 0, 0, 0};
  std::size_t index = 0;
  std::uint32_t value = 0;
  bool any = false;
  for (char ch : text) {
    if (ch == '.') {
      if (!any || index >= 3) return std::nullopt;
      octets[index++] = value;
      value = 0;
      any = false;
    } else if (ch >= '0' && ch <= '9') {
      value = value * 10 + static_cast<std::uint32_t>(ch - '0');
      if (value > 255) return std::nullopt;
      any = true;
    } else {
      return std::nullopt;
    }
  }
  if (!any || index != 3) return std::nullopt;
  octets[3] = value;
  return (octets[0] << 24U) | (octets[1] << 16U) | (octets[2] << 8U) | octets[3];
}

std::vector<std::uint32_t> expand(std::string_view spec) {
  std::vector<std::uint32_t> list;
  const auto dash = spec.find('-');
  if (dash == std::string_view::npos) {
    if (const auto one = parse_v4(spec)) list.push_back(*one);
    return list;
  }
  const auto lo = parse_v4(spec.substr(0, dash));
  const auto hi = parse_v4(spec.substr(dash + 1));
  if (!lo || !hi || *hi < *lo || *hi - *lo > 65535) return list;
  for (std::uint32_t a = *lo; a <= *hi; ++a) list.push_back(a);
  return list;
}

std::vector<std::byte> secret_bytes(std::string_view token) {
  std::vector<std::byte> out;
  out.reserve(token.size());
  for (char c : token) out.push_back(static_cast<std::byte>(static_cast<unsigned char>(c)));
  return out;
}

std::string flag(const std::vector<std::string>& args, std::string_view name) {
  for (std::size_t i = 0; i + 1 < args.size(); ++i) {
    if (args[i] == name) return args[i + 1];
  }
  return {};
}

#if !defined(__linux__)
int unsupported() {
  std::fprintf(stderr, "spooftest needs the Linux raw-socket backend\n");
  return 1;
}
int send_mode(const std::vector<std::string>&) { return unsupported(); }
int listen_mode(const std::vector<std::string>&) { return unsupported(); }
#else

int send_mode(const std::vector<std::string>& args) {
  const auto dest = parse_v4(flag(args, "--to"));
  const auto sources = expand(flag(args, "--sources"));
  const auto token = flag(args, "--token");
  if (!dest || sources.empty() || token.empty()) {
    std::fprintf(stderr, "usage: norrd spooftest send --to <ip> --sources <ip[-ip]> --token <secret>\n");
    return 1;
  }
  const auto secret = secret_bytes(token);

  const int raw = ::socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_RAW);
  if (raw < 0) {
    std::fprintf(stderr, "cannot open raw socket (need root or CAP_NET_RAW): %s\n", std::strerror(errno));
    return 1;
  }
  const int on = 1;
  static_cast<void>(::setsockopt(raw, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)));

  std::uint16_t sequence = 0;
  std::size_t sent = 0;
  for (std::uint32_t repeat = 0; repeat < 10; ++repeat) {
    for (const auto source : sources) {
      const auto probe = spoof_probe(secret, source, *dest, sequence);
      std::array<std::byte, 20 + 8 + kSpoofProbeSize> packet{};
      const auto n = build_spoofed_udp(source, *dest, kSpoofPort, kSpoofPort, probe, packet);
      if (n == 0) continue;
      sockaddr_in to{};
      to.sin_family = AF_INET;
      to.sin_port = htons(kSpoofPort);
      to.sin_addr.s_addr = htonl(*dest);
      const auto r = ::sendto(raw, packet.data(), n, 0, reinterpret_cast<sockaddr*>(&to), sizeof(to));
      if (r > 0) ++sent;
      ++sequence;
    }
    ::usleep(50000);
  }
  ::close(raw);
  std::printf("sent %zu spoofed probes to %u.%u.%u.%u from %zu source(s)\n", sent,
              (*dest >> 24U) & 0xFFU, (*dest >> 16U) & 0xFFU, (*dest >> 8U) & 0xFFU, *dest & 0xFFU,
              sources.size());
  std::printf("run the listener on the destination to see which arrived\n");
  return 0;
}

int listen_mode(const std::vector<std::string>& args) {
  const auto token = flag(args, "--token");
  auto seconds = 30;
  if (const auto s = flag(args, "--seconds"); !s.empty()) seconds = std::max(1, std::atoi(s.c_str()));
  if (token.empty()) {
    std::fprintf(stderr, "usage: norrd spooftest listen --token <secret> [--seconds N]\n");
    return 1;
  }
  const auto secret = secret_bytes(token);

  const int sock = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (sock < 0) {
    std::fprintf(stderr, "cannot open udp socket: %s\n", std::strerror(errno));
    return 1;
  }
  sockaddr_in bind_addr{};
  bind_addr.sin_family = AF_INET;
  bind_addr.sin_port = htons(kSpoofPort);
  bind_addr.sin_addr.s_addr = INADDR_ANY;
  if (::bind(sock, reinterpret_cast<sockaddr*>(&bind_addr), sizeof(bind_addr)) != 0) {
    std::fprintf(stderr, "cannot bind udp %u: %s\n", kSpoofPort, std::strerror(errno));
    ::close(sock);
    return 1;
  }
  const int want_pktinfo = 1;
  static_cast<void>(::setsockopt(sock, IPPROTO_IP, IP_PKTINFO, &want_pktinfo, sizeof(want_pktinfo)));

  std::printf("listening on udp %u for %ds; spoofed sources that arrive are listed\n", kSpoofPort,
              seconds);
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
  std::vector<std::uint32_t> seen;
  std::uint64_t valid = 0, bogus = 0;
  while (std::chrono::steady_clock::now() < deadline) {
    pollfd pfd{.fd = sock, .events = POLLIN, .revents = 0};
    if (::poll(&pfd, 1, 500) <= 0) continue;
    std::array<std::byte, 256> buf{};
    sockaddr_in from{};
    iovec iov{.iov_base = buf.data(), .iov_len = buf.size()};
    std::array<std::byte, 256> control{};
    msghdr msg{};
    msg.msg_name = &from;
    msg.msg_namelen = sizeof(from);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.data();
    msg.msg_controllen = control.size();
    const auto n = ::recvmsg(sock, &msg, 0);
    if (n <= 0) continue;

    std::uint32_t destination = 0;
    for (cmsghdr* c = CMSG_FIRSTHDR(&msg); c != nullptr; c = CMSG_NXTHDR(&msg, c)) {
      if (c->cmsg_level == IPPROTO_IP && c->cmsg_type == IP_PKTINFO) {
        in_pktinfo info{};
        std::memcpy(&info, CMSG_DATA(c), sizeof(info));
        destination = ntohl(info.ipi_addr.s_addr);
      }
    }
    const auto claimed = ntohl(from.sin_addr.s_addr);
    if (spoof_probe_valid(secret, std::span{buf}.first(static_cast<std::size_t>(n)),
                          static_cast<std::uint32_t>(claimed), destination)) {
      ++valid;
      if (std::find(seen.begin(), seen.end(), claimed) == seen.end()) {
        seen.push_back(claimed);
        std::printf("  arrived from spoofed %u.%u.%u.%u\n", (claimed >> 24U) & 0xFFU,
                    (claimed >> 16U) & 0xFFU, (claimed >> 8U) & 0xFFU, claimed & 0xFFU);
      }
    } else {
      ++bogus;
    }
  }
  ::close(sock);
  std::printf("\n%zu distinct spoofed source(s) crossed the network; %llu valid probes, %llu other packets\n",
              seen.size(), static_cast<unsigned long long>(valid),
              static_cast<unsigned long long>(bogus));
  if (seen.empty()) {
    std::printf("verdict: no spoofed packet arrived — this provider likely applies BCP38 egress filtering\n");
  } else {
    std::printf("verdict: spoofing works from the sender toward this host for those sources\n");
  }
  return 0;
}
#endif
}

int spooftest_main(const std::vector<std::string>& args) {
  if (!args.empty() && args.front() == "send") return send_mode(args);
  if (!args.empty() && args.front() == "listen") return listen_mode(args);
  std::fprintf(stderr,
               "usage:\n"
               "  norrd spooftest listen --token <secret> [--seconds N]\n"
               "  norrd spooftest send --to <ip> --sources <ip[-ip]> --token <secret>\n"
               "\n"
               "Run listen on the destination server and send on the source server with the\n"
               "same token. It reports which forged source addresses crossed the network, so\n"
               "you learn whether IP spoofing is possible between the two hosts before relying\n"
               "on it. It only sends probes and reads them; it changes nothing.\n");
  return 1;
}
}
