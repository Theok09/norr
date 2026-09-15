// Minimal UDP loop driving the Norr QUIC server against a real client.
#include <cstdio>
#include <vector>
#include <array>
#include "norr/crypto.hpp"
#include "norr/quic_transport.hpp"
#include "norr/udp_transport.hpp"
using namespace norr;

int main(int argc, char** argv) {
  (void)crypto_init();
  const auto bind = parse_endpoint(argc > 1 ? argv[1] : "127.0.0.1:4433");
  UdpTransport sock;
  if (!sock.start(*bind)) { std::puts("bind failed"); return 1; }
  std::printf("listening on %s\n", bind->to_string().c_str());
  std::fflush(stdout);

  ReceiveBuffers pool{8, 2048};
  std::array<InboundDatagram, 8> in{};
  Ngtcp2Connection server;
  bool accepted = false;

  for (int i = 0; i < 200000; ++i) {
    auto got = sock.receive_batch(pool, in);
    if (got && *got > 0) {
      for (std::size_t j = 0; j < *got; ++j) {
        std::vector<std::byte> copy(in[j].payload.begin(), in[j].payload.end());
        if (!accepted) {
          auto r = server.accept(*bind, in[j].source, copy);
          std::printf("accept: %s\n", r ? "ok" : quic_error_message(r.error()).data());
          std::fflush(stdout);
          if (!r) return 2;
          accepted = true;
        } else {
          static_cast<void>(server.feed(copy));
        }
        while (true) {
          auto out = server.next_outgoing();
          if (out.empty()) break;
          std::array<OutboundDatagram,1> d{OutboundDatagram{in[j].source, out}};
          static_cast<void>(sock.send_batch(d));
        }
      }
      if (server.established()) { std::puts("ESTABLISHED"); return 0; }
    }
  }
  std::printf("timeout, established=%d\n", (int)server.established());
  return 3;
}
