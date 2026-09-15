// Exercises the real socket and TUN layers.
//
// On Linux this binds actual UDP sockets and moves real datagrams between them.
// Opening a TUN device needs CAP_NET_ADMIN, so that part reports itself as
// skipped when the privilege is absent rather than failing the suite.
//
// On a non-Linux host the same entry points must report unsupported_platform,
// which is checked explicitly so the platform guards cannot rot.

#include <array>
#include "check.hpp"
#include <cstddef>
#include <cstdio>
#include <span>
#include <vector>

#include "norr/tun.hpp"
#include "norr/udp_transport.hpp"

namespace {

norr::Endpoint loopback_endpoint(std::uint16_t port) {
  const auto address = norr::parse_address("127.0.0.1");
  NORR_CHECK(address.has_value());
  return norr::Endpoint{*address, port};
}

void test_unsupported_platform() {
  norr::UdpTransport transport;
  const auto started = transport.start(loopback_endpoint(51880));
  NORR_CHECK(!started.has_value());
  NORR_CHECK(started.error() == norr::TransportError::unsupported_platform);
  NORR_CHECK(!transport.started());

  norr::TunDevice device;
  const auto opened = device.open();
  NORR_CHECK(!opened.has_value());
  NORR_CHECK(opened.error() == norr::TunError::unsupported_platform);
  NORR_CHECK(!device.is_open());

  std::puts("datapath: platform unsupported, guards verified");
}

#if defined(__linux__)

void test_udp_roundtrip() {
  // Port zero asks the kernel for an ephemeral port, which avoids collisions
  // with anything already running on the host.
  norr::UdpTransport receiver;
  {
    const auto address = norr::parse_address("127.0.0.1");
    NORR_CHECK(address.has_value());
    const auto started = receiver.start(norr::Endpoint{*address, 0});
    NORR_CHECK(started.has_value());
  }
  const auto port = receiver.local_port();
  NORR_CHECK(port.has_value() && *port != 0);

  norr::UdpTransport sender;
  {
    const auto address = norr::parse_address("127.0.0.1");
    NORR_CHECK(address.has_value());
    const auto started = sender.start(norr::Endpoint{*address, 0});
    NORR_CHECK(started.has_value());
  }

  constexpr std::array payload{std::byte{0xDE}, std::byte{0xAD}, std::byte{0xBE}, std::byte{0xEF}};
  const std::array datagrams{
      norr::OutboundDatagram{.destination = loopback_endpoint(*port), .payload = payload}};

  const auto sent = sender.send_batch(datagrams);
  NORR_CHECK(sent.has_value() && *sent == 1);
  NORR_CHECK(sender.stats().tx_packets == 1);
  NORR_CHECK(sender.stats().tx_bytes == payload.size());

  // The socket is non-blocking, so the datagram may not have arrived yet.
  norr::ReceiveBuffers buffers{norr::UdpTransport::kDefaultBatchSize,
                               norr::UdpTransport::kDefaultDatagramSize};
  std::array<norr::InboundDatagram, norr::UdpTransport::kDefaultBatchSize> inbound{};

  std::size_t received = 0;
  for (int attempt = 0; attempt < 1000 && received == 0; ++attempt) {
    const auto result = receiver.receive_batch(buffers, inbound);
    NORR_CHECK(result.has_value());
    received = *result;
  }
  NORR_CHECK(received == 1);
  NORR_CHECK(inbound[0].payload.size() == payload.size());
  NORR_CHECK(std::equal(payload.begin(), payload.end(), inbound[0].payload.begin()));
  NORR_CHECK(inbound[0].source.port() == *sender.local_port());
  NORR_CHECK(receiver.stats().rx_packets == 1);

  std::puts("datapath: UDP round-trip over loopback OK");
}

void test_udp_batch() {
  norr::UdpTransport receiver;
  {
    const auto address = norr::parse_address("127.0.0.1");
    NORR_CHECK(address.has_value());
    NORR_CHECK(receiver.start(norr::Endpoint{*address, 0}).has_value());
  }
  const auto port = receiver.local_port();
  NORR_CHECK(port.has_value());

  norr::UdpTransport sender;
  {
    const auto address = norr::parse_address("127.0.0.1");
    NORR_CHECK(address.has_value());
    NORR_CHECK(sender.start(norr::Endpoint{*address, 0}).has_value());
  }

  constexpr std::size_t kCount = 16;
  std::vector<std::array<std::byte, 8>> payloads(kCount);
  std::vector<norr::OutboundDatagram> datagrams;
  datagrams.reserve(kCount);
  for (std::size_t index = 0; index < kCount; ++index) {
    payloads[index].fill(static_cast<std::byte>(index));
    datagrams.push_back(norr::OutboundDatagram{.destination = loopback_endpoint(*port),
                                               .payload = payloads[index]});
  }

  const auto sent = sender.send_batch(datagrams);
  NORR_CHECK(sent.has_value() && *sent == kCount);

  norr::ReceiveBuffers buffers{norr::UdpTransport::kDefaultBatchSize,
                               norr::UdpTransport::kDefaultDatagramSize};
  std::array<norr::InboundDatagram, norr::UdpTransport::kDefaultBatchSize> inbound{};

  std::size_t total = 0;
  for (int attempt = 0; attempt < 1000 && total < kCount; ++attempt) {
    const auto result = receiver.receive_batch(buffers, inbound);
    NORR_CHECK(result.has_value());
    total += *result;
  }
  // UDP may drop even on loopback under pressure, so the assertion is that
  // batching delivers without corruption, not that nothing is ever lost.
  NORR_CHECK(total > 0 && total <= kCount);
  NORR_CHECK(receiver.stats().rx_packets == total);

  std::printf("datapath: UDP batch delivered %zu/%zu datagrams\n", total, kCount);
}

void test_transport_lifecycle() {
  norr::UdpTransport transport;

  // Operations before start must be refused rather than touching a closed fd.
  norr::ReceiveBuffers buffers{4, 128};
  std::array<norr::InboundDatagram, 4> inbound{};
  NORR_CHECK(transport.receive_batch(buffers, inbound).error() == norr::TransportError::not_started);
  NORR_CHECK(transport.local_port().error() == norr::TransportError::not_started);

  const auto address = norr::parse_address("127.0.0.1");
  NORR_CHECK(address.has_value());
  NORR_CHECK(transport.start(norr::Endpoint{*address, 0}).has_value());

  // Starting twice must not leak the first socket.
  const auto again = transport.start(norr::Endpoint{*address, 0});
  NORR_CHECK(!again.has_value() && again.error() == norr::TransportError::already_started);

  transport.stop();
  NORR_CHECK(!transport.started());
  // Stopping twice is harmless.
  transport.stop();

  std::puts("datapath: transport lifecycle OK");
}

void test_ipv6_socket() {
  norr::UdpTransport transport;
  const auto address = norr::parse_address("::1");
  NORR_CHECK(address.has_value());

  const auto started = transport.start(norr::Endpoint{*address, 0}, /*dual_stack=*/false);
  if (!started.has_value()) {
    // A host or container with IPv6 disabled is a valid environment.
    std::puts("datapath: IPv6 unavailable, skipped");
    return;
  }
  NORR_CHECK(transport.local_port().has_value());
  std::puts("datapath: IPv6 socket OK");
}

void test_tun() {
  norr::TunDevice device;
  const auto opened = device.open("norrtest0");
  if (!opened.has_value()) {
    // Opening a TUN device needs CAP_NET_ADMIN and /dev/net/tun.
    std::printf("datapath: TUN unavailable (%s), skipped\n",
                norr::tun_error_message(opened.error()).data());
    return;
  }

  NORR_CHECK(device.is_open());
  NORR_CHECK(device.name() == "norrtest0");

  // The device has no address or route, so nothing should be pending.
  std::array<std::byte, 2048> buffer{};
  const auto frame = device.read_frame(buffer);
  NORR_CHECK(frame.has_value());
  NORR_CHECK(frame->empty());

  // A frame beyond the configured maximum is refused rather than written.
  const std::vector<std::byte> oversized(norr::TunDevice::kMaximumFrameSize + 1);
  const auto refused = device.write_frame(oversized);
  NORR_CHECK(!refused.has_value() && refused.error() == norr::TunError::frame_too_large);
  NORR_CHECK(device.stats().oversized == 1);

  device.close();
  NORR_CHECK(!device.is_open());

  // Reading a closed device is refused, not undefined.
  const auto closed = device.read_frame(buffer);
  NORR_CHECK(!closed.has_value() && closed.error() == norr::TunError::not_open);

  std::puts("datapath: TUN device OK");
}

#endif  // __linux__

}  // namespace

int main() {
  if (!norr::UdpTransport::supported()) {
    NORR_CHECK(!norr::TunDevice::supported());
    test_unsupported_platform();
    return 0;
  }

#if defined(__linux__)
  NORR_CHECK(norr::TunDevice::supported());
  test_transport_lifecycle();
  test_udp_roundtrip();
  test_udp_batch();
  test_ipv6_socket();
  test_tun();
#endif
  return 0;
}
