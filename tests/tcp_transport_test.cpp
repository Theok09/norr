
#include "check.hpp"
#include <cstdio>
#include <string_view>
#include <vector>

#include "norr/tcp_transport.hpp"

namespace {
std::vector<std::byte> framed(std::span<const std::byte> body) {
  std::vector<std::byte> out;
  out.push_back(static_cast<std::byte>((body.size() >> 8U) & 0xFFU));
  out.push_back(static_cast<std::byte>(body.size() & 0xFFU));
  out.insert(out.end(), body.begin(), body.end());
  return out;
}

std::vector<std::byte> body_of(std::size_t size, std::uint8_t fill) {
  return std::vector<std::byte>(size, static_cast<std::byte>(fill));
}

void test_single_frame() {
  norr::FrameReassembler reassembler;
  const auto body = body_of(100, 0xAB);
  NORR_CHECK(reassembler.push(framed(body)));

  const auto frame = reassembler.next();
  NORR_CHECK(frame.size() == body.size());
  NORR_CHECK(std::equal(body.begin(), body.end(), frame.begin()));

  NORR_CHECK(reassembler.next().empty());

  std::puts("tcp: single frame OK");
}

void test_byte_at_a_time() {
  norr::FrameReassembler reassembler;
  const auto body = body_of(50, 0x11);
  const auto wire = framed(body);

  for (std::size_t index = 0; index + 1 < wire.size(); ++index) {
    NORR_CHECK(reassembler.push(std::span{wire}.subspan(index, 1)));
    NORR_CHECK(reassembler.next().empty());
  }
  NORR_CHECK(reassembler.push(std::span{wire}.last(1)));

  const auto frame = reassembler.next();
  NORR_CHECK(frame.size() == body.size());

  std::puts("tcp: byte-at-a-time delivery OK");
}

void test_multiple_frames_in_one_read() {
  norr::FrameReassembler reassembler;
  std::vector<std::byte> stream;
  for (std::uint8_t index = 0; index < 5; ++index) {
    const auto wire = framed(body_of(20 + index, index));
    stream.insert(stream.end(), wire.begin(), wire.end());
  }
  NORR_CHECK(reassembler.push(stream));

  for (std::uint8_t index = 0; index < 5; ++index) {
    const auto frame = reassembler.next();
    NORR_CHECK(frame.size() == static_cast<std::size_t>(20 + index));
    NORR_CHECK(frame[0] == static_cast<std::byte>(index));
  }
  NORR_CHECK(reassembler.next().empty());

  std::puts("tcp: multiple frames in one read OK");
}

void test_split_across_reads() {
  norr::FrameReassembler reassembler;
  const auto first = framed(body_of(30, 1));
  const auto second = framed(body_of(40, 2));

  std::vector<std::byte> stream = first;
  stream.insert(stream.end(), second.begin(), second.end());

  const auto split = first.size() + 1;
  NORR_CHECK(reassembler.push(std::span{stream}.first(split)));
  NORR_CHECK(reassembler.next().size() == 30);
  NORR_CHECK(reassembler.next().empty());

  NORR_CHECK(reassembler.push(std::span{stream}.subspan(split)));
  NORR_CHECK(reassembler.next().size() == 40);

  std::puts("tcp: frame split across reads OK");
}

void test_oversized_frame_is_refused() {
  norr::FrameReassembler reassembler{1000};

  std::vector<std::byte> header;
  header.push_back(std::byte{0xFF});
  header.push_back(std::byte{0xFF});
  NORR_CHECK(reassembler.push(header));

  NORR_CHECK(reassembler.next().empty());
  NORR_CHECK(reassembler.violated());

  NORR_CHECK(!reassembler.push(header));

  std::puts("tcp: oversized declared length refused OK");
}

void test_zero_length_frame() {
  norr::FrameReassembler reassembler;
  std::vector<std::byte> wire{std::byte{0}, std::byte{0}};
  NORR_CHECK(reassembler.push(wire));

  NORR_CHECK(reassembler.next().empty());
  NORR_CHECK(reassembler.buffered() == 0);

  std::puts("tcp: zero-length frame consumed OK");
}

void test_reset() {
  norr::FrameReassembler reassembler;
  NORR_CHECK(reassembler.push(framed(body_of(10, 1))));
  reassembler.reset();
  NORR_CHECK(reassembler.buffered() == 0);
  NORR_CHECK(!reassembler.violated());

  std::puts("tcp: reset clears state OK");
}

#if defined(__linux__)

void test_connect_and_exchange() {
  const auto loopback = norr::parse_address("127.0.0.1");
  NORR_CHECK(loopback.has_value());

  norr::TcpListener listener;
  const auto listening = listener.listen(norr::Endpoint{*loopback, 0});
  NORR_CHECK(listening.has_value());
  const auto port = listener.local_port();
  NORR_CHECK(port.has_value());

  norr::TcpTransport client;
  NORR_CHECK(client.connect(norr::Endpoint{*loopback, *port}).has_value());

  for (int attempt = 0; attempt < 1000 && !client.connected(); ++attempt) {
    static_cast<void>(client.poll_connect());
  }
  NORR_CHECK(client.connected());

  std::optional<norr::TcpTransport> server;
  for (int attempt = 0; attempt < 1000 && !server.has_value(); ++attempt) {
    auto accepted = listener.accept();
    NORR_CHECK(accepted.has_value());
    if (accepted->has_value()) server = std::move(**accepted);
  }
  NORR_CHECK(server.has_value());

  const auto body = body_of(200, 0x5A);
  NORR_CHECK(client.send_frame(body).has_value());

  std::array<std::span<const std::byte>, 4> frames{};
  std::size_t received = 0;
  for (int attempt = 0; attempt < 1000 && received == 0; ++attempt) {
    const auto result = server->receive_frames(frames);
    NORR_CHECK(result.has_value());
    received = *result;
  }
  NORR_CHECK(received == 1);
  NORR_CHECK(frames[0].size() == body.size());
  NORR_CHECK(std::equal(body.begin(), body.end(), frames[0].begin()));

  std::puts("tcp: connect and frame exchange OK");
}

void test_backpressure_keeps_framing() {
  const auto loopback = norr::parse_address("127.0.0.1");
  norr::TcpListener listener;
  NORR_CHECK(listener.listen(norr::Endpoint{*loopback, 0}).has_value());
  const auto port = listener.local_port();

  norr::TcpTransport client;
  NORR_CHECK(client.connect(norr::Endpoint{*loopback, *port}).has_value());
  for (int attempt = 0; attempt < 1000 && !client.connected(); ++attempt) {
    static_cast<void>(client.poll_connect());
  }
  std::optional<norr::TcpTransport> server;
  for (int attempt = 0; attempt < 1000 && !server.has_value(); ++attempt) {
    auto accepted = listener.accept();
    if (accepted && accepted->has_value()) server = std::move(**accepted);
  }
  NORR_CHECK(client.connected() && server.has_value());

  constexpr std::size_t kFrames = 400;
  std::size_t accepted = 0;
  std::size_t delivered = 0;
  std::size_t refusals = 0;
  std::array<std::span<const std::byte>, 16> frames{};
  for (int round = 0; round < 200000 && delivered < kFrames; ++round) {
    while (accepted < kFrames) {
      const auto body = body_of(60000 - accepted % 7, static_cast<std::uint8_t>(accepted));
      const auto sent = client.send_frame(body);
      if (!sent) {
        NORR_CHECK(sent.error() == norr::TransportError::would_block);
        ++refusals;
        break;
      }
      ++accepted;
    }
    static_cast<void>(client.flush_output());
    const auto received = server->receive_frames(frames);
    NORR_CHECK(received.has_value());
    for (std::size_t index = 0; index < *received; ++index) {
      const auto expected = body_of(60000 - delivered % 7, static_cast<std::uint8_t>(delivered));
      NORR_CHECK(frames[index].size() == expected.size());
      NORR_CHECK(std::equal(expected.begin(), expected.end(), frames[index].begin()));
      ++delivered;
    }
  }
  NORR_CHECK(delivered == kFrames);
  NORR_CHECK(refusals > 0);
  NORR_CHECK(!client.has_pending_output());
  std::puts("tcp: back pressure never splits a frame OK");
}

void test_state_before_connect() {
  norr::TcpTransport transport;
  NORR_CHECK(transport.state() == norr::TcpState::closed);
  NORR_CHECK(!transport.connected());

  NORR_CHECK(!transport.send_frame(body_of(10, 1)).has_value());
  std::array<std::span<const std::byte>, 1> frames{};
  NORR_CHECK(!transport.receive_frames(frames).has_value());

  std::puts("tcp: operations before connect refused OK");
}

#endif
}

int main() {
  test_single_frame();
  test_byte_at_a_time();
  test_multiple_frames_in_one_read();
  test_split_across_reads();
  test_oversized_frame_is_refused();
  test_zero_length_frame();
  test_reset();

#if defined(__linux__)
  test_connect_and_exchange();
  test_backpressure_keeps_framing();
  test_state_before_connect();
#else
  std::puts("tcp: not Linux, socket tests skipped");
#endif
  return 0;
}
