#include <array>
#include <algorithm>
#include "check.hpp"
#include <cstddef>
#include <cstdio>
#include <span>
#include <string_view>
#include <vector>

#include "norr/camouflage.hpp"
#include "norr/reality.hpp"
#include "norr/crypto.hpp"
#include "norr/crypto.hpp"

namespace {
std::uint16_t be16(std::span<const std::byte> b, std::size_t o) {
  return static_cast<std::uint16_t>((static_cast<std::uint8_t>(b[o]) << 8) |
                                    static_cast<std::uint8_t>(b[o + 1]));
}

void test_client_hello_is_valid_tls13() {
  const auto ch = norr::build_client_hello("www.microsoft.com");
  NORR_CHECK(ch.size() > 60);
  NORR_CHECK(static_cast<std::uint8_t>(ch[0]) == 22);
  NORR_CHECK(static_cast<std::uint8_t>(ch[1]) == 0x03);
  const auto rec_len = be16(ch, 3);
  NORR_CHECK(rec_len + norr::kTlsRecordHeaderSize == ch.size());
  NORR_CHECK(static_cast<std::uint8_t>(ch[5]) == 0x01);
  const auto hs_len = (static_cast<std::size_t>(static_cast<std::uint8_t>(ch[6])) << 16) |
                      (static_cast<std::size_t>(static_cast<std::uint8_t>(ch[7])) << 8) |
                      static_cast<std::size_t>(static_cast<std::uint8_t>(ch[8]));
  NORR_CHECK(hs_len + 4 + norr::kTlsRecordHeaderSize == ch.size());

  bool found_sni = false;
  bool found_supported_versions = false;
  bool found_key_share = false;
  for (std::size_t i = 9; i + 1 < ch.size(); ++i) {
    const auto v = be16(ch, i);
    if (v == 0x0000) found_sni = true;
    if (v == 0x002b) found_supported_versions = true;
    if (v == 0x0033) found_key_share = true;
  }
  NORR_CHECK(found_sni);
  NORR_CHECK(found_supported_versions);
  NORR_CHECK(found_key_share);
  NORR_CHECK(norr::looks_like_client_hello(ch));
  std::puts("camouflage: ClientHello is well-formed TLS 1.3 with SNI/versions/key_share OK");
}

void test_record_roundtrip() {
  std::array<std::byte, norr::kTlsRecordHeaderSize> hdr{};
  const auto n = norr::write_record_header(norr::TlsRecordType::application_data, 100, hdr);
  NORR_CHECK(n == norr::kTlsRecordHeaderSize);
  NORR_CHECK(static_cast<std::uint8_t>(hdr[0]) == 23);

  std::vector<std::byte> wire(hdr.begin(), hdr.end());
  for (int i = 0; i < 100; ++i) wire.push_back(static_cast<std::byte>(i));
  const auto rec = norr::parse_record(wire);
  NORR_CHECK(rec.has_value());
  NORR_CHECK(rec->type == norr::TlsRecordType::application_data);
  NORR_CHECK(rec->payload.size() == 100);
  NORR_CHECK(rec->consumed == 105);
  std::puts("camouflage: record header write/parse round-trips OK");
}

void test_partial_record_needs_more() {
  std::array<std::byte, norr::kTlsRecordHeaderSize> hdr{};
  static_cast<void>(norr::write_record_header(norr::TlsRecordType::application_data, 50, hdr));
  std::vector<std::byte> wire(hdr.begin(), hdr.end());
  for (int i = 0; i < 20; ++i) wire.push_back(std::byte{0});
  const auto rec = norr::parse_record(wire);
  NORR_CHECK(!rec.has_value());
  NORR_CHECK(rec.error() == norr::CamouflageError::need_more);
  std::puts("camouflage: truncated record reports need_more OK");
}

void test_client_hello_has_grease() {
  norr::CamouflageFramer client{norr::CamouflageFramer::Role::client, "example.org"};
  const auto hello = client.open();
  NORR_CHECK(norr::looks_like_client_hello(hello));

  auto is_grease = [](unsigned v) { return (v & 0x0F0FU) == 0x0A0AU && (v >> 8U) == (v & 0xFFU); };

  const std::size_t cipher_len_off = norr::kTlsRecordHeaderSize + 4 + 2 + norr::kTlsRandomSize + 1 + 32;
  const auto first_cipher = (static_cast<unsigned>(hello[cipher_len_off + 2]) << 8U) |
                            static_cast<unsigned>(hello[cipher_len_off + 3]);
  NORR_CHECK(is_grease(first_cipher));

  bool grease_ext = false;
  for (std::size_t i = cipher_len_off; i + 1 < hello.size(); ++i) {
    const auto v = (static_cast<unsigned>(hello[i]) << 8U) | static_cast<unsigned>(hello[i + 1]);
    if (is_grease(v)) { grease_ext = true; break; }
  }
  NORR_CHECK(grease_ext);

  const auto share = norr::extract_key_share_x25519(hello);
  NORR_CHECK(share.size() == norr::kPublicKeySize);
  std::puts("camouflage: ClientHello carries GREASE and a readable x25519 key_share OK");
}

void test_framer_handshake_and_data() {
  norr::CamouflageFramer client{norr::CamouflageFramer::Role::client, "cdn.example.com"};
  norr::CamouflageFramer server{norr::CamouflageFramer::Role::server};

  const auto hello = client.open();
  NORR_CHECK(!hello.empty());
  NORR_CHECK(norr::looks_like_client_hello(hello));

  server.feed(hello);
  NORR_CHECK(!server.next_payload().has_value());
  const auto reply = server.take_handshake_reply();
  NORR_CHECK(!reply.empty());
  NORR_CHECK(server.handshake_done());

  client.feed(reply);
  NORR_CHECK(!client.next_payload().has_value());
  NORR_CHECK(client.handshake_done());

  std::vector<std::byte> msg;
  for (int i = 0; i < 300; ++i) msg.push_back(static_cast<std::byte>(i * 7));
  const auto framed = client.wrap(msg);
  NORR_CHECK(static_cast<std::uint8_t>(framed[0]) == 23);

  server.feed(framed);
  const auto got = server.next_payload();
  NORR_CHECK(got.has_value());
  NORR_CHECK(got->size() == msg.size());
  NORR_CHECK(std::equal(msg.begin(), msg.end(), got->begin()));
  std::puts("camouflage: client<->server framer handshake + data payload OK");
}

void test_framer_byte_dribble() {
  norr::CamouflageFramer client{norr::CamouflageFramer::Role::client};
  norr::CamouflageFramer server{norr::CamouflageFramer::Role::server};
  server.feed(client.open());
  static_cast<void>(server.next_payload());
  client.feed(server.take_handshake_reply());
  static_cast<void>(client.next_payload());

  std::vector<std::byte> msg(500);
  for (std::size_t i = 0; i < msg.size(); ++i) msg[i] = static_cast<std::byte>(i);
  const auto framed = server.wrap(msg);

  for (const auto b : framed) {
    const std::array<std::byte, 1> one{b};
    client.feed(one);
  }
  const auto got = client.next_payload();
  NORR_CHECK(got.has_value());
  NORR_CHECK(got->size() == msg.size());
  NORR_CHECK(std::equal(msg.begin(), msg.end(), got->begin()));
  std::puts("camouflage: record reassembles across 1-byte dribble OK");
}

void test_large_payload_splits_records() {
  norr::CamouflageFramer client{norr::CamouflageFramer::Role::client};
  std::vector<std::byte> big(40000, std::byte{0xAB});
  const auto framed = client.wrap(big);
  std::size_t offset = 0;
  std::size_t total = 0;
  int records = 0;
  while (offset < framed.size()) {
    const auto rec = norr::parse_record(std::span{framed}.subspan(offset));
    NORR_CHECK(rec.has_value());
    NORR_CHECK(rec->payload.size() <= norr::kTlsMaxRecordPayload);
    total += rec->payload.size();
    offset += rec->consumed;
    ++records;
  }
  NORR_CHECK(total == big.size());
  NORR_CHECK(records == 3);
  std::puts("camouflage: oversized payload splits into <=16KB records OK");
}
}

void test_malformed_record_is_fatal() {
  norr::CamouflageFramer f{norr::CamouflageFramer::Role::server};
  std::array<std::byte, 8> junk{std::byte{0x99}, std::byte{0x02}, std::byte{0x03},
                               std::byte{0xFF}, std::byte{0xFF}, std::byte{0x00},
                               std::byte{0x00}, std::byte{0x00}};
  f.feed(junk);
  const auto p = f.next_payload();
  NORR_CHECK(!p.has_value());
  NORR_CHECK(f.violated());
  const auto p2 = f.next_payload();
  NORR_CHECK(!p2.has_value());
  std::puts("camouflage: malformed record marks framer violated OK");
}


void test_reality_authenticated_client() {
  const auto server = norr::generate_keypair();
  NORR_CHECK(server.has_value());
  norr::RealityShortId id{};
  std::fill(id.begin(), id.end(), std::byte{0x5A});

  norr::CamouflageFramer client{norr::CamouflageFramer::Role::client, "www.microsoft.com"};
  client.configure_reality_client(server->public_key, id);
  norr::CamouflageFramer srv{norr::CamouflageFramer::Role::server};
  srv.configure_reality_server(server->private_key, 120);

  const auto hello = client.open();
  NORR_CHECK(!hello.empty());
  srv.feed(hello);
  static_cast<void>(srv.next_payload());
  NORR_CHECK(srv.reality_authenticated());
  NORR_CHECK(!srv.reality_rejected());
  std::puts("camouflage/reality: authenticated client accepted OK");
}

// The server half was already covered. This is the other half: a client that
// accepts whoever answers is wide open to an active man in the middle, which
// is exactly the adversary REALITY exists to defeat.
void test_reality_client_verifies_server() {
  const auto server = norr::generate_keypair();
  NORR_CHECK(server.has_value());
  norr::RealityShortId id{};
  std::fill(id.begin(), id.end(), std::byte{0x5B});

  norr::CamouflageFramer client{norr::CamouflageFramer::Role::client, "www.microsoft.com"};
  client.configure_reality_client(server->public_key, id);
  norr::CamouflageFramer srv{norr::CamouflageFramer::Role::server};
  srv.configure_reality_server(server->private_key, 120);

  const auto hello = client.open();
  srv.feed(hello);
  static_cast<void>(srv.next_payload());
  NORR_CHECK(srv.reality_authenticated());

  const auto reply = srv.take_handshake_reply();
  NORR_CHECK(!reply.empty());

  client.feed(reply);
  static_cast<void>(client.next_payload());
  NORR_CHECK(client.reality_server_verified());
  NORR_CHECK(!client.violated());
  std::puts("camouflage/reality: client verifies the real server OK");
}

void test_reality_client_rejects_impostor_server() {
  const auto server = norr::generate_keypair();
  const auto impostor = norr::generate_keypair();
  NORR_CHECK(server.has_value() && impostor.has_value());
  norr::RealityShortId id{};
  std::fill(id.begin(), id.end(), std::byte{0x5C});

  norr::CamouflageFramer client{norr::CamouflageFramer::Role::client, "www.microsoft.com"};
  client.configure_reality_client(server->public_key, id);

  const auto hello = client.open();

  // A rejecting server sends nothing, which is the probe-resistance path and
  // not what is under test here. The adversary that matters answers in full:
  // it forges a complete ServerHello with its own key share and the best tag
  // its wrong private key can produce.
  const auto client_share = norr::extract_key_share_x25519(std::span{hello});
  NORR_CHECK(client_share.size() == norr::kPublicKeySize);
  norr::PublicKey share{};
  std::copy(client_share.begin(), client_share.end(), share.begin());

  const auto rogue_share = norr::generate_keypair();
  NORR_CHECK(rogue_share.has_value());
  const auto forged = norr::reality_server_auth(impostor->private_key, share,
                                                rogue_share->public_key);
  NORR_CHECK(forged.has_value());

  norr::RealitySessionId echoed{};
  const auto sid = std::span{hello}.subspan(
      norr::kTlsRecordHeaderSize + 4 + 2 + norr::kTlsRandomSize + 1,
      norr::kRealitySessionIdSize);
  std::copy(sid.begin(), sid.end(), echoed.begin());

  const auto reply = norr::build_server_hello(echoed, rogue_share->public_key, *forged);
  NORR_CHECK(!reply.empty());

  client.feed(reply);
  static_cast<void>(client.next_payload());
  NORR_CHECK(!client.reality_server_verified());
  NORR_CHECK(client.violated());
  std::puts("camouflage/reality: client rejects a forged ServerHello OK");
}

// Verifying only records that are a ServerHello lets an impostor skip it: send
// a handshake of another type, or go straight to application data, and the
// check never fires. Nothing from the server may be accepted before the proof.
void test_reality_client_rejects_skipped_server_hello() {
  const auto server = norr::generate_keypair();
  NORR_CHECK(server.has_value());
  norr::RealityShortId id{};
  std::fill(id.begin(), id.end(), std::byte{0x5D});

  norr::CamouflageFramer client{norr::CamouflageFramer::Role::client, "www.microsoft.com"};
  client.configure_reality_client(server->public_key, id);
  static_cast<void>(client.open());

  // Straight to application data, no ServerHello at all.
  std::array<std::byte, 8> payload{};
  std::array<std::byte, norr::kTlsRecordHeaderSize> header{};
  static_cast<void>(norr::write_record_header(norr::TlsRecordType::application_data,
                                              payload.size(), header));
  std::vector<std::byte> record(header.begin(), header.end());
  record.insert(record.end(), payload.begin(), payload.end());

  client.feed(record);
  const auto opened = client.next_payload();
  NORR_CHECK(!opened.has_value());
  NORR_CHECK(!client.reality_server_verified());
  NORR_CHECK(client.violated());
  std::puts("camouflage/reality: client rejects a skipped ServerHello OK");
}

void test_certificate_flight_is_sent_and_discarded() {
  norr::CamouflageFramer client{norr::CamouflageFramer::Role::client, "cdn.example.com"};
  norr::CamouflageFramer server{norr::CamouflageFramer::Role::server};

  server.feed(client.open());
  static_cast<void>(server.next_payload());
  const auto reply = server.take_handshake_reply();
  NORR_CHECK(reply.size() > 1700);

  client.feed(reply);
  NORR_CHECK(!client.next_payload().has_value());
  NORR_CHECK(!client.violated());

  std::vector<std::byte> msg;
  for (int i = 0; i < 200; ++i) msg.push_back(static_cast<std::byte>(i));
  client.feed(server.wrap(msg));
  const auto got = client.next_payload();
  NORR_CHECK(got.has_value());
  NORR_CHECK(got->size() == msg.size());
  NORR_CHECK(std::equal(msg.begin(), msg.end(), got->begin()));
  std::puts("camouflage: certificate flight sent, discarded, data follows intact OK");
}

void test_reality_probe_rejected() {
  const auto server = norr::generate_keypair();
  NORR_CHECK(server.has_value());

  norr::CamouflageFramer probe{norr::CamouflageFramer::Role::client, "www.microsoft.com"};
  norr::CamouflageFramer srv{norr::CamouflageFramer::Role::server};
  srv.configure_reality_server(server->private_key, 120);

  const auto hello = probe.open();
  NORR_CHECK(!hello.empty());
  srv.feed(hello);
  static_cast<void>(srv.next_payload());
  NORR_CHECK(!srv.reality_authenticated());
  NORR_CHECK(srv.reality_rejected());
  std::puts("camouflage/reality: unauthenticated probe rejected (fallback) OK");
}

void test_reality_wrong_key_rejected() {
  const auto server = norr::generate_keypair();
  const auto other = norr::generate_keypair();
  NORR_CHECK(server.has_value() && other.has_value());
  norr::RealityShortId id{};
  std::fill(id.begin(), id.end(), std::byte{0x11});

  norr::CamouflageFramer client{norr::CamouflageFramer::Role::client, "www.microsoft.com"};
  client.configure_reality_client(other->public_key, id);
  norr::CamouflageFramer srv{norr::CamouflageFramer::Role::server};
  srv.configure_reality_server(server->private_key, 120);

  const auto hello = client.open();
  srv.feed(hello);
  static_cast<void>(srv.next_payload());
  NORR_CHECK(!srv.reality_authenticated());
  std::puts("camouflage/reality: wrong server key rejected OK");
}

int main() {
  if (norr::crypto_available()) static_cast<void>(norr::crypto_init());
  test_client_hello_is_valid_tls13();
  test_record_roundtrip();
  test_partial_record_needs_more();
  test_framer_handshake_and_data();
  test_client_hello_has_grease();
  test_framer_byte_dribble();
  test_large_payload_splits_records();
  test_malformed_record_is_fatal();
  test_reality_authenticated_client();
  test_reality_probe_rejected();
  test_reality_wrong_key_rejected();
  test_reality_client_verifies_server();
  test_reality_client_rejects_impostor_server();
  test_reality_client_rejects_skipped_server_hello();
  test_certificate_flight_is_sent_and_discarded();
  std::puts("camouflage: all checks passed");
  return 0;
}
