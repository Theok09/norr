// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#include "norr/camouflage.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <utility>

#include "norr/crypto.hpp"
#include "norr/reality.hpp"

namespace norr {
namespace {
void push_u8(std::vector<std::byte>& out, std::uint8_t value) {
  out.push_back(static_cast<std::byte>(value));
}
void push_u16(std::vector<std::byte>& out, std::uint16_t value) {
  out.push_back(static_cast<std::byte>(value >> 8U));
  out.push_back(static_cast<std::byte>(value & 0xFFU));
}
void push_bytes(std::vector<std::byte>& out, std::span<const std::byte> bytes) {
  out.insert(out.end(), bytes.begin(), bytes.end());
}
void push_random(std::vector<std::byte>& out, std::size_t count) {
  const auto base = out.size();
  out.resize(base + count);
  if (!random_bytes(std::span{out}.subspan(base, count))) {
    std::fill(out.begin() + static_cast<std::ptrdiff_t>(base), out.end(), std::byte{0});
  }
}

std::vector<std::byte> framed_handshake(std::uint8_t message_type,
                                        const std::vector<std::byte>& body,
                                        std::uint16_t record_version) {
  std::vector<std::byte> handshake;
  push_u8(handshake, message_type);
  push_u8(handshake, static_cast<std::uint8_t>((body.size() >> 16U) & 0xFFU));
  push_u8(handshake, static_cast<std::uint8_t>((body.size() >> 8U) & 0xFFU));
  push_u8(handshake, static_cast<std::uint8_t>(body.size() & 0xFFU));
  push_bytes(handshake, body);

  std::vector<std::byte> record;
  record.reserve(kTlsRecordHeaderSize + handshake.size());
  push_u8(record, static_cast<std::uint8_t>(TlsRecordType::handshake));
  push_u16(record, record_version);
  push_u16(record, static_cast<std::uint16_t>(handshake.size()));
  push_bytes(record, handshake);
  return record;
}

std::uint64_t unix_now() noexcept {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
}

std::span<const std::byte> extract_key_share_x25519(std::span<const std::byte> record) noexcept {
  const auto rd16 = [](std::span<const std::byte> b, std::size_t o) {
    return (static_cast<std::size_t>(static_cast<std::uint8_t>(b[o])) << 8U) |
           static_cast<std::size_t>(static_cast<std::uint8_t>(b[o + 1]));
  };
  std::size_t p = kTlsRecordHeaderSize + 4;
  if (record.size() < p + 2 + kTlsRandomSize + 1) return {};
  p += 2 + kTlsRandomSize;
  const auto sid_len = static_cast<std::size_t>(static_cast<std::uint8_t>(record[p]));
  p += 1 + sid_len;
  if (record.size() < p + 2) return {};
  const auto cipher_len = rd16(record, p);
  p += 2 + cipher_len;
  if (record.size() < p + 1) return {};
  const auto comp_len = static_cast<std::size_t>(static_cast<std::uint8_t>(record[p]));
  p += 1 + comp_len;
  if (record.size() < p + 2) return {};
  const auto ext_total = rd16(record, p);
  p += 2;
  const auto ext_end = std::min(record.size(), p + ext_total);
  while (p + 4 <= ext_end) {
    const auto ext_type = rd16(record, p);
    const auto ext_len = rd16(record, p + 2);
    const auto ext_body = p + 4;
    if (ext_body + ext_len > ext_end) break;
    if (ext_type == 0x0033) {
      std::size_t q = ext_body;
      if (q + 2 > ext_body + ext_len) return {};
      const auto list_len = rd16(record, q);
      q += 2;
      const auto list_end = std::min(ext_body + ext_len, q + list_len);
      while (q + 4 <= list_end) {
        const auto group = rd16(record, q);
        const auto klen = rd16(record, q + 2);
        const auto kbody = q + 4;
        if (kbody + klen > list_end) break;
        if (group == 0x001d && klen == kPublicKeySize) {
          return record.subspan(kbody, klen);
        }
        q = kbody + klen;
      }
      return {};
    }
    p = ext_body + ext_len;
  }
  return {};
}
}

std::size_t write_record_header(TlsRecordType type, std::size_t length,
                                std::span<std::byte> out) noexcept {
  if (out.size() < kTlsRecordHeaderSize) return 0;
  out[0] = static_cast<std::byte>(type);
  out[1] = std::byte{0x03};
  out[2] = std::byte{0x03};
  out[3] = static_cast<std::byte>((length >> 8U) & 0xFFU);
  out[4] = static_cast<std::byte>(length & 0xFFU);
  return kTlsRecordHeaderSize;
}

std::expected<TlsRecordView, CamouflageError> parse_record(
    std::span<const std::byte> bytes) noexcept {
  if (bytes.size() < kTlsRecordHeaderSize) return std::unexpected(CamouflageError::need_more);
  const auto type = static_cast<std::uint8_t>(bytes[0]);
  const auto major = static_cast<std::uint8_t>(bytes[1]);
  const auto length = (static_cast<std::size_t>(static_cast<std::uint8_t>(bytes[3])) << 8U) |
                      static_cast<std::size_t>(static_cast<std::uint8_t>(bytes[4]));
  if (major != 0x03) return std::unexpected(CamouflageError::malformed);
  if (type < 20 || type > 23) return std::unexpected(CamouflageError::malformed);
  if (length > kTlsMaxRecordPayload) return std::unexpected(CamouflageError::oversized);
  if (bytes.size() < kTlsRecordHeaderSize + length) return std::unexpected(CamouflageError::need_more);
  return TlsRecordView{.type = static_cast<TlsRecordType>(type),
                       .payload = bytes.subspan(kTlsRecordHeaderSize, length),
                       .consumed = kTlsRecordHeaderSize + length};
}

std::vector<std::byte> build_client_hello(std::string_view server_name,
                                         std::span<const std::byte> key_share,
                                         std::span<const std::byte> session_id) {
  static constexpr std::array<std::uint16_t, 15> kCiphers{
      0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9,
      0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035};

  std::vector<std::byte> body;
  push_u16(body, 0x0303);
  push_random(body, kTlsRandomSize);
  push_u8(body, static_cast<std::uint8_t>(kTlsSessionIdSize));
  if (session_id.size() == kTlsSessionIdSize) {
    push_bytes(body, session_id);
  } else {
    push_random(body, kTlsSessionIdSize);
  }

  push_u16(body, static_cast<std::uint16_t>(kCiphers.size() * 2));
  for (const auto cipher : kCiphers) push_u16(body, cipher);

  push_u8(body, 1);
  push_u8(body, 0);

  std::vector<std::byte> ext;

  push_u16(ext, 0x0000);
  {
    const auto name_len = static_cast<std::uint16_t>(server_name.size());
    push_u16(ext, static_cast<std::uint16_t>(name_len + 5));
    push_u16(ext, static_cast<std::uint16_t>(name_len + 3));
    push_u8(ext, 0);
    push_u16(ext, name_len);
    push_bytes(ext, std::as_bytes(std::span{server_name}));
  }

  push_u16(ext, 0x000b);
  push_u16(ext, 2);
  push_u8(ext, 1);
  push_u8(ext, 0);

  push_u16(ext, 0x000a);
  push_u16(ext, 8);
  push_u16(ext, 6);
  push_u16(ext, 0x001d);
  push_u16(ext, 0x0017);
  push_u16(ext, 0x0018);

  push_u16(ext, 0x0023);
  push_u16(ext, 0);

  push_u16(ext, 0x0010);
  push_u16(ext, 14);
  push_u16(ext, 12);
  push_u8(ext, 2);
  push_u8(ext, 'h');
  push_u8(ext, '2');
  push_u8(ext, 8);
  push_bytes(ext, std::as_bytes(std::span{std::string_view{"http/1.1"}}));

  push_u16(ext, 0x000d);
  {
    static constexpr std::array<std::uint16_t, 8> kSig{0x0403, 0x0804, 0x0401, 0x0503,
                                                       0x0805, 0x0501, 0x0806, 0x0601};
    push_u16(ext, static_cast<std::uint16_t>(kSig.size() * 2 + 2));
    push_u16(ext, static_cast<std::uint16_t>(kSig.size() * 2));
    for (const auto sig : kSig) push_u16(ext, sig);
  }

  push_u16(ext, 0x002b);
  push_u16(ext, 5);
  push_u8(ext, 4);
  push_u16(ext, 0x0304);
  push_u16(ext, 0x0303);

  push_u16(ext, 0x002d);
  push_u16(ext, 2);
  push_u8(ext, 1);
  push_u8(ext, 1);

  push_u16(ext, 0x0033);
  {
    push_u16(ext, static_cast<std::uint16_t>(kTlsRandomSize + 6));
    push_u16(ext, static_cast<std::uint16_t>(kTlsRandomSize + 4));
    push_u16(ext, 0x001d);
    push_u16(ext, static_cast<std::uint16_t>(kTlsRandomSize));
    if (key_share.size() == kTlsRandomSize) {
      push_bytes(ext, key_share);
    } else {
      push_random(ext, kTlsRandomSize);
    }
  }

  push_u16(body, static_cast<std::uint16_t>(ext.size()));
  push_bytes(body, ext);

  return framed_handshake(0x01, body, 0x0301);
}

std::vector<std::byte> build_server_hello(std::span<const std::byte> session_id) {
  std::vector<std::byte> body;
  push_u16(body, 0x0303);
  push_random(body, kTlsRandomSize);
  if (session_id.size() >= 1 && session_id.size() <= 32) {
    push_u8(body, static_cast<std::uint8_t>(session_id.size()));
    push_bytes(body, session_id);
  } else {
    push_u8(body, static_cast<std::uint8_t>(kTlsSessionIdSize));
    push_random(body, kTlsSessionIdSize);
  }
  push_u16(body, 0x1301);
  push_u8(body, 0);

  std::vector<std::byte> ext;
  push_u16(ext, 0x002b);
  push_u16(ext, 2);
  push_u16(ext, 0x0304);

  push_u16(ext, 0x0033);
  push_u16(ext, static_cast<std::uint16_t>(kTlsRandomSize + 4));
  push_u16(ext, 0x001d);
  push_u16(ext, static_cast<std::uint16_t>(kTlsRandomSize));
  push_random(ext, kTlsRandomSize);

  push_u16(body, static_cast<std::uint16_t>(ext.size()));
  push_bytes(body, ext);

  return framed_handshake(0x02, body, 0x0303);
}

std::vector<std::byte> build_change_cipher_spec() {
  std::vector<std::byte> record;
  push_u8(record, static_cast<std::uint8_t>(TlsRecordType::change_cipher_spec));
  push_u16(record, 0x0303);
  push_u16(record, 1);
  push_u8(record, 1);
  return record;
}

bool looks_like_client_hello(std::span<const std::byte> bytes) noexcept {
  if (bytes.size() < kTlsRecordHeaderSize + 4) return false;
  if (static_cast<std::uint8_t>(bytes[0]) != static_cast<std::uint8_t>(TlsRecordType::handshake)) {
    return false;
  }
  if (static_cast<std::uint8_t>(bytes[1]) != 0x03) return false;
  return static_cast<std::uint8_t>(bytes[kTlsRecordHeaderSize]) == 0x01;
}

std::vector<std::byte> CamouflageFramer::open() {
  opened_ = true;
  if (role_ != Role::client) return {};
  if (reality_enabled_) {
    auto hello = reality_client_hello(reality_server_public_, reality_short_id_, unix_now());
    if (hello) {
      reality_ephemeral_ = hello->ephemeral;
      return build_client_hello(server_name_, hello->ephemeral.public_key, hello->session_id);
    }
  }
  return build_client_hello(server_name_);
}

std::vector<std::byte> CamouflageFramer::wrap(std::span<const std::byte> payload) const {
  std::vector<std::byte> out;
  std::size_t offset = 0;
  while (offset < payload.size()) {
    const auto chunk = std::min<std::size_t>(kTlsMaxRecordPayload, payload.size() - offset);
    std::array<std::byte, kTlsRecordHeaderSize> header{};
    static_cast<void>(write_record_header(TlsRecordType::application_data, chunk, header));
    push_bytes(out, header);
    push_bytes(out, payload.subspan(offset, chunk));
    offset += chunk;
  }
  return out;
}

void CamouflageFramer::feed(std::span<const std::byte> bytes) {
  inbox_.insert(inbox_.end(), bytes.begin(), bytes.end());
}

void CamouflageFramer::compact() {
  if (consumed_ == 0) return;
  inbox_.erase(inbox_.begin(), inbox_.begin() + static_cast<std::ptrdiff_t>(consumed_));
  consumed_ = 0;
}

std::expected<std::span<const std::byte>, CamouflageError> CamouflageFramer::next_payload() {
  if (violated_) return std::unexpected(CamouflageError::malformed);
  while (true) {
    const std::span<const std::byte> view{inbox_.data() + consumed_, inbox_.size() - consumed_};
    const auto record = parse_record(view);
    if (!record) {
      if (record.error() == CamouflageError::need_more) {
        compact();
      } else {
        violated_ = true;
      }
      return std::unexpected(record.error());
    }

    if (record->type == TlsRecordType::handshake) {
      if (role_ == Role::server && !sent_reply_ && looks_like_client_hello(view)) {
        std::span<const std::byte> session_id{};
        constexpr std::size_t kSessionIdLenOffset = kTlsRecordHeaderSize + 4 + 2 + kTlsRandomSize;
        if (view.size() > kSessionIdLenOffset) {
          const auto sid_len = static_cast<std::size_t>(view[kSessionIdLenOffset]);
          if (sid_len <= 32 && view.size() >= kSessionIdLenOffset + 1 + sid_len) {
            session_id = view.subspan(kSessionIdLenOffset + 1, sid_len);
          }
        }
        if (reality_enabled_) {
          const auto key_share = extract_key_share_x25519(view.first(record->consumed));
          if (key_share.size() == kPublicKeySize &&
              session_id.size() == kRealitySessionIdSize) {
            PublicKey share{};
            std::copy(key_share.begin(), key_share.end(), share.begin());
            const auto verdict = reality_server_verify(reality_server_private_, share,
                                                       session_id, unix_now(), reality_window_);
            reality_authenticated_ = verdict.authenticated;
            reality_rejected_ = !verdict.authenticated;
          } else {
            reality_rejected_ = true;
          }
          if (reality_rejected_) {
            const auto raw = view.first(record->consumed);
            fallback_prelude_.assign(raw.begin(), raw.end());
          }
        }
        pending_reply_ = build_server_hello(session_id);
        const auto ccs = build_change_cipher_spec();
        pending_reply_.insert(pending_reply_.end(), ccs.begin(), ccs.end());
        sent_reply_ = true;
      }
      handshake_done_ = true;
      consumed_ += record->consumed;
      continue;
    }
    if (record->type != TlsRecordType::application_data) {
      handshake_done_ = true;
      consumed_ += record->consumed;
      continue;
    }

    scratch_.assign(record->payload.begin(), record->payload.end());
    consumed_ += record->consumed;
    handshake_done_ = true;
    if (consumed_ > 65536 || consumed_ * 2 > inbox_.size()) compact();
    return std::span<const std::byte>{scratch_};
  }
}

std::vector<std::byte> CamouflageFramer::take_handshake_reply() {
  return std::exchange(pending_reply_, {});
}
}
