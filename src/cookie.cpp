// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#include "norr/cookie.hpp"

#include <algorithm>
#include <cstring>

#include "norr/blake2s.hpp"

#if defined(NORR_HAVE_LIBSODIUM)
#include <sodium.h>
#endif

namespace norr {
namespace {
[[nodiscard]] std::array<std::byte, 32> hash_label_and_key(std::string_view label,
                                                           const PublicKey& key) noexcept {
  Blake2s state;
  std::array<std::byte, 8> label_bytes{};
  for (std::size_t index = 0; index < label.size() && index < label_bytes.size(); ++index) {
    label_bytes[index] = static_cast<std::byte>(static_cast<unsigned char>(label[index]));
  }
  state.update(label_bytes);
  state.update(key);

  Blake2s::Digest digest{};
  state.finish(digest);

  std::array<std::byte, 32> out{};
  std::copy(digest.begin(), digest.end(), out.begin());
  return out;
}

constexpr void write_u32(std::span<std::byte> out, std::size_t offset, std::uint32_t value) noexcept {
  out[offset] = static_cast<std::byte>((value >> 24U) & 0xFFU);
  out[offset + 1] = static_cast<std::byte>((value >> 16U) & 0xFFU);
  out[offset + 2] = static_cast<std::byte>((value >> 8U) & 0xFFU);
  out[offset + 3] = static_cast<std::byte>(value & 0xFFU);
}

[[nodiscard]] constexpr std::uint32_t read_u32(std::span<const std::byte> bytes,
                                               std::size_t offset) noexcept {
  return (static_cast<std::uint32_t>(bytes[offset]) << 24U) |
         (static_cast<std::uint32_t>(bytes[offset + 1]) << 16U) |
         (static_cast<std::uint32_t>(bytes[offset + 2]) << 8U) |
         static_cast<std::uint32_t>(bytes[offset + 3]);
}

}

Mac keyed_mac(std::span<const std::byte> key, std::span<const std::byte> message) noexcept {
  Blake2s state{kMacSize, key};
  state.update(message);

  Mac mac{};
  state.finish(mac);
  return mac;
}

std::array<std::byte, 32> mac1_key(const PublicKey& responder_static) noexcept {
  return hash_label_and_key(kLabelMac1, responder_static);
}

std::array<std::byte, 32> cookie_key(const PublicKey& responder_static) noexcept {
  return hash_label_and_key(kLabelCookie, responder_static);
}

std::expected<std::size_t, CookieError> serialize_cookie_reply(const CookieReply& reply,
                                                               std::span<std::byte> out) noexcept {
  if (out.size() < kCookieReplySize) return std::unexpected(CookieError::buffer_too_small);

  write_u32(out, 0, reply.receiver_index);
  std::copy(reply.nonce.begin(), reply.nonce.end(), out.begin() + 4);
  std::copy(reply.encrypted_cookie.begin(), reply.encrypted_cookie.end(),
            out.begin() + 4 + static_cast<std::ptrdiff_t>(kCookieNonceSize));
  return kCookieReplySize;
}

std::expected<CookieReply, CookieError> parse_cookie_reply(
    std::span<const std::byte> bytes) noexcept {
  if (bytes.size() < kCookieReplySize) return std::unexpected(CookieError::message_too_short);

  CookieReply reply{};
  reply.receiver_index = read_u32(bytes, 0);
  std::copy_n(bytes.begin() + 4, kCookieNonceSize, reply.nonce.begin());
  std::copy_n(bytes.begin() + 4 + static_cast<std::ptrdiff_t>(kCookieNonceSize),
              reply.encrypted_cookie.size(), reply.encrypted_cookie.begin());
  return reply;
}

CookieIssuer::CookieIssuer(const PublicKey& local_static)
    : mac1_key_(mac1_key(local_static)), cookie_key_(cookie_key(local_static)) {}

void CookieIssuer::refresh(Instant now) {
  const auto expired = secret_created_ == Instant{} ||
                       now - secret_created_ >= kCookieSecretLifetime;
  if (!expired) return;

  if (secret_created_ != Instant{}) {
    previous_secret_ = secret_;
    has_previous_ = true;
  }

  if (!random_bytes(secret_)) {
    secret_ = {};
  }
  secret_created_ = now;
}

Cookie CookieIssuer::compute_cookie(const Endpoint& source, Instant now) {
  refresh(now);
  const auto mac = keyed_mac(secret_, source.address().bytes());
  Cookie cookie{};
  std::copy(mac.begin(), mac.end(), cookie.begin());
  return cookie;
}

Mac CookieIssuer::compute_mac1(std::span<const std::byte> message) const noexcept {
  return keyed_mac(mac1_key_, message);
}

bool CookieIssuer::verify_mac1(std::span<const std::byte> message, const Mac& mac1) const noexcept {
  const auto expected = compute_mac1(message);
  return constant_time_equal(expected, mac1);
}

bool CookieIssuer::verify_mac2(const Endpoint& source, std::span<const std::byte> message,
                               const Mac& mac2, Instant now) {
  refresh(now);

  const auto check = [&](std::span<const std::byte> secret) {
    const auto mac = keyed_mac(secret, source.address().bytes());
    Cookie cookie{};
    std::copy(mac.begin(), mac.end(), cookie.begin());
    const auto expected = keyed_mac(cookie, message);
    return constant_time_equal(expected, mac2);
  };

  if (check(secret_)) return true;

  return has_previous_ && check(previous_secret_);
}

#if !defined(NORR_HAVE_LIBSODIUM)

std::expected<CookieReply, CookieError> CookieIssuer::build_reply(const Endpoint&, std::uint32_t,
                                                                  const Mac&, Instant) {
  return std::unexpected(CookieError::unsupported_platform);
}

CookieHolder::CookieHolder(const PublicKey& responder_static)
    : mac1_key_(mac1_key(responder_static)), cookie_key_(cookie_key(responder_static)) {}

std::expected<void, CookieError> CookieHolder::accept_reply(const CookieReply&, const Mac&,
                                                            Instant) {
  return std::unexpected(CookieError::unsupported_platform);
}

#else

std::expected<CookieReply, CookieError> CookieIssuer::build_reply(const Endpoint& source,
                                                                  std::uint32_t receiver_index,
                                                                  const Mac& received_mac1,
                                                                  Instant now) {
  const auto cookie = compute_cookie(source, now);

  CookieReply reply{};
  reply.receiver_index = receiver_index;
  if (!random_bytes(reply.nonce)) return std::unexpected(CookieError::unsupported_platform);

  unsigned long long written = 0;
  if (crypto_aead_xchacha20poly1305_ietf_encrypt(
          reinterpret_cast<unsigned char*>(reply.encrypted_cookie.data()), &written,
          reinterpret_cast<const unsigned char*>(cookie.data()), cookie.size(),
          reinterpret_cast<const unsigned char*>(received_mac1.data()), received_mac1.size(),
          nullptr, reinterpret_cast<const unsigned char*>(reply.nonce.data()),
          reinterpret_cast<const unsigned char*>(cookie_key_.data())) != 0) {
    return std::unexpected(CookieError::decryption_failed);
  }
  return reply;
}

CookieHolder::CookieHolder(const PublicKey& responder_static)
    : mac1_key_(mac1_key(responder_static)), cookie_key_(cookie_key(responder_static)) {}

std::expected<void, CookieError> CookieHolder::accept_reply(const CookieReply& reply,
                                                            const Mac& sent_mac1, Instant now) {
  Cookie cookie{};
  unsigned long long written = 0;
  if (crypto_aead_xchacha20poly1305_ietf_decrypt(
          reinterpret_cast<unsigned char*>(cookie.data()), &written, nullptr,
          reinterpret_cast<const unsigned char*>(reply.encrypted_cookie.data()),
          reply.encrypted_cookie.size(),
          reinterpret_cast<const unsigned char*>(sent_mac1.data()), sent_mac1.size(),
          reinterpret_cast<const unsigned char*>(reply.nonce.data()),
          reinterpret_cast<const unsigned char*>(cookie_key_.data())) != 0) {
    return std::unexpected(CookieError::decryption_failed);
  }

  cookie_ = cookie;
  received_ = now;
  has_cookie_ = true;
  return {};
}

#endif

Mac CookieHolder::compute_mac1(std::span<const std::byte> message) const noexcept {
  return keyed_mac(mac1_key_, message);
}

Mac CookieHolder::compute_mac2(std::span<const std::byte> message) const noexcept {
  if (!has_cookie_) return Mac{};
  return keyed_mac(cookie_, message);
}

}
