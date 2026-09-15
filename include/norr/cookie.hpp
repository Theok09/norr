#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string_view>

#include "norr/crypto.hpp"
#include "norr/endpoint.hpp"
#include "norr/rate_limit.hpp"

namespace norr {
inline constexpr std::string_view kLabelMac1 = "mac1----";
inline constexpr std::string_view kLabelCookie = "cookie--";

inline constexpr std::size_t kMacSize = 16;
inline constexpr std::size_t kCookieSize = 16;
inline constexpr std::size_t kCookieNonceSize = 24;

using Mac = std::array<std::byte, kMacSize>;
using Cookie = std::array<std::byte, kCookieSize>;
using CookieNonce = std::array<std::byte, kCookieNonceSize>;

inline constexpr auto kCookieSecretLifetime = std::chrono::minutes{2};

enum class CookieError {
  unsupported_platform,
  invalid_mac,
  decryption_failed,
  buffer_too_small,
  message_too_short,
};

[[nodiscard]] constexpr std::string_view cookie_error_message(CookieError error) noexcept {
  switch (error) {
    case CookieError::unsupported_platform: return "crypto backend not available";
    case CookieError::invalid_mac: return "MAC verification failed";
    case CookieError::decryption_failed: return "cookie decryption failed";
    case CookieError::buffer_too_small: return "output buffer too small";
    case CookieError::message_too_short: return "message too short to carry MACs";
  }
  return "unknown cookie error";
}

[[nodiscard]] Mac keyed_mac(std::span<const std::byte> key,
                            std::span<const std::byte> message) noexcept;

[[nodiscard]] std::array<std::byte, 32> mac1_key(const PublicKey& responder_static) noexcept;

[[nodiscard]] std::array<std::byte, 32> cookie_key(const PublicKey& responder_static) noexcept;

struct CookieReply {
  std::uint32_t receiver_index{};
  CookieNonce nonce{};

  std::array<std::byte, kCookieSize + kAeadTagSize> encrypted_cookie{};
};

inline constexpr std::size_t kCookieReplySize = 4 + kCookieNonceSize + kCookieSize + kAeadTagSize;

[[nodiscard]] std::expected<std::size_t, CookieError> serialize_cookie_reply(
    const CookieReply& reply, std::span<std::byte> out) noexcept;

[[nodiscard]] std::expected<CookieReply, CookieError> parse_cookie_reply(
    std::span<const std::byte> bytes) noexcept;

class CookieIssuer {
 public:
  explicit CookieIssuer(const PublicKey& local_static);

  void refresh(Instant now);

  [[nodiscard]] bool under_load() const noexcept { return under_load_; }
  void set_under_load(bool value) noexcept { under_load_ = value; }

  [[nodiscard]] Cookie compute_cookie(const Endpoint& source, Instant now);

  [[nodiscard]] std::expected<CookieReply, CookieError> build_reply(
      const Endpoint& source, std::uint32_t receiver_index, const Mac& received_mac1,
      Instant now);

  [[nodiscard]] bool verify_mac2(const Endpoint& source, std::span<const std::byte> message,
                                 const Mac& mac2, Instant now);

  [[nodiscard]] Mac compute_mac1(std::span<const std::byte> message) const noexcept;

  [[nodiscard]] bool verify_mac1(std::span<const std::byte> message,
                                 const Mac& mac1) const noexcept;

 private:

  std::array<std::byte, 32> mac1_key_{};
  std::array<std::byte, 32> cookie_key_{};
  std::array<std::byte, 32> secret_{};
  std::array<std::byte, 32> previous_secret_{};
  Instant secret_created_{};
  bool has_previous_{};
  bool under_load_{};
};

class CookieHolder {
 public:
  explicit CookieHolder(const PublicKey& responder_static);

  [[nodiscard]] std::expected<void, CookieError> accept_reply(const CookieReply& reply,
                                                              const Mac& sent_mac1, Instant now);

  [[nodiscard]] bool has_cookie() const noexcept { return has_cookie_; }

  [[nodiscard]] Mac compute_mac1(std::span<const std::byte> message) const noexcept;

  [[nodiscard]] Mac compute_mac2(std::span<const std::byte> message) const noexcept;

 private:
  std::array<std::byte, 32> mac1_key_{};
  std::array<std::byte, 32> cookie_key_{};
  Cookie cookie_{};
  Instant received_{};
  bool has_cookie_{};
};

}
