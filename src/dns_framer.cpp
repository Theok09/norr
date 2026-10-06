// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#include "norr/dns_framer.hpp"

#include <algorithm>

namespace norr {
namespace {
constexpr std::string_view kDefaultDomain = "t.example.com";

void encode_domain(std::string_view domain, std::vector<std::byte>& out) {
  out.clear();
  std::size_t start = 0;
  while (start <= domain.size()) {
    auto dot = domain.find('.', start);
    if (dot == std::string_view::npos) dot = domain.size();
    auto length = dot - start;
    if (length > kDnsLabelMaxSize) length = kDnsLabelMaxSize;
    if (length > 0) {
      out.push_back(static_cast<std::byte>(length));
      for (std::size_t i = 0; i < length; ++i) {
        out.push_back(static_cast<std::byte>(domain[start + i]));
      }
    }
    if (dot == domain.size()) break;
    start = dot + 1;
  }
  out.push_back(std::byte{0});
}

void put_u16(std::span<std::byte> out, std::size_t pos, std::uint16_t value) noexcept {
  out[pos] = static_cast<std::byte>(value >> 8U);
  out[pos + 1] = static_cast<std::byte>(value & 0xFFU);
}

[[nodiscard]] std::uint16_t get_u16(std::span<const std::byte> in, std::size_t pos) noexcept {
  return static_cast<std::uint16_t>(
      (static_cast<unsigned>(static_cast<std::uint8_t>(in[pos])) << 8U) |
      static_cast<unsigned>(static_cast<std::uint8_t>(in[pos + 1])));
}
}

void DnsFramer::configure(DnsRole role, std::string domain) {
  role_ = role;
  encode_domain(domain.empty() ? kDefaultDomain : std::string_view{domain}, qname_);
}

std::expected<std::size_t, DnsFramerError> DnsFramer::wrap(
    std::span<const std::byte> payload, std::span<std::byte> out) noexcept {
  if (payload.size() > 0xFFFFU) return std::unexpected(DnsFramerError::payload_too_large);
  const auto total = envelope_size() + payload.size();
  if (out.size() < total) return std::unexpected(DnsFramerError::buffer_too_small);

  const auto flags = role_ == DnsRole::server ? kDnsFlagsResponse : kDnsFlagsQuery;
  const auto answers = role_ == DnsRole::server ? std::uint16_t{1} : std::uint16_t{0};
  put_u16(out, 0, ++id_);
  put_u16(out, 2, flags);
  put_u16(out, 4, 1);
  put_u16(out, 6, answers);
  put_u16(out, 8, 0);
  put_u16(out, 10, 0);

  std::size_t pos = kDnsHeaderSize;
  std::copy(qname_.begin(), qname_.end(), out.begin() + static_cast<std::ptrdiff_t>(pos));
  pos += qname_.size();
  put_u16(out, pos, kDnsTypeTxt);
  put_u16(out, pos + 2, kDnsClassIn);
  pos += kDnsQuestionTrailerSize;
  put_u16(out, pos, static_cast<std::uint16_t>(payload.size()));
  pos += kDnsPayloadLengthSize;
  std::copy(payload.begin(), payload.end(), out.begin() + static_cast<std::ptrdiff_t>(pos));
  return total;
}

std::expected<std::size_t, DnsFramerError> DnsFramer::unwrap(
    std::span<const std::byte> wire, std::span<std::byte> out) const noexcept {
  if (wire.size() < kDnsHeaderSize) return std::unexpected(DnsFramerError::malformed);
  std::size_t pos = kDnsHeaderSize;
  bool terminated = false;
  while (pos < wire.size()) {
    const auto label = static_cast<std::size_t>(static_cast<std::uint8_t>(wire[pos]));
    ++pos;
    if (label == 0) {
      terminated = true;
      break;
    }
    if (label > kDnsLabelMaxSize || pos + label > wire.size()) {
      return std::unexpected(DnsFramerError::malformed);
    }
    pos += label;
  }
  if (!terminated) return std::unexpected(DnsFramerError::malformed);
  if (pos + kDnsQuestionTrailerSize + kDnsPayloadLengthSize > wire.size()) {
    return std::unexpected(DnsFramerError::malformed);
  }
  pos += kDnsQuestionTrailerSize;
  const auto length = static_cast<std::size_t>(get_u16(wire, pos));
  pos += kDnsPayloadLengthSize;
  if (pos + length > wire.size()) return std::unexpected(DnsFramerError::malformed);
  if (out.size() < length) return std::unexpected(DnsFramerError::buffer_too_small);
  std::copy(wire.begin() + static_cast<std::ptrdiff_t>(pos),
            wire.begin() + static_cast<std::ptrdiff_t>(pos + length), out.begin());
  return length;
}
}
