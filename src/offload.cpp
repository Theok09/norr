// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#include "norr/offload.hpp"

#include <algorithm>
#include <cstring>

namespace norr {
namespace {
constexpr std::uint8_t kProtocolTcp = 6;
constexpr std::uint8_t kProtocolUdp = 17;
constexpr std::uint8_t kTcpFin = 0x01;
constexpr std::uint8_t kTcpPsh = 0x08;
constexpr std::uint8_t kTcpAck = 0x10;
constexpr std::uint8_t kTcpCwr = 0x80;
constexpr unsigned kKeepUnlessLast = 0xFFU & ~static_cast<unsigned>(kTcpFin | kTcpPsh);
constexpr unsigned kKeepUnlessFirst = 0xFFU & ~static_cast<unsigned>(kTcpCwr);
constexpr unsigned kNotAckOrPush = 0xFFU & ~static_cast<unsigned>(kTcpAck | kTcpPsh);

[[nodiscard]] std::uint16_t load16(std::span<const std::byte> bytes, std::size_t offset) noexcept {
  return static_cast<std::uint16_t>((static_cast<unsigned>(bytes[offset]) << 8U) |
                                    static_cast<unsigned>(bytes[offset + 1]));
}

void store16(std::span<std::byte> bytes, std::size_t offset, std::uint16_t value) noexcept {
  bytes[offset] = static_cast<std::byte>(value >> 8U);
  bytes[offset + 1] = static_cast<std::byte>(value & 0xFFU);
}

[[nodiscard]] std::uint32_t load32(std::span<const std::byte> bytes, std::size_t offset) noexcept {
  return (static_cast<std::uint32_t>(bytes[offset]) << 24U) |
         (static_cast<std::uint32_t>(bytes[offset + 1]) << 16U) |
         (static_cast<std::uint32_t>(bytes[offset + 2]) << 8U) |
         static_cast<std::uint32_t>(bytes[offset + 3]);
}

void store32(std::span<std::byte> bytes, std::size_t offset, std::uint32_t value) noexcept {
  bytes[offset] = static_cast<std::byte>(value >> 24U);
  bytes[offset + 1] = static_cast<std::byte>((value >> 16U) & 0xFFU);
  bytes[offset + 2] = static_cast<std::byte>((value >> 8U) & 0xFFU);
  bytes[offset + 3] = static_cast<std::byte>(value & 0xFFU);
}

[[nodiscard]] bool is_ipv4(std::span<const std::byte> packet) noexcept {
  return !packet.empty() && (static_cast<std::uint8_t>(packet[0]) >> 4U) == 4;
}

[[nodiscard]] std::size_t ip_header_length(std::span<const std::byte> packet) noexcept {
  if (is_ipv4(packet)) return static_cast<std::size_t>(static_cast<std::uint8_t>(packet[0]) & 0x0FU) * 4U;
  return 40;
}

[[nodiscard]] std::uint8_t ip_protocol(std::span<const std::byte> packet) noexcept {
  return static_cast<std::uint8_t>(is_ipv4(packet) ? packet[9] : packet[6]);
}

void set_ip_length(std::span<std::byte> packet, std::size_t total) noexcept {
  if (is_ipv4(packet)) {
    store16(packet, 2, static_cast<std::uint16_t>(total));
    store16(packet, 10, 0);
    const auto header = ip_header_length(packet);
    store16(packet, 10, static_cast<std::uint16_t>(~fold_checksum(checksum_add(packet.first(header)))));
  } else {
    store16(packet, 4, static_cast<std::uint16_t>(total - 40));
  }
}

void finish_transport_checksum(std::span<std::byte> packet, std::size_t ip_length,
                               std::uint8_t protocol) {
  const auto transport = packet.subspan(ip_length);
  const auto field = protocol == kProtocolTcp ? 16U : 6U;
  store16(transport, field, 0);
  const auto sum = pseudo_header_sum(packet, protocol, transport.size()) + checksum_add(transport);
  auto value = static_cast<std::uint16_t>(~fold_checksum(sum));
  if (protocol == kProtocolUdp && value == 0) value = 0xFFFF;
  store16(transport, field, value);
}
}

VirtioHeader parse_virtio_header(std::span<const std::byte> bytes) noexcept {
  VirtioHeader header{};
  if (bytes.size() < kVirtioHeaderSize) return header;
  const auto little = [&](std::size_t offset) {
    std::uint16_t value{};
    std::memcpy(&value, bytes.data() + offset, sizeof(value));
    return value;
  };
  header.flags = static_cast<std::uint8_t>(bytes[0]);
  header.gso_type = static_cast<std::uint8_t>(bytes[1]);
  header.header_length = little(2);
  header.gso_size = little(4);
  header.checksum_start = little(6);
  header.checksum_offset = little(8);
  return header;
}

void write_virtio_header(const VirtioHeader& header, std::span<std::byte> out) noexcept {
  if (out.size() < kVirtioHeaderSize) return;
  out[0] = static_cast<std::byte>(header.flags);
  out[1] = static_cast<std::byte>(header.gso_type);
  std::memcpy(out.data() + 2, &header.header_length, 2);
  std::memcpy(out.data() + 4, &header.gso_size, 2);
  std::memcpy(out.data() + 6, &header.checksum_start, 2);
  std::memcpy(out.data() + 8, &header.checksum_offset, 2);
}

std::uint16_t fold_checksum(std::uint64_t sum) noexcept {
  while ((sum >> 16U) != 0) sum = (sum & 0xFFFFU) + (sum >> 16U);
  return static_cast<std::uint16_t>(sum);
}

std::uint64_t checksum_add(std::span<const std::byte> bytes, std::uint64_t initial) noexcept {
  std::uint64_t sum = initial;
  std::size_t index = 0;
  for (; index + 8 <= bytes.size(); index += 8) {
    sum += load16(bytes, index);
    sum += load16(bytes, index + 2);
    sum += load16(bytes, index + 4);
    sum += load16(bytes, index + 6);
  }
  for (; index + 1 < bytes.size(); index += 2) sum += load16(bytes, index);
  if (index < bytes.size()) sum += static_cast<std::uint64_t>(bytes[index]) << 8U;
  return sum;
}

std::uint64_t pseudo_header_sum(std::span<const std::byte> packet, std::uint8_t protocol,
                                std::size_t transport_length) noexcept {
  std::uint64_t sum = protocol;
  if (is_ipv4(packet)) {
    sum = checksum_add(packet.subspan(12, 8), sum);
    sum += transport_length;
  } else {
    sum = checksum_add(packet.subspan(8, 32), sum);
    sum += transport_length >> 16U;
    sum += transport_length & 0xFFFFU;
  }
  return sum;
}

bool transport_checksum_valid(std::span<const std::byte> packet) noexcept {
  const auto ip_length = ip_header_length(packet);
  if (packet.size() < ip_length) return false;
  const auto transport = packet.subspan(ip_length);
  const auto sum = pseudo_header_sum(packet, ip_protocol(packet), transport.size()) +
                   checksum_add(transport);
  return fold_checksum(sum) == 0xFFFF;
}

bool expand_offloaded(const VirtioHeader& header, std::span<std::byte> packet,
                      std::vector<std::byte>& scratch, const SegmentSink& sink) {
  if (packet.size() < 20) return false;
  const bool ipv4 = is_ipv4(packet);
  const auto ip_length = ip_header_length(packet);
  if (ip_length < 20 || packet.size() < ip_length) return false;
  const auto protocol = ip_protocol(packet);

  if (header.gso_type == kGsoNone) {
    if ((header.flags & kVirtioNeedsChecksum) != 0) {
      const std::size_t start = header.checksum_start;
      const std::size_t field = start + header.checksum_offset;
      if (field + 2 > packet.size() || start >= packet.size()) return false;
      auto value = static_cast<std::uint16_t>(~fold_checksum(checksum_add(packet.subspan(start))));
      if (protocol == kProtocolUdp && value == 0) value = 0xFFFF;
      store16(packet, field, value);
    }
    sink(packet);
    return true;
  }

  const bool tcp = header.gso_type == kGsoTcpV4 || header.gso_type == kGsoTcpV6;
  const bool udp = header.gso_type == kGsoUdpL4;
  if ((!tcp && !udp) || header.gso_size == 0) return false;
  if (tcp && protocol != kProtocolTcp) return false;
  if (udp && protocol != kProtocolUdp) return false;
  if (packet.size() < ip_length + (tcp ? 20U : 8U)) return false;

  const std::size_t transport_length =
      tcp ? static_cast<std::size_t>(static_cast<std::uint8_t>(packet[ip_length + 12]) >> 4U) * 4U
          : 8U;
  const auto headers = ip_length + transport_length;
  const std::size_t min_transport = tcp ? 20U : 8U;
  if (transport_length < min_transport || (tcp && transport_length > 60) ||
      headers > packet.size()) {
    return false;
  }

  const auto payload = packet.subspan(headers);
  const std::size_t segment = header.gso_size;
  const auto sequence = tcp ? load32(packet, ip_length + 4) : 0U;
  const auto flags = tcp ? static_cast<std::uint8_t>(packet[ip_length + 13]) : 0U;
  const auto identifier = ipv4 ? load16(packet, 4) : 0U;

  std::size_t index = 0;
  for (std::size_t offset = 0; offset < payload.size(); offset += segment, ++index) {
    const auto chunk = std::min(segment, payload.size() - offset);
    const bool last = offset + chunk >= payload.size();
    scratch.resize(headers + chunk);
    std::copy_n(packet.begin(), headers, scratch.begin());
    std::copy_n(payload.begin() + static_cast<std::ptrdiff_t>(offset), chunk,
                scratch.begin() + static_cast<std::ptrdiff_t>(headers));
    auto out = std::span<std::byte>{scratch};

    if (ipv4) store16(out, 4, static_cast<std::uint16_t>(identifier + index));
    set_ip_length(out, out.size());

    if (tcp) {
      store32(out, ip_length + 4, static_cast<std::uint32_t>(sequence + offset));
      auto segment_flags = flags;
      if (!last) segment_flags = static_cast<std::uint8_t>(segment_flags & kKeepUnlessLast);
      if (index > 0) segment_flags = static_cast<std::uint8_t>(segment_flags & kKeepUnlessFirst);
      out[ip_length + 13] = static_cast<std::byte>(segment_flags);
    } else {
      store16(out, ip_length + 4, static_cast<std::uint16_t>(8 + chunk));
    }
    finish_transport_checksum(out, ip_length, protocol);
    sink(out);
  }
  return true;
}

TcpCoalescer::Item& TcpCoalescer::next_item() {
  if (used_ == items_.size()) items_.emplace_back();
  auto& item = items_[used_++];
  item.head.clear();
  item.payloads.clear();
  item.tcp = false;
  item.ipv4 = false;
  item.ip_length = 0;
  item.tcp_length = 0;
  item.segment = 0;
  item.total = 0;
  item.next_sequence = 0;
  item.open = false;
  return item;
}

std::span<const std::byte> TcpCoalescer::retain(std::span<const std::byte> packet, bool stable) {
  if (stable) return packet;
  if (owned_used_ == owned_.size()) owned_.emplace_back();
  auto& storage = owned_[owned_used_++];
  storage.assign(packet.begin(), packet.end());
  return storage;
}

bool TcpCoalescer::try_append(const Item& item, std::span<const std::byte> packet, bool ipv4,
                              std::size_t ip_length, std::size_t tcp_length) const noexcept {
  if (!item.tcp || !item.open || item.ipv4 != ipv4 || item.ip_length != ip_length ||
      item.tcp_length != tcp_length) {
    return false;
  }
  const auto base = std::span<const std::byte>{item.head};
  const auto payload = packet.size() - ip_length - tcp_length;
  if (payload == 0 || payload > item.segment) return false;
  if (item.total + payload > kMaximumOffloadFrame || item.payloads.size() >= 64) return false;

  if (ipv4) {
    if (!std::equal(packet.begin() + 12, packet.begin() + 20, base.begin() + 12)) return false;
    if (packet[1] != base[1] || packet[8] != base[8]) return false;
    if ((load16(packet, 6) & 0xBFFFU) != 0) return false;
    if (load16(packet, 6) != load16(base, 6)) return false;
  } else {
    if (!std::equal(packet.begin() + 8, packet.begin() + 40, base.begin() + 8)) return false;
    if (packet[0] != base[0] || packet[1] != base[1] || packet[7] != base[7]) return false;
  }

  const auto tcp = packet.subspan(ip_length);
  const auto first = base.subspan(ip_length);
  if (load32(tcp, 0) != load32(first, 0)) return false;
  if (load32(tcp, 4) != item.next_sequence) return false;
  if (load32(tcp, 8) != load32(first, 8)) return false;
  if (load16(tcp, 14) != load16(first, 14)) return false;
  const auto flags = static_cast<std::uint8_t>(tcp[13]);
  if ((flags & kNotAckOrPush) != 0) return false;
  return std::equal(tcp.begin() + 20, tcp.begin() + static_cast<std::ptrdiff_t>(tcp_length),
                    first.begin() + 20);
}

void TcpCoalescer::add(std::span<const std::byte> packet, bool stable) {
  const bool candidate = [&] {
    if (packet.size() < 40) return false;
    const auto version = static_cast<std::uint8_t>(packet[0]) >> 4U;
    if (version == 4) {
      if ((static_cast<std::uint8_t>(packet[0]) & 0x0FU) != 5) return false;
      if (static_cast<std::uint8_t>(packet[9]) != kProtocolTcp) return false;
      return (load16(packet, 6) & 0x3FFFU) == 0;
    }
    return version == 6 && packet.size() >= 60 && static_cast<std::uint8_t>(packet[6]) == kProtocolTcp;
  }();

  if (candidate) {
    const bool ipv4 = is_ipv4(packet);
    const auto ip_length = ip_header_length(packet);
    const auto tcp_length =
        static_cast<std::size_t>(static_cast<std::uint8_t>(packet[ip_length + 12]) >> 4U) * 4U;
    const auto headers = ip_length + tcp_length;
    if (tcp_length >= 20 && headers < packet.size()) {
      const auto payload = packet.size() - headers;
      const auto flags = static_cast<std::uint8_t>(packet[ip_length + 13]);

      for (std::size_t index = used_; index-- > 0;) {
        auto& item = items_[index];
        if (!item.tcp || item.ipv4 != ipv4) continue;
        const auto base = std::span<const std::byte>{item.head};
        const bool same_flow =
            (ipv4 ? std::equal(packet.begin() + 12, packet.begin() + 20, base.begin() + 12)
                  : std::equal(packet.begin() + 8, packet.begin() + 40, base.begin() + 8)) &&
            load32(packet, ip_length) == load32(base, item.ip_length);
        if (!same_flow) continue;
        if (try_append(item, packet, ipv4, ip_length, tcp_length)) {
          const auto kept = retain(packet, stable);
          item.payloads.push_back(kept.subspan(headers));
          item.total += payload;
          item.next_sequence = static_cast<std::uint32_t>(item.next_sequence + payload);
          if (payload < item.segment || (flags & kTcpPsh) != 0) item.open = false;
          if ((flags & kTcpPsh) != 0) {
            item.head[item.ip_length + 13] = static_cast<std::byte>(
                static_cast<std::uint8_t>(item.head[item.ip_length + 13]) | kTcpPsh);
          }
          return;
        }
        break;
      }

      const auto kept = retain(packet, stable);
      auto& item = next_item();
      item.head.assign(kept.begin(), kept.begin() + static_cast<std::ptrdiff_t>(headers));
      item.payloads.push_back(kept.subspan(headers));
      item.tcp = true;
      item.ipv4 = ipv4;
      item.ip_length = ip_length;
      item.tcp_length = tcp_length;
      item.segment = payload;
      item.total = packet.size();
      item.next_sequence = static_cast<std::uint32_t>(load32(packet, ip_length + 4) + payload);
      item.open = flags == kTcpAck;
      return;
    }
  }

  auto& item = next_item();
  item.payloads.push_back(retain(packet, stable));
  item.total = packet.size();
}

std::size_t TcpCoalescer::flush(const Writer& writer) {
  std::array<std::byte, kVirtioHeaderSize> header{};
  std::size_t written = 0;
  for (std::size_t index = 0; index < used_; ++index) {
    auto& item = items_[index];
    header.fill(std::byte{0});
    if (!item.tcp || item.payloads.size() < 2) {
      writer(header, item.head, item.payloads);
      ++written;
      continue;
    }

    auto head = std::span<std::byte>{item.head};
    set_ip_length(head, item.total);
    const auto transport_length = item.total - item.ip_length;
    store16(head, item.ip_length + 16,
            fold_checksum(pseudo_header_sum(head, kProtocolTcp, transport_length)));

    const VirtioHeader virtio{.flags = kVirtioNeedsChecksum,
                              .gso_type = item.ipv4 ? kGsoTcpV4 : kGsoTcpV6,
                              .header_length =
                                  static_cast<std::uint16_t>(item.ip_length + item.tcp_length),
                              .gso_size = static_cast<std::uint16_t>(item.segment),
                              .checksum_start = static_cast<std::uint16_t>(item.ip_length),
                              .checksum_offset = 16};
    write_virtio_header(virtio, header);
    writer(header, head, item.payloads);
    coalesced_ += item.payloads.size() - 1;
    ++written;
  }
  used_ = 0;
  owned_used_ = 0;
  return written;
}
}
