// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#include "norr/session.hpp"

#include <algorithm>

namespace norr {
Session::Session(PeerId peer, std::uint16_t local_key_id, std::uint16_t remote_key_id,
                 TrafficKeys send_keys, TrafficKeys receive_keys) noexcept
    : peer_(peer),
      local_key_id_(local_key_id),
      remote_key_id_(remote_key_id),
      send_keys_(std::move(send_keys)),
      receive_keys_(std::move(receive_keys)) {}

std::expected<std::size_t, SessionError> Session::seal(FrameType type,
                                                       std::span<const std::byte> plaintext,
                                                       std::span<std::byte> out) {
  const std::lock_guard lock{*guard_};

  const auto required = kPacketHeaderSize + plaintext.size() + kAeadTagSize;
  if (out.size() < required) return std::unexpected(SessionError::buffer_too_small);

  if (stats_.sent >= kRejectAfterMessages) {
    return std::unexpected(SessionError::counter_exhausted);
  }

  const auto counter = send_counter_.next();
  if (!counter) return std::unexpected(SessionError::counter_exhausted);

  const auto ciphertext_length = plaintext.size() + kAeadTagSize;
  if (ciphertext_length > kMaximumPacketSize - kPacketHeaderSize) {
    return std::unexpected(SessionError::buffer_too_small);
  }

  const PacketHeader header{
      .version = kProtocolVersion,
      .type = type,
      .flags = 0,
      .key_id = remote_key_id_,
      .header_length = kPacketHeaderSize,
      .counter = *counter,
      .payload_length = static_cast<std::uint16_t>(ciphertext_length),
  };

  const auto encoded = serialize_header(header, ciphertext_length, out);
  if (!encoded) return std::unexpected(SessionError::buffer_too_small);

  const auto associated = out.first(kPacketHeaderSize);
  const auto sealed = send_keys_.seal(*counter, associated, plaintext, out.subspan(kPacketHeaderSize));
  if (!sealed) {
    return std::unexpected(sealed.error() == CryptoError::buffer_too_small
                               ? SessionError::buffer_too_small
                               : SessionError::authentication_failed);
  }

  ++stats_.sent;
  return kPacketHeaderSize + *sealed;
}

std::expected<std::size_t, SessionError> Session::open(const PacketView& view,
                                                       std::span<const std::byte> packet,
                                                       std::span<std::byte> out) {
  const std::lock_guard lock{*guard_};

  if (packet.size() < kPacketHeaderSize) return std::unexpected(SessionError::buffer_too_small);

  if (view.header.counter < replay_.highest_accepted() &&
      replay_.highest_accepted() - view.header.counter >= ReplayWindow::kWindowSize) {
    ++stats_.too_old_drops;
    return std::unexpected(SessionError::too_old);
  }

  const auto associated = packet.first(kPacketHeaderSize);
  const auto opened =
      receive_keys_.open(view.header.counter, associated, view.payload, out);
  if (!opened) {
    ++stats_.auth_failures;
    return std::unexpected(opened.error() == CryptoError::buffer_too_small
                               ? SessionError::buffer_too_small
                               : SessionError::authentication_failed);
  }

  switch (replay_.accept(view.header.counter)) {
    case ReplayResult::accepted: break;
    case ReplayResult::replayed:
      ++stats_.replay_drops;
      return std::unexpected(SessionError::replayed);
    case ReplayResult::too_old:
      ++stats_.too_old_drops;
      return std::unexpected(SessionError::too_old);
  }

  ++stats_.received;
  last_received_ = std::chrono::steady_clock::now();
  return *opened;
}

std::expected<std::uint16_t, SessionError> SessionTable::allocate_key_id() {
  if (sessions_.size() >= kMaximumSessions) {
    return std::unexpected(SessionError::too_many_sessions);
  }

  for (std::uint32_t attempt = 0; attempt < 0x1'0000U; ++attempt) {
    const auto candidate = next_key_id_;
    next_key_id_ = static_cast<std::uint16_t>(next_key_id_ == 0xFFFFU ? 1U : next_key_id_ + 1U);
    if (candidate == kPreSessionKeyId) continue;
    if (!sessions_.contains(candidate)) return candidate;
  }
  return std::unexpected(SessionError::key_id_exhausted);
}

std::expected<std::shared_ptr<Session>, SessionError> SessionTable::install(
    PeerId peer, std::uint16_t local_key_id, std::uint16_t remote_key_id,
    TrafficKeys send_keys, TrafficKeys receive_keys) {
  return install(peer, local_key_id,
                 Session{peer, local_key_id, remote_key_id, std::move(send_keys),
                         std::move(receive_keys)});
}

std::expected<std::shared_ptr<Session>, SessionError> SessionTable::install(
    PeerId peer, std::uint16_t local_key_id, Session session) {
  if (peer == kNoPeer) return std::unexpected(SessionError::unknown_peer);
  if (local_key_id == kPreSessionKeyId) return std::unexpected(SessionError::unknown_key_id);
  if (sessions_.size() >= kMaximumSessions) {
    return std::unexpected(SessionError::too_many_sessions);
  }

  if (const auto existing = by_peer_.find(peer); existing != by_peer_.end()) {
    if (existing->second != local_key_id) {
      retired_.push_back(Retired{.key_id = existing->second,
                                 .retired_at = std::chrono::steady_clock::now()});
    } else {
      sessions_.erase(existing->second);
    }
    by_peer_.erase(existing);
  }
  sessions_.erase(local_key_id);

  std::erase_if(retired_, [&](const Retired& entry) { return entry.key_id == local_key_id; });

  const auto [entry, inserted] =
      sessions_.try_emplace(local_key_id, std::make_shared<Session>(std::move(session)));
  if (!inserted) return std::unexpected(SessionError::unknown_key_id);

  by_peer_[peer] = local_key_id;
  return entry->second;
}

std::shared_ptr<Session> SessionTable::find_by_key_id(std::uint16_t key_id) noexcept {
  const auto entry = sessions_.find(key_id);
  if (entry == sessions_.end()) return nullptr;

  const auto is_retired =
      std::ranges::any_of(retired_, [&](const Retired& r) { return r.key_id == key_id; });
  if (is_retired) ++retired_receives_;

  return entry->second;
}

void SessionTable::expire_retired(Instant now) noexcept {
  std::erase_if(retired_, [&](const Retired& entry) {
    if (now - entry.retired_at < kRetireAfter) return false;
    sessions_.erase(entry.key_id);
    return true;
  });
}

std::shared_ptr<Session> SessionTable::find_by_peer(PeerId peer) noexcept {
  const auto mapping = by_peer_.find(peer);
  if (mapping == by_peer_.end()) return nullptr;
  return find_by_key_id(mapping->second);
}

void SessionTable::remove(std::uint16_t local_key_id) noexcept {
  const auto entry = sessions_.find(local_key_id);
  if (entry == sessions_.end()) return;

  std::erase_if(retired_, [&](const Retired& r) { return r.key_id == local_key_id; });

  const auto peer = entry->second->peer();
  if (const auto mapping = by_peer_.find(peer);
      mapping != by_peer_.end() && mapping->second == local_key_id) {
    by_peer_.erase(mapping);
  }
  sessions_.erase(entry);
}

}
