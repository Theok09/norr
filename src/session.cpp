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

std::expected<std::uint64_t, SessionError> Session::reserve_counter() {
  const std::lock_guard lock{*guard_};
  if (stats_.sent >= kRejectAfterMessages) {
    return std::unexpected(SessionError::counter_exhausted);
  }
  const auto counter = send_counter_.next();
  if (!counter) return std::unexpected(SessionError::counter_exhausted);
  ++stats_.sent;
  return *counter;
}

std::expected<std::size_t, SessionError> Session::seal_reserved(FrameType type,
                                                                std::uint64_t counter,
                                                                std::span<const std::byte> plaintext,
                                                                std::span<std::byte> out) const {
  const auto ciphertext_length = plaintext.size() + kAeadTagSize;
  if (out.size() < kPacketHeaderSize + ciphertext_length) {
    return std::unexpected(SessionError::buffer_too_small);
  }
  if (ciphertext_length > kMaximumPacketSize - kPacketHeaderSize) {
    return std::unexpected(SessionError::buffer_too_small);
  }

  const PacketHeader header{
      .version = kProtocolVersion,
      .type = type,
      .flags = 0,
      .key_id = remote_key_id_,
      .header_length = kPacketHeaderSize,
      .counter = counter,
      .payload_length = static_cast<std::uint16_t>(ciphertext_length),
  };
  if (!serialize_header(header, ciphertext_length, out)) {
    return std::unexpected(SessionError::buffer_too_small);
  }

  const auto associated = out.first(kPacketHeaderSize);
  const auto sealed = send_keys_.seal(counter, associated, plaintext, out.subspan(kPacketHeaderSize));
  if (!sealed) {
    return std::unexpected(sealed.error() == CryptoError::buffer_too_small
                               ? SessionError::buffer_too_small
                               : SessionError::authentication_failed);
  }
  return kPacketHeaderSize + *sealed;
}

std::expected<std::size_t, SessionError> Session::seal(FrameType type,
                                                       std::span<const std::byte> plaintext,
                                                       std::span<std::byte> out) {
  if (out.size() < kPacketHeaderSize + plaintext.size() + kAeadTagSize) {
    return std::unexpected(SessionError::buffer_too_small);
  }
  const auto counter = reserve_counter();
  if (!counter) return std::unexpected(counter.error());
  return seal_reserved(type, *counter, plaintext, out);
}

std::expected<void, SessionError> Session::check_window(std::uint64_t counter) {
  const std::lock_guard lock{*guard_};
  if (counter < replay_.highest_accepted() &&
      replay_.highest_accepted() - counter >= ReplayWindow::kWindowSize) {
    ++stats_.too_old_drops;
    return std::unexpected(SessionError::too_old);
  }
  return {};
}

std::expected<std::size_t, SessionError> Session::decrypt(const PacketView& view,
                                                          std::span<const std::byte> packet,
                                                          std::span<std::byte> out) const {
  if (packet.size() < kPacketHeaderSize) return std::unexpected(SessionError::buffer_too_small);
  const auto associated = packet.first(kPacketHeaderSize);
  const auto opened = receive_keys_.open(view.header.counter, associated, view.payload, out);
  if (!opened) {
    return std::unexpected(opened.error() == CryptoError::buffer_too_small
                               ? SessionError::buffer_too_small
                               : SessionError::authentication_failed);
  }
  return *opened;
}

void Session::note_authentication_failure() noexcept {
  const std::lock_guard lock{*guard_};
  ++stats_.auth_failures;
}

std::expected<void, SessionError> Session::commit(std::uint64_t counter) {
  const std::lock_guard lock{*guard_};
  switch (replay_.accept(counter)) {
    case ReplayResult::accepted: break;
    case ReplayResult::replayed:
      ++stats_.replay_drops;
      ++sample_late_;
      return std::unexpected(SessionError::replayed);
    case ReplayResult::too_old:
      ++stats_.too_old_drops;
      return std::unexpected(SessionError::too_old);
  }
  ++stats_.received;
  ++sample_received_;
  last_received_ = std::chrono::steady_clock::now();
  return {};
}

std::expected<std::size_t, SessionError> Session::open(const PacketView& view,
                                                       std::span<const std::byte> packet,
                                                       std::span<std::byte> out) {
  if (const auto window = check_window(view.header.counter); !window) {
    return std::unexpected(window.error());
  }
  const auto opened = decrypt(view, packet, out);
  if (!opened) {
    if (opened.error() == SessionError::authentication_failed) note_authentication_failure();
    return std::unexpected(opened.error());
  }
  if (const auto committed = commit(view.header.counter); !committed) {
    return std::unexpected(committed.error());
  }
  return *opened;
}

void Session::note_recovered() noexcept {
  const std::lock_guard lock{*guard_};
  ++sample_recovered_;
}

std::optional<Session::LossSample> Session::take_loss_sample() noexcept {
  const std::lock_guard lock{*guard_};
  const auto highest = replay_.highest_accepted();
  if (!sample_primed_) {
    if (stats_.received == 0) return std::nullopt;
    sample_primed_ = true;
    sample_base_ = highest;
    sample_received_ = 0;
    sample_recovered_ = 0;
    sample_late_ = 0;
    return std::nullopt;
  }
  const auto expected = highest > sample_base_ ? highest - sample_base_ : 0;
  if (expected < 64) return std::nullopt;
  const auto late = std::min(sample_late_, sample_recovered_);
  const auto direct = sample_received_ - sample_recovered_ + late;
  const auto fraction_missing = [&](std::uint64_t arrived) {
    return arrived >= expected ? 0.0
                               : 1.0 - static_cast<double>(arrived) / static_cast<double>(expected);
  };
  const LossSample sample{.raw = fraction_missing(direct),
                          .residual = fraction_missing(sample_received_),
                          .expected = expected};
  sample_base_ = highest;
  sample_received_ = 0;
  sample_recovered_ = 0;
  sample_late_ = 0;
  return sample;
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
