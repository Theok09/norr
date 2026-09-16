// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#include "norr/path_selector.hpp"

#include <algorithm>

namespace norr {
namespace {
constexpr double kSmoothing = 0.3;

[[nodiscard]] double smooth(double previous, double sample) noexcept {
  return previous + kSmoothing * (sample - previous);
}

}

void Path::observe(const PathSample& sample, const PathThresholds& thresholds) {
  if (!primed_) {
    primed_ = true;
    smoothed_loss_ = sample.loss_fraction;
    smoothed_rtt_ = sample.rtt_microseconds;
  } else {
    smoothed_loss_ = smooth(smoothed_loss_, sample.loss_fraction);
    smoothed_rtt_ = smooth(smoothed_rtt_, sample.rtt_microseconds);
  }

  const auto rtt_term = std::min(smoothed_rtt_ / 1'000'000.0, 1.0);
  score_ = smoothed_loss_ * 10.0 + rtt_term;

  if (!sample.reachable) {
    bad_ = thresholds.demotion_threshold;
    good_ = 0;
    state_ = PathState::failed;
    return;
  }

  const auto bad_sample = sample.loss_fraction > thresholds.loss_degraded ||
                          sample.rtt_microseconds > thresholds.rtt_degraded_microseconds;
  const auto good_sample = sample.loss_fraction <= thresholds.loss_healthy &&
                           sample.rtt_microseconds <= thresholds.rtt_healthy_microseconds;

  if (bad_sample) {
    ++bad_;
    good_ = 0;
  } else if (good_sample) {
    ++good_;
    bad_ = 0;
  } else {
    return;
  }

  switch (state_) {
    case PathState::probing:

      if (good_ >= thresholds.promotion_window) state_ = PathState::healthy;
      else if (bad_ >= thresholds.demotion_threshold) state_ = PathState::failed;
      break;

    case PathState::healthy:
      if (bad_ >= thresholds.demotion_threshold) state_ = PathState::degraded;
      break;

    case PathState::degraded:
      if (good_ >= thresholds.promotion_window) state_ = PathState::healthy;

      else if (bad_ >= thresholds.demotion_threshold * 2) state_ = PathState::failed;
      break;

    case PathState::failed:

      if (good_ >= 1) state_ = PathState::recovering;
      break;

    case PathState::recovering:
      if (good_ >= thresholds.promotion_window) state_ = PathState::healthy;
      else if (bad_ >= thresholds.demotion_threshold) state_ = PathState::failed;
      break;
  }
}

void PathSelector::add_path(TransportKind kind) {
  if (find(kind) != nullptr) return;
  if (count_ >= paths_.size()) return;

  paths_[count_] = Path{kind};
  ++count_;
  if (!has_active_) {
    active_ = kind;
    has_active_ = true;
  }
}

void PathSelector::set_active(TransportKind kind) {
  if (find(kind) == nullptr) return;
  active_ = kind;
  has_active_ = true;
}

Path* PathSelector::find(TransportKind kind) noexcept {
  for (std::size_t index = 0; index < count_; ++index) {
    if (paths_[index].kind() == kind) return &paths_[index];
  }
  return nullptr;
}

const Path* PathSelector::path(TransportKind kind) const noexcept {
  for (std::size_t index = 0; index < count_; ++index) {
    if (paths_[index].kind() == kind) return &paths_[index];
  }
  return nullptr;
}

void PathSelector::observe(TransportKind kind, const PathSample& sample) {
  auto* path = find(kind);
  if (path == nullptr) return;
  path->observe(sample, thresholds_);
}

bool PathSelector::evaluate(Instant now) {
  if (count_ == 0 || !has_active_) return false;

  const auto* current = path(active_);
  if (current == nullptr) return false;

  const auto must_move = !current->usable();

  // A path that has never carried anything is unknown, not bad. While the
  // active path still works there is no reason to gamble on one, but once it
  // has failed an untried carrier is the only candidate there will ever be:
  // nothing samples a carrier that is not selected, so waiting for it to
  // become "usable" first is waiting forever. This is what makes falling back
  // to TCP or QUIC possible when UDP is blocked outright.
  const Path* best = nullptr;
  for (std::size_t index = 0; index < count_; ++index) {
    const auto& candidate = paths_[index];
    if (candidate.kind() == active_) continue;
    const auto eligible =
        candidate.usable() || (must_move && candidate.state() == PathState::probing);
    if (!eligible) continue;
    if (best == nullptr || candidate.score() < best->score()) best = &candidate;
  }
  if (best == nullptr) return false;

  if (last_switch_ != Instant{} && now - last_switch_ < thresholds_.cooldown) {
    ++stats_.switches_suppressed_by_cooldown;
    return false;
  }

  if (!must_move) {
    if (current->state() == PathState::healthy) {
      ++stats_.switches_suppressed_by_margin;
      return false;
    }

    const auto improvement =
        current->score() > 0.0 ? (current->score() - best->score()) / current->score() : 0.0;
    if (improvement < thresholds_.minimum_improvement) {
      ++stats_.switches_suppressed_by_margin;
      return false;
    }
  }

  // The path being left is recorded as failed when that is why it was left.
  // Only the active path is ever sampled, so an abandoned one would otherwise
  // keep the state it had when it broke and be selected again immediately,
  // which is how a fallback turns into a rotation.
  if (must_move) {
    if (auto* leaving = find(active_); leaving != nullptr) leaving->mark_failed();
  }

  active_ = best->kind();
  last_switch_ = now;
  ++stats_.switches;
  if (must_move) ++stats_.failovers;
  return true;
}

}
