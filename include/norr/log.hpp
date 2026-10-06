// Norr — encrypted layer 3 tunnel. Copyright (C) 2026 Theok09.
// Licensed under the GNU AGPL v3 or later. See LICENSE.
#pragma once

#include <array>
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string_view>

namespace norr {
enum class LogLevel : std::uint8_t { debug, info, warn, error, off };

[[nodiscard]] constexpr std::string_view log_level_name(LogLevel level) noexcept {
  switch (level) {
    case LogLevel::debug: return "DBG";
    case LogLevel::info: return "INF";
    case LogLevel::warn: return "WRN";
    case LogLevel::error: return "ERR";
    case LogLevel::off: break;
  }
  return "OFF";
}

[[nodiscard]] constexpr LogLevel parse_log_level(std::string_view text) noexcept {
  if (text == "debug") return LogLevel::debug;
  if (text == "warn" || text == "warning") return LogLevel::warn;
  if (text == "error") return LogLevel::error;
  if (text == "off" || text == "none") return LogLevel::off;
  return LogLevel::info;
}

class Log {
 public:
  static void set_level(LogLevel level) noexcept { level_ = level; }

  [[nodiscard]] static LogLevel level() noexcept { return level_; }

  [[nodiscard]] static bool enabled(LogLevel level) noexcept {
    return level_ != LogLevel::off && level >= level_;
  }

  __attribute__((format(printf, 2, 3))) static void emit(LogLevel level, const char* format,
                                                         ...) noexcept {
    if (!enabled(level)) return;
    const std::lock_guard guard{mutex()};
    std::array<char, 32> stamp{};
    format_stamp(stamp);
    std::fprintf(stderr, "%s %s ", stamp.data(), log_level_name(level).data());
    va_list args;
    va_start(args, format);
    std::vfprintf(stderr, format, args);
    va_end(args);
    std::fputc('\n', stderr);
    std::fflush(stderr);
  }

 private:
  static void format_stamp(std::array<char, 32>& out) noexcept {
    const auto now = std::chrono::system_clock::now();
    const auto seconds = std::chrono::floor<std::chrono::seconds>(now);
    const auto millis =
        std::chrono::duration_cast<std::chrono::milliseconds>(now - seconds).count();
    const auto raw = std::chrono::system_clock::to_time_t(seconds);
    std::tm parts{};
#if defined(_WIN32)
    localtime_s(&parts, &raw);
#else
    localtime_r(&raw, &parts);
#endif
    std::array<char, 24> head{};
    if (std::strftime(head.data(), head.size(), "%Y-%m-%d %H:%M:%S", &parts) == 0) {
      out[0] = '\0';
      return;
    }
    std::snprintf(out.data(), out.size(), "%s.%03d", head.data(), static_cast<int>(millis));
  }

  static std::mutex& mutex() noexcept {
    static std::mutex instance;
    return instance;
  }

  static inline LogLevel level_{LogLevel::info};
};

#define NORR_LOG_DEBUG(...) ::norr::Log::emit(::norr::LogLevel::debug, __VA_ARGS__)
#define NORR_LOG_INFO(...) ::norr::Log::emit(::norr::LogLevel::info, __VA_ARGS__)
#define NORR_LOG_WARN(...) ::norr::Log::emit(::norr::LogLevel::warn, __VA_ARGS__)
#define NORR_LOG_ERROR(...) ::norr::Log::emit(::norr::LogLevel::error, __VA_ARGS__)
}
