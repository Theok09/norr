#include <csignal>
#include <cstdio>
#include <string>
#include <string_view>

#include "norr/config.hpp"
#include "norr/crypto.hpp"
#include "norr/notify.hpp"
#include "norr/privilege.hpp"
#include "norr/quic_transport.hpp"
#include "norr/runtime.hpp"
#include "norr/tls.hpp"
#include "norr/tun.hpp"
#include "norr/udp_transport.hpp"
#include "norr/worker.hpp"

namespace {
constexpr std::string_view kVersion = "0.1.0";

int usage() {
  std::fputs(
      "usage: norr <command>\n"
      "\n"
      "  run\n"
      "  check\n"
      "  keygen\n"
      "  features\n"
      "  hardening\n"
      "  version\n",
      stderr);
  return 2;
}

int wrong_usage(std::string_view form) {
  std::fprintf(stderr, "usage: norr %s\n", std::string{form}.c_str());
  return 2;
}

void print_hex(std::span<const std::byte> bytes) {
  for (const auto byte : bytes) std::printf("%02x", static_cast<unsigned>(byte));
}

int check(const std::string& path) {
  const auto config = norr::load_config_file(path);
  if (!config) {
    const auto& problem = config.error();
    std::fprintf(stderr, "%s", path.c_str());
    if (problem.line != 0) std::fprintf(stderr, ":%zu", problem.line);
    std::fprintf(stderr, ": %s", std::string{norr::config_error_message(problem.error)}.c_str());
    if (!problem.detail.empty()) std::fprintf(stderr, " (%s)", problem.detail.c_str());
    std::fputc('\n', stderr);
    return 1;
  }

  std::printf("ok  port %u  %s\n", config->listen_port, config->identity_key_file.c_str());
  return 0;
}

norr::Runtime* g_runtime = nullptr;

extern "C" void handle_signal(int) {
  if (g_runtime != nullptr) g_runtime->stop();
}

int run(const std::string& path) {
  const auto config = norr::load_config_file(path);
  if (!config) {
    const auto& problem = config.error();
    std::fprintf(stderr, "%s", path.c_str());
    if (problem.line != 0) std::fprintf(stderr, ":%zu", problem.line);
    std::fprintf(stderr, ": %s", std::string{norr::config_error_message(problem.error)}.c_str());
    if (!problem.detail.empty()) std::fprintf(stderr, " (%s)", problem.detail.c_str());
    std::fputc('\n', stderr);
    return 1;
  }

  norr::Runtime runtime;
  if (const auto started = runtime.start(*config); !started) {
    const auto& problem = started.error();
    std::fprintf(stderr, "%s", std::string{norr::runtime_error_message(problem.error)}.c_str());
    if (!problem.detail.empty()) std::fprintf(stderr, ": %s", problem.detail.c_str());
    std::fputc('\n', stderr);
    return 1;
  }

  static_cast<void>(norr::disable_core_dumps());
  static_cast<void>(norr::set_no_new_privileges());

  g_runtime = &runtime;
  std::signal(SIGINT, handle_signal);
  std::signal(SIGTERM, handle_signal);

  std::signal(SIGPIPE, SIG_IGN);

  std::printf("%s  port %u  peers %zu\n", runtime.interface_name().c_str(),
              config->listen_port, runtime.peer_count());
  std::fflush(stdout);

  const auto dialed = runtime.dial_configured_peers();
  if (dialed > 0) std::printf("dialing %zu\n", dialed);
  std::fflush(stdout);

  static_cast<void>(norr::notify_ready());

  runtime.run();

  static_cast<void>(norr::notify_stopping());
  g_runtime = nullptr;

  const auto& stats = runtime.stats();
  const auto& control = runtime.control_stats();
  std::printf("out %llu  in %llu  drops %llu\n",
              static_cast<unsigned long long>(stats.tun_to_udp),
              static_cast<unsigned long long>(stats.udp_to_tun),
              static_cast<unsigned long long>(stats.drops));
  std::printf("handshakes started %llu  completed %llu  failed %llu\n",
              static_cast<unsigned long long>(control.handshakes_started),
              static_cast<unsigned long long>(control.handshakes_completed),
              static_cast<unsigned long long>(control.handshakes_failed));

  for (std::size_t index = 0; index < stats.drop_reasons.size(); ++index) {
    if (stats.drop_reasons[index] == 0) continue;
    std::printf("drop %s %llu\n",
                std::string{norr::drop_reason_message(static_cast<norr::DropReason>(index))}.c_str(),
                static_cast<unsigned long long>(stats.drop_reasons[index]));
  }
  return 0;
}

int keygen() {
  if (!norr::crypto_available() || !norr::crypto_init()) {
    std::fputs("crypto backend unavailable\n", stderr);
    return 1;
  }
  const auto pair = norr::generate_keypair();
  if (!pair) {
    std::fputs("key generation failed\n", stderr);
    return 1;
  }

  std::printf("private ");
  print_hex(pair->private_key);
  std::printf("\n");
  std::fprintf(stderr, "public  ");
  for (const auto byte : pair->public_key) {
    std::fprintf(stderr, "%02x", static_cast<unsigned>(byte));
  }
  std::fputc('\n', stderr);
  return 0;
}

int features() {
  std::printf("crypto     %s\n", norr::crypto_available() ? "libsodium" : "none");
  std::printf("tls        %s\n", norr::tls_available() ? "gnutls" : "none");
  std::printf("quic       %s\n",
              norr::quic_available() ? std::string{norr::quic_backend_version()}.c_str() : "none");
  std::printf("udp        %s\n", norr::UdpTransport::supported() ? "yes" : "no");
  std::printf("tun        %s\n", norr::TunDevice::supported() ? "yes" : "no");
  return 0;
}

int hardening() {
  const auto state = norr::current_privilege_state();
  std::printf("uid        %u\n", state.uid);
  std::printf("root       %s\n", state.root ? "yes" : "no");
  std::printf("core dumps %s\n", state.core_dumps_disabled ? "disabled" : "enabled");
  std::printf("no-new-priv %s\n", state.no_new_privileges ? "yes" : "no");

  return state.root ? 1 : 0;
}

}

int main(int argc, char* argv[]) {
  if (argc < 2) return usage();
  const std::string_view command{argv[1]};

  if (command == "version") return argc == 2 ? (std::printf("norr %s\n", kVersion.data()), 0)
                                             : wrong_usage("version");
  if (command == "run") return argc == 3 ? run(argv[2]) : wrong_usage("run <file>");
  if (command == "check") return argc == 3 ? check(argv[2]) : wrong_usage("check <file>");
  if (command == "keygen") return argc == 2 ? keygen() : wrong_usage("keygen");
  if (command == "features") return argc == 2 ? features() : wrong_usage("features");
  if (command == "hardening") return argc == 2 ? hardening() : wrong_usage("hardening");

  std::fprintf(stderr, "unknown command: %s\n", argv[1]);
  return usage();
}
