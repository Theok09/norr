cmake_minimum_required(VERSION 3.25)

project(norr VERSION 0.1.0 LANGUAGES CXX)

option(NORR_BUILD_TESTS "Build unit tests" ON)
# libsodium supplies X25519 and ChaCha20-Poly1305. It is required for the real
# datapath; without it the crypto layer reports unsupported_platform, exactly as
# the socket and TUN layers do off Linux, so the project stays buildable on a
# development machine without pretending the tunnel works there.
option(NORR_USE_LIBSODIUM "Build the libsodium-backed crypto layer" ON)
option(NORR_BUILD_FUZZERS "Build libFuzzer targets (Clang only)" OFF)
option(NORR_ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(norr_core
    src/address.cpp
    src/blake2s.cpp
    src/capability.cpp
    src/carrier.cpp
    src/config.cpp
    src/congestion.cpp
    src/bench.cpp
    src/control_plane.cpp
    src/cookie.cpp
    src/crypto.cpp
    src/endpoint.cpp
    src/fec.cpp
    src/file_descriptor.cpp
    src/flow_hash.cpp
    src/handshake.cpp
    src/handshake_frame.cpp
    src/io_backend.cpp
    src/ip_packet.cpp
    src/key_schedule.cpp
    src/load_monitor.cpp
    src/metrics.cpp
    src/notify.cpp
    src/noise.cpp
    src/nonce.cpp
    src/pacer.cpp
    src/path_selector.cpp
    src/packet.cpp
    src/privilege.cpp
    src/qos.cpp
    src/quic_transport.cpp
    src/rate_limit.cpp
    src/replay_window.cpp
    src/runtime.cpp
    src/routing.cpp
    src/session.cpp
    src/timers.cpp
    src/tls.cpp
    src/tun.cpp
    src/tcp_transport.cpp
    src/udp_transport.cpp
    src/worker.cpp
    src/worker_pool.cpp
)
target_include_directories(norr_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_features(norr_core PUBLIC cxx_std_23)

find_package(Threads REQUIRED)
target_link_libraries(norr_core PUBLIC Threads::Threads)

if(NORR_USE_LIBSODIUM)
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(SODIUM QUIET libsodium)
    endif()
    if(NOT SODIUM_FOUND)
        find_path(SODIUM_INCLUDE_DIR sodium.h)
        find_library(SODIUM_LIBRARY NAMES sodium libsodium)
        if(SODIUM_INCLUDE_DIR AND SODIUM_LIBRARY)
            set(SODIUM_FOUND TRUE)
            set(SODIUM_INCLUDE_DIRS ${SODIUM_INCLUDE_DIR})
            set(SODIUM_LIBRARIES ${SODIUM_LIBRARY})
        endif()
    endif()

    if(SODIUM_FOUND)
        target_compile_definitions(norr_core PUBLIC NORR_HAVE_LIBSODIUM=1)
        target_include_directories(norr_core PUBLIC ${SODIUM_INCLUDE_DIRS})
        # pkg-config reports the library name and its directory separately.
        # Passing only the name leaves the linker unable to find a libsodium
        # outside the default search path, which is the normal case for
        # Homebrew, so the search directories must be passed too.
        if(SODIUM_LIBRARY_DIRS)
            target_link_directories(norr_core PUBLIC ${SODIUM_LIBRARY_DIRS})
        endif()
        target_link_libraries(norr_core PUBLIC ${SODIUM_LIBRARIES})
        message(STATUS "libsodium found: crypto layer enabled")
    else()
        message(WARNING
            "libsodium not found: the crypto layer will report unsupported_platform. "
            "Install libsodium-dev to build the real datapath.")
    endif()
endif()

# GnuTLS provides TLS 1.3 for the TCP carrier. Optional: without it the TLS
# layer reports `unsupported` exactly as the QUIC adapter does, so the project
# still builds on a machine that lacks it.
option(NORR_USE_GNUTLS "Build the GnuTLS-backed TLS layer" ON)
# ngtcp2 provides QUIC v1. It needs GnuTLS for its crypto callbacks, so it is
# only attempted when the TLS layer is also enabled.
option(NORR_USE_NGTCP2 "Build the ngtcp2-backed QUIC layer" ON)
if(NORR_USE_GNUTLS)
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(GNUTLS QUIET gnutls)
    endif()
    if(GNUTLS_FOUND)
        target_compile_definitions(norr_core PUBLIC NORR_HAVE_GNUTLS=1)
        target_include_directories(norr_core PUBLIC ${GNUTLS_INCLUDE_DIRS})
        if(GNUTLS_LIBRARY_DIRS)
            target_link_directories(norr_core PUBLIC ${GNUTLS_LIBRARY_DIRS})
        endif()
        target_link_libraries(norr_core PUBLIC ${GNUTLS_LIBRARIES})
        message(STATUS "GnuTLS found: TLS layer enabled")
    else()
        message(WARNING "GnuTLS not found: the TLS layer will report unsupported")
    endif()
endif()

if(NORR_USE_NGTCP2 AND GNUTLS_FOUND)
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(NGTCP2 QUIET libngtcp2)
        pkg_check_modules(NGTCP2_GNUTLS QUIET libngtcp2_crypto_gnutls)
    endif()
    if(NGTCP2_FOUND AND NGTCP2_GNUTLS_FOUND)
        target_compile_definitions(norr_core PUBLIC NORR_HAVE_NGTCP2=1)
        target_include_directories(norr_core PUBLIC ${NGTCP2_INCLUDE_DIRS} ${NGTCP2_GNUTLS_INCLUDE_DIRS})
        if(NGTCP2_LIBRARY_DIRS)
            target_link_directories(norr_core PUBLIC ${NGTCP2_LIBRARY_DIRS})
        endif()
        if(NGTCP2_GNUTLS_LIBRARY_DIRS)
            target_link_directories(norr_core PUBLIC ${NGTCP2_GNUTLS_LIBRARY_DIRS})
        endif()
        target_link_libraries(norr_core PUBLIC ${NGTCP2_LIBRARIES} ${NGTCP2_GNUTLS_LIBRARIES})
        message(STATUS "ngtcp2 found: QUIC layer enabled")
    else()
        message(STATUS "ngtcp2 not found: QUIC reports unsupported")
    endif()
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(norr_core PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror)
endif()

if(NORR_ENABLE_SANITIZERS)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
        message(FATAL_ERROR "Sanitizers currently require Clang or GCC")
    endif()
    add_library(norr_sanitizers INTERFACE)
    target_compile_options(norr_sanitizers INTERFACE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(norr_sanitizers INTERFACE -fsanitize=address,undefined)
    target_link_libraries(norr_core PUBLIC norr_sanitizers)
endif()

add_executable(norr src/main.cpp)
target_link_libraries(norr PRIVATE norr_core)


include(GNUInstallDirs)

install(TARGETS norr RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

install(PROGRAMS scripts/norr-quick DESTINATION ${CMAKE_INSTALL_BINDIR})

install(FILES deployment/norr.toml.example
        DESTINATION ${CMAKE_INSTALL_DOCDIR}
        RENAME norr.toml.example)

install(FILES README.md docs/known-limitations.md
        DESTINATION ${CMAKE_INSTALL_DOCDIR})

install(FILES LICENSE DESTINATION ${CMAKE_INSTALL_DOCDIR})

install(FILES deployment/systemd/norr.service
        DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/systemd/system)

if(NORR_BUILD_TESTS)
    enable_testing()
    # Test targets include "check.hpp" from tests/ by plain name.
    add_library(tests_support INTERFACE)
    target_include_directories(tests_support INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/tests)
    add_executable(norr_unit_tests tests/packet_test.cpp)
    target_link_libraries(norr_unit_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_unit_tests COMMAND norr_unit_tests)
    add_executable(norr_handshake_tests tests/handshake_test.cpp)
    target_link_libraries(norr_handshake_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_handshake_tests COMMAND norr_handshake_tests)
    add_executable(norr_config_tests tests/config_test.cpp)
    target_link_libraries(norr_config_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_config_tests COMMAND norr_config_tests)
    add_executable(norr_key_schedule_tests tests/key_schedule_test.cpp)
    target_link_libraries(norr_key_schedule_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_key_schedule_tests COMMAND norr_key_schedule_tests)
    add_executable(norr_address_tests tests/address_test.cpp)
    target_link_libraries(norr_address_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_address_tests COMMAND norr_address_tests)
    add_executable(norr_routing_tests tests/routing_test.cpp)
    target_link_libraries(norr_routing_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_routing_tests COMMAND norr_routing_tests)
    add_executable(norr_endpoint_tests tests/endpoint_test.cpp)
    target_link_libraries(norr_endpoint_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_endpoint_tests COMMAND norr_endpoint_tests)
    add_executable(norr_blake2s_tests tests/blake2s_test.cpp)
    target_link_libraries(norr_blake2s_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_blake2s_tests COMMAND norr_blake2s_tests)
    add_executable(norr_crypto_tests tests/crypto_test.cpp)
    target_link_libraries(norr_crypto_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_crypto_tests COMMAND norr_crypto_tests)
    add_executable(norr_session_tests tests/session_test.cpp)
    target_link_libraries(norr_session_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_session_tests COMMAND norr_session_tests)
    add_executable(norr_noise_tests tests/noise_test.cpp)
    target_link_libraries(norr_noise_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_noise_tests COMMAND norr_noise_tests)
    add_executable(norr_rate_limit_tests tests/rate_limit_test.cpp)
    target_link_libraries(norr_rate_limit_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_rate_limit_tests COMMAND norr_rate_limit_tests)
    add_executable(norr_timers_tests tests/timers_test.cpp)
    target_link_libraries(norr_timers_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_timers_tests COMMAND norr_timers_tests)
    add_executable(norr_flow_hash_tests tests/flow_hash_test.cpp)
    target_link_libraries(norr_flow_hash_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_flow_hash_tests COMMAND norr_flow_hash_tests)
    add_executable(norr_control_plane_tests tests/control_plane_test.cpp)
    target_link_libraries(norr_control_plane_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_control_plane_tests COMMAND norr_control_plane_tests)
    add_executable(norr_load_monitor_tests tests/load_monitor_test.cpp)
    target_link_libraries(norr_load_monitor_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_load_monitor_tests COMMAND norr_load_monitor_tests)
    add_executable(norr_cookie_tests tests/cookie_test.cpp)
    target_link_libraries(norr_cookie_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_cookie_tests COMMAND norr_cookie_tests)
    add_executable(norr_pacer_tests tests/pacer_test.cpp)
    target_link_libraries(norr_pacer_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_pacer_tests COMMAND norr_pacer_tests)
    add_executable(norr_worker_pool_tests tests/worker_pool_test.cpp)
    target_link_libraries(norr_worker_pool_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_worker_pool_tests COMMAND norr_worker_pool_tests)
    add_executable(norr_tcp_transport_tests tests/tcp_transport_test.cpp)
    target_link_libraries(norr_tcp_transport_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_tcp_transport_tests COMMAND norr_tcp_transport_tests)
    add_executable(norr_path_selector_tests tests/path_selector_test.cpp)
    target_link_libraries(norr_path_selector_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_path_selector_tests COMMAND norr_path_selector_tests)
    add_executable(norr_qos_tests tests/qos_test.cpp)
    target_link_libraries(norr_qos_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_qos_tests COMMAND norr_qos_tests)
    add_executable(norr_fec_tests tests/fec_test.cpp)
    target_link_libraries(norr_fec_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_fec_tests COMMAND norr_fec_tests)
    add_executable(norr_quic_transport_tests tests/quic_transport_test.cpp)
    target_link_libraries(norr_quic_transport_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_quic_transport_tests COMMAND norr_quic_transport_tests)
    add_executable(norr_reconnect_tests tests/reconnect_test.cpp)
    target_link_libraries(norr_reconnect_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_reconnect_tests COMMAND norr_reconnect_tests)
    add_executable(norr_tls_tests tests/tls_test.cpp)
    target_link_libraries(norr_tls_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_tls_tests COMMAND norr_tls_tests)
    add_executable(norr_failover_tests tests/failover_test.cpp)
    target_link_libraries(norr_failover_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_failover_tests COMMAND norr_failover_tests)
    add_executable(norr_congestion_tests tests/congestion_test.cpp)
    target_link_libraries(norr_congestion_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_congestion_tests COMMAND norr_congestion_tests)
    add_executable(norr_privilege_tests tests/privilege_test.cpp)
    target_link_libraries(norr_privilege_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_privilege_tests COMMAND norr_privilege_tests)
    add_executable(norr_io_backend_tests tests/io_backend_test.cpp)
    target_link_libraries(norr_io_backend_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_io_backend_tests COMMAND norr_io_backend_tests)
    add_executable(norr_worker_tests tests/worker_test.cpp)
    target_link_libraries(norr_worker_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_worker_tests COMMAND norr_worker_tests)
    # Exercises real sockets and, where permitted, a real TUN device. On a
    # non-Linux host it verifies that every entry point reports
    # unsupported_platform instead of pretending to work.
    add_executable(norr_datapath_tests tests/datapath_test.cpp)
    target_link_libraries(norr_datapath_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_datapath_tests COMMAND norr_datapath_tests)

    # Replaces global operator new to count allocations, so it must not be
    # linked with anything that allocates for its own reasons.
    add_executable(norr_notify_tests tests/notify_test.cpp)
    target_link_libraries(norr_notify_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_notify_tests COMMAND norr_notify_tests)

    add_executable(norr_tcp_tls_tests tests/tcp_tls_test.cpp)
    target_link_libraries(norr_tcp_tls_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_tcp_tls_tests COMMAND norr_tcp_tls_tests)

    add_executable(norr_metrics_tests tests/metrics_test.cpp)
    target_link_libraries(norr_metrics_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_metrics_tests COMMAND norr_metrics_tests)

    add_executable(norr_alloc_tests tests/alloc_test.cpp)
    target_link_libraries(norr_alloc_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_alloc_tests COMMAND norr_alloc_tests)

    # Two nodes in separate network namespaces carrying real ICMP over a real
    # TUN device. This is the only test that exercises `norr run` — every other
    # test drives the library directly, so without it the binary could stop
    # tunnelling and the suite would still pass.
    #
    # Needs Linux, root and CAP_NET_ADMIN, so it reports "skipped" rather than
    # failing on a developer machine that cannot provide them.
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        add_test(NAME norr_e2e_tunnel
                 COMMAND ${CMAKE_COMMAND} -E env NORR=$<TARGET_FILE:norr>
                         bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/e2e_tunnel.sh)
        set_tests_properties(norr_e2e_tunnel PROPERTIES
            SKIP_RETURN_CODE 77
            TIMEOUT 120)

        add_test(NAME norr_e2e_tcp
                 COMMAND ${CMAKE_COMMAND} -E env NORR=$<TARGET_FILE:norr>
                         bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/e2e_tcp.sh)
        set_tests_properties(norr_e2e_tcp PROPERTIES
            SKIP_RETURN_CODE 77
            TIMEOUT 120)

        add_test(NAME norr_e2e_quic
                 COMMAND ${CMAKE_COMMAND} -E env NORR=$<TARGET_FILE:norr>
                         bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/e2e_quic.sh)
        set_tests_properties(norr_e2e_quic PROPERTIES
            SKIP_RETURN_CODE 77
            TIMEOUT 120)

        add_test(NAME norr_e2e_multipeer
                 COMMAND ${CMAKE_COMMAND} -E env NORR=$<TARGET_FILE:norr>
                         bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/e2e_multipeer.sh)
        set_tests_properties(norr_e2e_multipeer PROPERTIES
            SKIP_RETURN_CODE 77
            TIMEOUT 180)

        add_test(NAME norr_e2e_fec
                 COMMAND ${CMAKE_COMMAND} -E env NORR=$<TARGET_FILE:norr>
                         bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/e2e_fec.sh)
        set_tests_properties(norr_e2e_fec PROPERTIES
            SKIP_RETURN_CODE 77
            TIMEOUT 180)
    endif()
endif()

# The benchmark harness is a separate executable, not a test: it reports
# distributions rather than asserting, and a debug build's figures are not
# comparable to a release build's.
add_executable(norr_bench bench/main.cpp)
target_link_libraries(norr_bench PRIVATE norr_core)

# End-to-end benchmark: two real nodes over real sockets, covering the gates
# in performance/acceptance-gates.md that per-component timing cannot reach.
add_executable(norr_bench_e2e bench/end_to_end.cpp)
target_link_libraries(norr_bench_e2e PRIVATE norr_core)

# Gates E and F: impairment applied by tc netem on a veth pair, so delay and
# loss are real rather than simulated in the harness.
add_executable(norr_bench_netem bench/netem.cpp)
target_link_libraries(norr_bench_netem PRIVATE norr_core)

if(NORR_BUILD_FUZZERS)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "libFuzzer targets require Clang")
    endif()
    if(APPLE)
        message(WARNING "Xcode does not ship the libFuzzer runtime; building a deterministic parser smoke-fuzzer instead. Real coverage-guided fuzzing runs in CI on Linux.")
        add_executable(norr_packet_fuzz fuzz/packet_fuzz_smoke.cpp)
        target_link_libraries(norr_packet_fuzz PRIVATE norr_core)
        # The libFuzzer entry points still compile here, driven deterministically,
        # so a macOS build cannot silently rot while only CI exercises them.
        # Each entry point defines LLVMFuzzerTestOneInput, so each needs its own
        # binary rather than being linked together.
        foreach(fuzz_parser handshake_frame config ip_packet noise tcp_frame fec)
            add_executable(norr_${fuzz_parser}_smoke fuzz/parser_smoke.cpp fuzz/${fuzz_parser}_fuzz.cpp)
            target_link_libraries(norr_${fuzz_parser}_smoke PRIVATE norr_core)
        endforeach()
    else()
        foreach(fuzz_target packet handshake_frame config ip_packet noise tcp_frame fec)
            add_executable(norr_${fuzz_target}_fuzz fuzz/${fuzz_target}_fuzz.cpp)
            target_link_libraries(norr_${fuzz_target}_fuzz PRIVATE norr_core)
            target_compile_options(norr_${fuzz_target}_fuzz PRIVATE -fsanitize=fuzzer,address,undefined)
            target_link_options(norr_${fuzz_target}_fuzz PRIVATE -fsanitize=fuzzer,address,undefined)
        endforeach()
    endif()
endif()
