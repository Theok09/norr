cmake_minimum_required(VERSION 3.25)

project(norr VERSION 0.2.1 LANGUAGES CXX)

if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/tests/check.hpp)
    set(NORR_TESTS_DEFAULT ON)
else()
    set(NORR_TESTS_DEFAULT OFF)
endif()
option(NORR_BUILD_TESTS "Build unit tests" ${NORR_TESTS_DEFAULT})
option(NORR_USE_LIBSODIUM "Build the libsodium-backed crypto layer" ON)
option(NORR_BUILD_FUZZERS "Build libFuzzer targets (Clang only)" OFF)
option(NORR_ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(NORR_ENABLE_TSAN "Enable ThreadSanitizer" OFF)

option(NORR_STATIC "Link a fully static executable" OFF)

macro(norr_link_package prefix)
    if(NORR_STATIC AND ${prefix}_STATIC_LIBRARIES)
        target_link_libraries(norr_core PUBLIC ${${prefix}_STATIC_LIBRARIES})
        if(${prefix}_STATIC_LIBRARY_DIRS)
            target_link_directories(norr_core PUBLIC ${${prefix}_STATIC_LIBRARY_DIRS})
        endif()
    else()
        target_link_libraries(norr_core PUBLIC ${${prefix}_LIBRARIES})
    endif()
endmacro()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(norr_core
    src/address.cpp
    src/blake2s.cpp
    src/capability.cpp
    src/camouflage.cpp
    src/carrier.cpp
    src/config.cpp
    src/tuning.cpp
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
    src/icmp_transport.cpp
    src/rawproto_transport.cpp
    src/dns_framer.cpp
    src/ssh_framer.cpp
    src/ip_packet.cpp
    src/key_schedule.cpp
    src/load_monitor.cpp
    src/metrics.cpp
    src/notify.cpp
    src/noise.cpp
    src/obfuscation.cpp
    src/reality.cpp
    src/fallback_proxy.cpp
    src/offload.cpp
    src/parallel.cpp
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
    src/spoof_pool.cpp
    src/spoof_feedback.cpp
    src/spoof_envelope.cpp
    src/spoof_sender.cpp
    src/spooftest.cpp
    src/spooftest_cli.cpp
    src/timers.cpp
    src/tls.cpp
    src/tun.cpp
    src/tcp_transport.cpp
    src/udp_transport.cpp
    src/worker.cpp
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
        if(SODIUM_LIBRARY_DIRS)
            target_link_directories(norr_core PUBLIC ${SODIUM_LIBRARY_DIRS})
        endif()
        norr_link_package(SODIUM)
        message(STATUS "libsodium found: crypto layer enabled")
    else()
        message(WARNING
            "libsodium not found: the crypto layer will report unsupported_platform. "
            "Install libsodium-dev to build the real datapath.")
    endif()
endif()

option(NORR_USE_OPENSSL "Use OpenSSL for datapath AEAD" ON)
if(NORR_USE_OPENSSL)
    if(NORR_STATIC)
        set(OPENSSL_USE_STATIC_LIBS TRUE)
    endif()
    find_package(OpenSSL 3.0 QUIET COMPONENTS Crypto)
    if(OpenSSL_FOUND)
        target_compile_definitions(norr_core PUBLIC NORR_HAVE_OPENSSL=1)
        target_link_libraries(norr_core PUBLIC OpenSSL::Crypto)
        message(STATUS "OpenSSL found: datapath AEAD uses OpenSSL")
    endif()
endif()

option(NORR_USE_GNUTLS "Build the GnuTLS-backed TLS layer" ON)
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
        norr_link_package(GNUTLS)
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
        norr_link_package(NGTCP2_GNUTLS)
        norr_link_package(NGTCP2)
        message(STATUS "ngtcp2 found: QUIC layer enabled")
    else()
        message(STATUS "ngtcp2 not found: QUIC reports unsupported")
    endif()
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(norr_core PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror)
endif()

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

option(NORR_NATIVE "Tune the build for the host CPU (-march=native)" OFF)

set(NORR_AEAD_CIPHER "chacha20-poly1305" CACHE STRING "AEAD cipher: chacha20-poly1305 or aes-256-gcm")
if(NORR_AEAD_CIPHER STREQUAL "aes-256-gcm")
    target_compile_definitions(norr_core PUBLIC NORR_AEAD_CIPHER_NAME="AES-256-GCM")
elseif(NORR_AEAD_CIPHER STREQUAL "chacha20-poly1305")
    target_compile_definitions(norr_core PUBLIC NORR_AEAD_CIPHER_NAME="ChaCha20-Poly1305")
else()
    message(FATAL_ERROR "NORR_AEAD_CIPHER must be chacha20-poly1305 or aes-256-gcm")
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(norr_core PRIVATE
        $<$<CONFIG:Release>:-O3>
        $<$<CONFIG:Release>:-fno-plt>)
    if(NORR_NATIVE)
        target_compile_options(norr_core PRIVATE -march=native -mtune=native)
    endif()
    include(CheckIPOSupported)
    check_ipo_supported(RESULT norr_ipo_ok OUTPUT norr_ipo_msg)
    if(norr_ipo_ok)
        set_property(TARGET norr_core PROPERTY INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)
    else()
        message(STATUS "LTO unsupported: ${norr_ipo_msg}")
    endif()
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

if(NORR_ENABLE_TSAN)
    if(NORR_ENABLE_SANITIZERS)
        message(FATAL_ERROR "ThreadSanitizer cannot be combined with AddressSanitizer")
    endif()
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
        message(FATAL_ERROR "ThreadSanitizer requires Clang or GCC")
    endif()
    add_library(norr_tsan INTERFACE)
    target_compile_options(norr_tsan INTERFACE -fsanitize=thread -fno-omit-frame-pointer -g)
    target_link_options(norr_tsan INTERFACE -fsanitize=thread)
    target_link_libraries(norr_core PUBLIC norr_tsan)
endif()

add_executable(norrd src/main.cpp)
target_link_libraries(norrd PRIVATE norr_core)
target_compile_definitions(norrd PRIVATE NORR_VERSION="${PROJECT_VERSION}")
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(norrd PRIVATE $<$<CONFIG:Release>:-O3>)
    if(NORR_NATIVE)
        target_compile_options(norrd PRIVATE -march=native -mtune=native)
    endif()
    if(norr_ipo_ok)
        set_property(TARGET norrd PROPERTY INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)
    endif()
endif()
if(NORR_STATIC)
    target_link_options(norrd PRIVATE -static)
    set_target_properties(norrd PROPERTIES LINK_SEARCH_START_STATIC ON LINK_SEARCH_END_STATIC ON)
endif()

include(GNUInstallDirs)

install(TARGETS norrd RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(PROGRAMS scripts/norr DESTINATION ${CMAKE_INSTALL_BINDIR})
install(PROGRAMS scripts/norr-quick DESTINATION ${CMAKE_INSTALL_LIBDIR}/norr)
install(FILES deployment/systemd/norr@.service DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/systemd/system)
install(FILES README.md LICENSE docs/configuration.md DESTINATION ${CMAKE_INSTALL_DOCDIR})

if(NORR_BUILD_TESTS)
    enable_testing()
    add_library(tests_support INTERFACE)
    target_include_directories(tests_support INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/tests)
    add_executable(norr_unit_tests tests/packet_test.cpp)
    target_link_libraries(norr_unit_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_unit_tests COMMAND norr_unit_tests)
    add_executable(norr_handshake_tests tests/handshake_test.cpp)
    target_link_libraries(norr_handshake_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_handshake_tests COMMAND norr_handshake_tests)
    add_executable(norr_concurrency_tests tests/concurrency_test.cpp)
    target_link_libraries(norr_concurrency_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_concurrency_tests COMMAND norr_concurrency_tests)

    add_executable(norr_config_tests tests/config_test.cpp)
    target_link_libraries(norr_config_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_config_tests COMMAND norr_config_tests)
    add_executable(norr_obfuscation_tests tests/obfuscation_test.cpp)
    target_link_libraries(norr_obfuscation_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_obfuscation_tests COMMAND norr_obfuscation_tests)

    add_executable(norr_dns_framer_tests tests/dns_framer_test.cpp)
    target_link_libraries(norr_dns_framer_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_dns_framer_tests COMMAND norr_dns_framer_tests)

    add_executable(norr_ssh_framer_tests tests/ssh_framer_test.cpp)
    target_link_libraries(norr_ssh_framer_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_ssh_framer_tests COMMAND norr_ssh_framer_tests)
    add_executable(norr_reality_tests tests/reality_test.cpp)
    target_link_libraries(norr_reality_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_reality_tests COMMAND norr_reality_tests)
    add_executable(norr_icmp_tests tests/icmp_test.cpp)
    target_link_libraries(norr_icmp_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_icmp_tests COMMAND norr_icmp_tests)
    add_executable(norr_camouflage_tests tests/camouflage_test.cpp)
    target_link_libraries(norr_camouflage_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_camouflage_tests COMMAND norr_camouflage_tests)
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
    add_executable(norr_spooftest_tests tests/spooftest_test.cpp)
    target_link_libraries(norr_spooftest_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_spooftest_tests COMMAND norr_spooftest_tests)
    add_executable(norr_spoof_pool_tests tests/spoof_pool_test.cpp)
    target_link_libraries(norr_spoof_pool_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_spoof_pool_tests COMMAND norr_spoof_pool_tests)
    add_executable(norr_spoof_feedback_tests tests/spoof_feedback_test.cpp)
    target_link_libraries(norr_spoof_feedback_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_spoof_feedback_tests COMMAND norr_spoof_feedback_tests)
    add_executable(norr_spoof_envelope_tests tests/spoof_envelope_test.cpp)
    target_link_libraries(norr_spoof_envelope_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_spoof_envelope_tests COMMAND norr_spoof_envelope_tests)
    add_executable(norr_spoof_sender_tests tests/spoof_sender_test.cpp)
    target_link_libraries(norr_spoof_sender_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_spoof_sender_tests COMMAND norr_spoof_sender_tests)

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
    add_executable(norr_tcp_transport_tests tests/tcp_transport_test.cpp)
    target_link_libraries(norr_tcp_transport_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_tcp_transport_tests COMMAND norr_tcp_transport_tests)
    add_executable(norr_path_selector_tests tests/path_selector_test.cpp)
    target_link_libraries(norr_path_selector_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_path_selector_tests COMMAND norr_path_selector_tests)
    add_executable(norr_qos_tests tests/qos_test.cpp)
    target_link_libraries(norr_qos_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_qos_tests COMMAND norr_qos_tests)
    add_executable(norr_offload_tests tests/offload_test.cpp)
    target_link_libraries(norr_offload_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_offload_tests COMMAND norr_offload_tests)
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
    add_executable(norr_datapath_tests tests/datapath_test.cpp)
    target_link_libraries(norr_datapath_tests PRIVATE norr_core tests_support)
    add_test(NAME norr_datapath_tests COMMAND norr_datapath_tests)

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

    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        add_test(NAME norr_e2e_tunnel
                 COMMAND ${CMAKE_COMMAND} -E env NORR=$<TARGET_FILE:norrd>
                         bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/e2e_tunnel.sh)
        set_tests_properties(norr_e2e_tunnel PROPERTIES
            SKIP_RETURN_CODE 77
            TIMEOUT 120)

        add_test(NAME norr_e2e_tcp
                 COMMAND ${CMAKE_COMMAND} -E env NORR=$<TARGET_FILE:norrd>
                         bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/e2e_tcp.sh)
        set_tests_properties(norr_e2e_tcp PROPERTIES
            SKIP_RETURN_CODE 77
            TIMEOUT 120)

        add_test(NAME norr_e2e_quic
                 COMMAND ${CMAKE_COMMAND} -E env NORR=$<TARGET_FILE:norrd>
                         bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/e2e_quic.sh)
        set_tests_properties(norr_e2e_quic PROPERTIES
            SKIP_RETURN_CODE 77
            TIMEOUT 120)

        add_test(NAME norr_e2e_multipeer
                 COMMAND ${CMAKE_COMMAND} -E env NORR=$<TARGET_FILE:norrd>
                         bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/e2e_multipeer.sh)
        set_tests_properties(norr_e2e_multipeer PROPERTIES
            SKIP_RETURN_CODE 77
            TIMEOUT 180)

        add_test(NAME norr_e2e_fec
                 COMMAND ${CMAKE_COMMAND} -E env NORR=$<TARGET_FILE:norrd>
                         bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/e2e_fec.sh)
        set_tests_properties(norr_e2e_fec PROPERTIES
            SKIP_RETURN_CODE 77
            TIMEOUT 180)

        add_test(NAME norr_e2e_icmp6
                 COMMAND ${CMAKE_COMMAND} -E env NORR=$<TARGET_FILE:norrd>
                         bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/e2e_icmp6.sh)
        set_tests_properties(norr_e2e_icmp6 PROPERTIES
            SKIP_RETURN_CODE 77
            TIMEOUT 120)

        add_test(NAME norr_e2e_ipv6
                 COMMAND ${CMAKE_COMMAND} -E env NORR=$<TARGET_FILE:norrd>
                         bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/e2e_ipv6.sh)
        set_tests_properties(norr_e2e_ipv6 PROPERTIES
            SKIP_RETURN_CODE 77
            TIMEOUT 120)

        add_test(NAME norr_e2e_tcp_zombie
                 COMMAND ${CMAKE_COMMAND} -E env NORR=$<TARGET_FILE:norrd>
                         bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/e2e_tcp_zombie.sh)
        set_tests_properties(norr_e2e_tcp_zombie PROPERTIES
            SKIP_RETURN_CODE 77
            TIMEOUT 300)

        add_test(NAME norr_e2e_tcp_stale_server
                 COMMAND ${CMAKE_COMMAND} -E env NORR=$<TARGET_FILE:norrd>
                         bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/e2e_tcp_stale_server.sh)
        set_tests_properties(norr_e2e_tcp_stale_server PROPERTIES
            SKIP_RETURN_CODE 77
            TIMEOUT 300)

        add_test(NAME norr_e2e_reality_probe
                 COMMAND ${CMAKE_COMMAND} -E env NORR=$<TARGET_FILE:norrd>
                         bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/e2e_reality_probe.sh)
        set_tests_properties(norr_e2e_reality_probe PROPERTIES
            SKIP_RETURN_CODE 77
            TIMEOUT 120)

        add_test(NAME norr_e2e_cli
                 COMMAND ${CMAKE_COMMAND} -E env NORR=$<TARGET_FILE:norrd>
                         CLI=${CMAKE_CURRENT_SOURCE_DIR}/scripts/norr
                         bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/e2e_cli.sh)
        set_tests_properties(norr_e2e_cli PROPERTIES
            SKIP_RETURN_CODE 77
            TIMEOUT 180)

        add_test(NAME norr_e2e_camo_bulk
                 COMMAND ${CMAKE_COMMAND} -E env NORR=$<TARGET_FILE:norrd>
                         bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/e2e_camo_bulk.sh)
        set_tests_properties(norr_e2e_camo_bulk PROPERTIES
            SKIP_RETURN_CODE 77
            TIMEOUT 180)

        add_test(NAME norr_e2e_tcp_hygiene
                 COMMAND ${CMAKE_COMMAND} -E env NORR=$<TARGET_FILE:norrd>
                         bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/e2e_tcp_hygiene.sh)
        set_tests_properties(norr_e2e_tcp_hygiene PROPERTIES
            SKIP_RETURN_CODE 77
            TIMEOUT 180)

        add_test(NAME norr_e2e_fallback
                 COMMAND ${CMAKE_COMMAND} -E env NORR=$<TARGET_FILE:norrd>
                         bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/e2e_fallback.sh)
        set_tests_properties(norr_e2e_fallback PROPERTIES
            SKIP_RETURN_CODE 77
            TIMEOUT 300)

        if(NORR_ENABLE_SANITIZERS OR NORR_ENABLE_TSAN)
            set(NORR_E2E_BULK 0)
        else()
            set(NORR_E2E_BULK 1)
        endif()
        add_test(NAME norr_e2e_forward
                 COMMAND ${CMAKE_COMMAND} -E env NORR=$<TARGET_FILE:norrd>
                         sh ${CMAKE_CURRENT_SOURCE_DIR}/scripts/e2e_forward.sh)
        set_tests_properties(norr_e2e_forward PROPERTIES
            SKIP_RETURN_CODE 77
            TIMEOUT 120)
        add_test(NAME norr_e2e_gateway
                 COMMAND ${CMAKE_COMMAND} -E env NORR=$<TARGET_FILE:norrd> NORR_E2E_BULK=${NORR_E2E_BULK}
                         sh ${CMAKE_CURRENT_SOURCE_DIR}/scripts/e2e_gateway.sh)
        set_tests_properties(norr_e2e_gateway PROPERTIES
            SKIP_RETURN_CODE 77
            TIMEOUT 180)
    endif()
endif()

if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/bench/main.cpp)
    add_executable(norr_bench bench/main.cpp)
    target_link_libraries(norr_bench PRIVATE norr_core)

    add_executable(norr_bench_e2e bench/end_to_end.cpp)
    target_link_libraries(norr_bench_e2e PRIVATE norr_core)

    add_executable(norr_bench_netem bench/netem.cpp)
    target_link_libraries(norr_bench_netem PRIVATE norr_core)
endif()

if(NORR_BUILD_FUZZERS)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "libFuzzer targets require Clang")
    endif()
    if(APPLE)
        message(WARNING "Xcode does not ship the libFuzzer runtime; building a deterministic parser smoke-fuzzer instead. Real coverage-guided fuzzing runs in CI on Linux.")
        add_executable(norr_packet_fuzz fuzz/packet_fuzz_smoke.cpp)
        target_link_libraries(norr_packet_fuzz PRIVATE norr_core)
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
