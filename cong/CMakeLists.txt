# cong_nanomq: JSONL login + ACL policy plugin for NanoMQ, plus its core
# rule-engine unit tests.
#
# Layout of this directory:
#   src/core/           the rule engine (auth digest schemes + MQTT ACL),
#                       broker-agnostic: libc + libcrypto + a cJSON header
#   src/cong_nanomq.c   the NanoMQ-side hook adapter (HOOK_BASIC_AUTH /
#                       HOOK_ACL_CHECK / HOOK_RELOAD)
#   include/cjson/      forwarding header onto nng's vendored cJSON
#   rules/              sample policy files (env: CONG_AUTH_FILE, CONG_ACL_FILE)
#   tools/cong_pwgen.py password derivation + rule-file validator
#   test/test_core.c    unit tests for the rule engine (no broker needed)
#   conf/ deploy/       broker config with the plugin block, systemd unit
#   patch/              the NanoNNG CONNECT-hook patch, applied to the nng
#                       submodule at build time (nng is a git submodule, so
#                       that one file cannot be committed in-tree)
#
# The plugin .so must NOT link libnng: plugin_hook_register() is provided by
# the nanomq process that dlopen()s it, which exports the hook registry via
# ENABLE_EXPORTS + -rdynamic (see nanomq/CMakeLists.txt). cJSON is nng's
# vendored copy compiled into the plugin and hidden behind -Bsymbolic, so the
# plugin and the broker never mix two cJSON versions in one process.

set(CONG_CORE_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/core/cong_util.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/core/cong_digest.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/core/cong_auth.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/core/cong_acl.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/core/cong_topic.c
)

# The nng submodule lives at <repo>/nng. Its CMake project() only publishes
# ${nng_SOURCE_DIR} inside its own subdirectory scope, which a sibling scope
# does not see - so point at the submodule directly and fail loudly when it
# has not been checked out.
set(CONG_NNG_DIR ${CMAKE_SOURCE_DIR}/nng)
set(CONG_NNG_CJSON ${CONG_NNG_DIR}/src/supplemental/nanolib/cJSON.c)

if(NOT EXISTS ${CONG_NNG_CJSON})
  message(FATAL_ERROR "cong: ${CONG_NNG_CJSON} not found - run 'git submodule update --init --recursive' first")
endif()

set(CONG_PLUGIN_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cong_nanomq.c
    ${CONG_CORE_SOURCES}
    ${CONG_NNG_CJSON}
)

set(CONG_INCLUDE_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}/src/core
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    # "include/plugin.h" of the broker, and the nng headers it pulls in
    ${CMAKE_SOURCE_DIR}/nanomq
    ${CONG_NNG_DIR}/include
)

add_library(cong_nanomq MODULE ${CONG_PLUGIN_SOURCES})

set_target_properties(cong_nanomq PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    C_STANDARD 99
    # keep the plain name: nanomq.conf's plugin { libs } points at
    # .../cong_nanomq.so, and Linux would otherwise prepend "lib"
    PREFIX ""
)

target_include_directories(cong_nanomq PRIVATE ${CONG_INCLUDE_DIRS})

# -Bsymbolic binds the plugin's own symbols (cong_*, cJSON_*) internally; the
# single unresolved symbol left is plugin_hook_register, supplied by the host.
if(NOT APPLE)
  target_link_options(cong_nanomq PRIVATE "-Wl,-Bsymbolic")
endif()

find_package(OpenSSL REQUIRED)
target_link_libraries(cong_nanomq PRIVATE OpenSSL::Crypto ${CMAKE_DL_LIBS})
if(NOT WIN32)
  target_link_libraries(cong_nanomq PRIVATE pthread m)
endif()

# nng's cJSON.c is third-party code; keep its warnings out of our build.
set_source_files_properties(${CONG_NNG_CJSON} PROPERTIES COMPILE_OPTIONS "-w")

# ------------------------------------------------------------- unit tests
# Build and run the core rule-engine tests standalone (no broker, no patches).
add_executable(cong_test
    ${CMAKE_CURRENT_SOURCE_DIR}/test/test_core.c
    ${CONG_CORE_SOURCES}
    ${CONG_NNG_CJSON}
)

set_target_properties(cong_test PROPERTIES C_STANDARD 99)

target_include_directories(cong_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/core
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CONG_NNG_DIR}/include
)

set_source_files_properties(${CONG_NNG_CJSON}
    PROPERTIES COMPILE_OPTIONS "-w")

target_link_libraries(cong_test PRIVATE OpenSSL::Crypto)
if(NOT WIN32)
  target_link_libraries(cong_test PRIVATE pthread m)
endif()

add_test(NAME cong_core_test COMMAND cong_test)

# -------------------------------------------------------------- install
include(GNUInstallDirs)

install(TARGETS cong_nanomq
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/rules/auth.jsonl
    ${CMAKE_CURRENT_SOURCE_DIR}/rules/acl.jsonl
    DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/nanomq
)

install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/conf/nanomq.conf
    DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/nanomq
)

if(UNIX AND NOT APPLE)
  install(FILES
      ${CMAKE_CURRENT_SOURCE_DIR}/deploy/nanomq.service
      DESTINATION ${CMAKE_INSTALL_DATADIR}/cong-nanomq
  )
endif()

install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/README.md
    DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/cong-nanomq
)
