set(PN vauth)

cmake_minimum_required(VERSION 3.20)
project(${PN} CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(SOURCE_DIR src)
set(DAEMON_TARGET vauthd)

include(CTest)
include(GNUInstallDirs)

set(
    VAUTH_SYSTEMD_SYSTEM_UNIT_DIR
    "lib/systemd/system"
    CACHE PATH
    "Directory for systemd system units"
)
set(
    VAUTH_SYSUSERS_DIR
    "lib/sysusers.d"
    CACHE PATH
    "Directory for systemd-sysusers declarations"
)
set(
    VAUTH_UDEV_RULES_DIR
    "lib/udev/rules.d"
    CACHE PATH
    "Directory for udev rules"
)
set(
    VAUTH_MODULES_LOAD_DIR
    "lib/modules-load.d"
    CACHE PATH
    "Directory for systemd-modules-load declarations"
)
set(
    VAUTH_DBUS_SYSTEM_POLICY_DIR
    "/usr/share/dbus-1/system.d"
    CACHE PATH
    "Directory for system-bus policy files"
)
set(
    VAUTH_PAM_CONFIG_DIR
    "/etc/vauth/config"
    CACHE PATH
    "Absolute directory for the isolated vAuth PAM configuration"
)
set(
    VAUTH_FAPI_SYSTEM_DIR
    "/var/lib/tpm2-tss/system/keystore"
    CACHE PATH
    "Absolute FAPI system directory writable by the vAuth daemon"
)

if(NOT IS_ABSOLUTE "${VAUTH_PAM_CONFIG_DIR}")
    message(FATAL_ERROR "VAUTH_PAM_CONFIG_DIR must be an absolute path")
endif()
if(NOT IS_ABSOLUTE "${VAUTH_FAPI_SYSTEM_DIR}")
    message(FATAL_ERROR "VAUTH_FAPI_SYSTEM_DIR must be an absolute path")
endif()

file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/generated")
configure_file(
    config/vauth.service.in
    "${CMAKE_CURRENT_BINARY_DIR}/generated/vauth.service"
    @ONLY
)
configure_file(
    config/vauth-pam-verifier@.service.in
    "${CMAKE_CURRENT_BINARY_DIR}/generated/vauth-pam-verifier@.service"
    @ONLY
)

add_subdirectory(${SOURCE_DIR}/uv)

find_package(PkgConfig REQUIRED)
find_package(sdbus-c++ CONFIG REQUIRED)
find_package(CLI11 CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
pkg_check_modules(SYSTEMD REQUIRED IMPORTED_TARGET libsystemd)
pkg_check_modules(TINYCBOR REQUIRED tinycbor)
pkg_check_modules(OPENSSL REQUIRED openssl)
pkg_check_modules(TSS2_ESYS REQUIRED tss2-esys)
pkg_check_modules(TSS2_FAPI REQUIRED tss2-fapi)
pkg_check_modules(TSS2_RC REQUIRED tss2-rc)
pkg_check_modules(TSS2_MU REQUIRED tss2-mu)

add_library(vauth_session
    ${SOURCE_DIR}/session_validation.cpp
)
target_include_directories(vauth_session PUBLIC ${SOURCE_DIR})
target_link_libraries(vauth_session PUBLIC PkgConfig::SYSTEMD)
target_link_libraries(uv PUBLIC vauth_session)

# Logging library
add_library(vauth_log
    ${SOURCE_DIR}/log.cpp
)
target_include_directories(vauth_log PUBLIC ${SOURCE_DIR})

# D-Bus library
add_library(vauth_dbus
    ${SOURCE_DIR}/dbus/agent_registry.cpp
    ${SOURCE_DIR}/dbus/agent_service.cpp
    ${SOURCE_DIR}/dbus/interaction_registry.cpp
    ${SOURCE_DIR}/dbus/peer_credentials.cpp
    ${SOURCE_DIR}/dbus/secret_pipe.cpp
)
target_include_directories(vauth_dbus PUBLIC ${SOURCE_DIR})
target_compile_definitions(vauth_dbus PRIVATE
    $<$<CONFIG:Debug>:DEBUG>
)
target_link_libraries(vauth_dbus PUBLIC
    SDBusCpp::sdbus-c++
    PkgConfig::SYSTEMD
    vauth_session
)
target_link_libraries(vauth_dbus PRIVATE vauth_log)

# Frame processing library
add_library(ctaphid_frame_processor
    ${SOURCE_DIR}/frame_processor.cpp
)
target_include_directories(ctaphid_frame_processor PUBLIC ${SOURCE_DIR})

# Packet library
add_library(ctaphid_packet
    ${SOURCE_DIR}/packet.cpp
)
target_include_directories(ctaphid_packet PUBLIC ${SOURCE_DIR})

# vAuth crypto library
add_library(vauth_crypto
  ${SOURCE_DIR}/cryptography/crypto.cpp
)
target_include_directories(vauth_crypto PUBLIC
  ${SOURCE_DIR}
  ${OPENSSL_INCLUDE_DIRS}
)
target_link_libraries(vauth_crypto PUBLIC
  ${OPENSSL_LIBRARIES}
)

# vAuth credential library
add_library(vauth_storage
    ${SOURCE_DIR}/encoding/hex.cpp
    ${SOURCE_DIR}/storage/authorization.cpp
    ${SOURCE_DIR}/credentials/credential.cpp
    ${SOURCE_DIR}/cryptography/store_security.cpp
)

target_include_directories(vauth_storage PUBLIC
    ${SOURCE_DIR}
    ${TSS2_FAPI_INCLUDE_DIRS}
    ${TSS2_RC_INCLUDE_DIRS}
)

target_link_libraries(vauth_storage PUBLIC
    nlohmann_json::nlohmann_json
    ${TSS2_FAPI_LIBRARIES}
    ${TSS2_RC_LIBRARIES}
    vauth_crypto
)

# vAuth main daemon
add_executable(${DAEMON_TARGET}
    # Uncategorized
    ${SOURCE_DIR}/${PN}.cpp
    ${SOURCE_DIR}/ctap_command_handler.cpp
    ${SOURCE_DIR}/event.cpp
    ${SOURCE_DIR}/response.cpp
    ${SOURCE_DIR}/device.cpp
    # Registration
    ${SOURCE_DIR}/registration/registration.cpp
    ${SOURCE_DIR}/registration/make_credential_response.cpp
    # Cryptography operations
    ${SOURCE_DIR}/cryptography/tpm.cpp
    # Authentication
    ${SOURCE_DIR}/authentication/authenticate.cpp
    ${SOURCE_DIR}/authentication/get_assertion_response.cpp
    # CBOR Operations
    ${SOURCE_DIR}/cbor_operations/cbor.cpp
    ${SOURCE_DIR}/cbor_operations/cbor_utils.cpp
    ${SOURCE_DIR}/cbor_operations/make_cred_parsing.cpp
    ${SOURCE_DIR}/cbor_operations/get_assertion_parsing.cpp
)

target_compile_definitions(${DAEMON_TARGET} PRIVATE
    $<$<CONFIG:Debug>:DEBUG>
    VAUTH_INSTALLED_PAM_CONFIG_DIR="${VAUTH_PAM_CONFIG_DIR}"
)

target_include_directories(${DAEMON_TARGET} PRIVATE ${SOURCE_DIR})
target_include_directories(${DAEMON_TARGET} PRIVATE
    ${TINYCBOR_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIRS}
    ${TSS2_ESYS_INCLUDE_DIRS}
    ${TSS2_FAPI_INCLUDE_DIRS}
    ${TSS2_RC_INCLUDE_DIRS}
    ${TSS2_MU_INCLUDE_DIRS}
)
target_link_libraries(${DAEMON_TARGET} PRIVATE
    ${TINYCBOR_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${TSS2_ESYS_LIBRARIES}
    ${TSS2_FAPI_LIBRARIES}
    ${TSS2_RC_LIBRARIES}
    ${TSS2_MU_LIBRARIES}
    vauth_storage
    ctaphid_frame_processor
    ctaphid_packet
    vauth_log
    vauth_dbus
    uv
)

install(
    TARGETS ${DAEMON_TARGET}
    RUNTIME DESTINATION "${CMAKE_INSTALL_LIBEXECDIR}/vauth"
)

install(
    FILES
        "${CMAKE_CURRENT_BINARY_DIR}/generated/vauth.service"
        "${CMAKE_CURRENT_BINARY_DIR}/generated/vauth-pam-verifier@.service"
        config/vauth-pam-verifier.socket
    DESTINATION "${VAUTH_SYSTEMD_SYSTEM_UNIT_DIR}"
)
install(
    FILES config/vauth.sysusers
    DESTINATION "${VAUTH_SYSUSERS_DIR}"
    RENAME vauth.conf
)
install(
    FILES config/70-vauth.rules
    DESTINATION "${VAUTH_UDEV_RULES_DIR}"
)
install(
    FILES config/vauth.modules-load.conf
    DESTINATION "${VAUTH_MODULES_LOAD_DIR}"
    RENAME vauth.conf
)
install(
    FILES config/org.lamellix.vAuth.conf
    DESTINATION "${VAUTH_DBUS_SYSTEM_POLICY_DIR}"
)
install(
    FILES config/vauth
    DESTINATION "${VAUTH_PAM_CONFIG_DIR}"
)
install(
    FILES
        LICENSE
        THIRD_PARTY_NOTICES.md
    DESTINATION "${CMAKE_INSTALL_DOCDIR}"
)

option(VAUTH_BUILD_UI "Build the Slint vAuth user-interaction agent" ON)
option(
    VAUTH_BUILD_DEBUG_AGENT
    "Build the temporary console D-Bus user-interaction agent"
    ${BUILD_TESTING}
)
if(VAUTH_BUILD_UI OR VAUTH_BUILD_DEBUG_AGENT)
  add_subdirectory(client)
endif()

add_subdirectory(vauthctl)

if(BUILD_TESTING)
  add_subdirectory(tests)
endif()
