add_executable(frame_processor_tests
    frame_processor_test.cpp
)

target_link_libraries(frame_processor_tests PRIVATE
    ctaphid_frame_processor
    ctaphid_packet
)

add_test(
    NAME frame_processor
    COMMAND frame_processor_tests
)

add_executable(request_parsing_tests
    request_parsing_test.cpp
    ${PROJECT_SOURCE_DIR}/src/cbor_operations/cbor_utils.cpp
    ${PROJECT_SOURCE_DIR}/src/registration/registration.cpp
    ${PROJECT_SOURCE_DIR}/src/cbor_operations/make_cred_parsing.cpp
    ${PROJECT_SOURCE_DIR}/src/authentication/authenticate.cpp
    ${PROJECT_SOURCE_DIR}/src/cbor_operations/get_assertion_parsing.cpp
)

target_include_directories(request_parsing_tests PRIVATE
    ${PROJECT_SOURCE_DIR}/src
    ${TINYCBOR_INCLUDE_DIRS}
)

target_link_libraries(request_parsing_tests PRIVATE
    ${TINYCBOR_LIBRARIES}
)

add_test(
    NAME request_parsing
    COMMAND request_parsing_tests
)

add_executable(cbor_response_tests
    cbor_response_test.cpp
    ${PROJECT_SOURCE_DIR}/src/cbor_operations/cbor.cpp
    ${PROJECT_SOURCE_DIR}/src/cbor_operations/cbor_utils.cpp
)

target_include_directories(cbor_response_tests PRIVATE
    ${PROJECT_SOURCE_DIR}/src
    ${TINYCBOR_INCLUDE_DIRS}
)

target_link_libraries(cbor_response_tests PRIVATE
    ${TINYCBOR_LIBRARIES}
)

add_test(
    NAME cbor_response
    COMMAND cbor_response_tests
)

add_executable(uv_process_tests
    uv_process_test.cpp
)

target_include_directories(uv_process_tests PRIVATE
    ${PROJECT_SOURCE_DIR}/src
)

target_link_libraries(uv_process_tests PRIVATE
    uv_process
)

add_test(
    NAME uv_process
    COMMAND uv_process_tests
)

add_executable(uv_verifier_protocol_tests
    uv_verifier_protocol_test.cpp
)

target_include_directories(uv_verifier_protocol_tests PRIVATE
    ${PROJECT_SOURCE_DIR}/src
)

target_link_libraries(uv_verifier_protocol_tests PRIVATE
    uv_verifier_protocol
)

add_test(
    NAME uv_verifier_protocol
    COMMAND uv_verifier_protocol_tests
)

add_executable(uv_verifier_conversation_tests
    uv_verifier_conversation_test.cpp
)

target_include_directories(uv_verifier_conversation_tests PRIVATE
    ${PROJECT_SOURCE_DIR}/src
)

target_link_libraries(uv_verifier_conversation_tests PRIVATE
    uv_verifier_protocol
)

add_test(
    NAME uv_verifier_conversation
    COMMAND uv_verifier_conversation_tests
)

add_executable(uv_verifier_socket_tests
    uv_verifier_socket_test.cpp
)

target_include_directories(uv_verifier_socket_tests PRIVATE
    ${PROJECT_SOURCE_DIR}/src
)

target_link_libraries(uv_verifier_socket_tests PRIVATE
    uv_verifier_protocol
)

add_test(
    NAME uv_verifier_socket
    COMMAND uv_verifier_socket_tests
)

add_executable(uv_verifier_client_tests
    uv_verifier_client_test.cpp
)

target_include_directories(uv_verifier_client_tests PRIVATE
    ${PROJECT_SOURCE_DIR}/src
)

target_link_libraries(uv_verifier_client_tests PRIVATE
    uv_verifier_client
)

add_test(
    NAME uv_verifier_client
    COMMAND uv_verifier_client_tests
)

add_executable(uv_user_interaction_tests
    uv_user_interaction_test.cpp
)

target_include_directories(uv_user_interaction_tests PRIVATE
    ${PROJECT_SOURCE_DIR}/src
)

target_link_libraries(uv_user_interaction_tests PRIVATE
    uv
)

add_test(
    NAME uv_user_interaction
    COMMAND uv_user_interaction_tests
)

add_executable(uv_auth_handler_tests
    uv_auth_handler_test.cpp
)

target_include_directories(uv_auth_handler_tests PRIVATE
    ${PROJECT_SOURCE_DIR}/src
)

target_link_libraries(uv_auth_handler_tests PRIVATE
    uv
)

add_test(
    NAME uv_auth_handler
    COMMAND uv_auth_handler_tests
)

add_executable(uv_verifier_authorization_tests
    uv_verifier_authorization_test.cpp
)

target_include_directories(uv_verifier_authorization_tests PRIVATE
    ${PROJECT_SOURCE_DIR}/src
)

target_link_libraries(uv_verifier_authorization_tests PRIVATE
    uv
)

add_test(
    NAME uv_verifier_authorization
    COMMAND uv_verifier_authorization_tests
)

add_executable(uv_pam_verifier_broker_tests
    uv_pam_verifier_broker_test.cpp
)

target_include_directories(uv_pam_verifier_broker_tests PRIVATE
    ${PROJECT_SOURCE_DIR}/src
)

target_link_libraries(uv_pam_verifier_broker_tests PRIVATE
    uv
)

add_test(
    NAME uv_pam_verifier_broker
    COMMAND uv_pam_verifier_broker_tests
)

pkg_check_modules(TEST_PAM REQUIRED IMPORTED_TARGET pam)

add_library(vauth_test_pam_module MODULE
    uv_test_pam_module.cpp
)

target_link_libraries(vauth_test_pam_module PRIVATE
    PkgConfig::TEST_PAM
)

add_executable(uv_pam_conversation_integration_tests
    uv_pam_conversation_integration_test.cpp
)

target_include_directories(uv_pam_conversation_integration_tests PRIVATE
    ${PROJECT_SOURCE_DIR}/src
)

target_link_libraries(uv_pam_conversation_integration_tests PRIVATE
    uv
)

add_test(
    NAME uv_pam_conversation_integration
    COMMAND uv_pam_conversation_integration_tests
        $<TARGET_FILE:vauth_test_pam_module>
)

add_executable(dbus_agent_registry_tests
    dbus_agent_registry_test.cpp
    ${PROJECT_SOURCE_DIR}/src/dbus/agent_registry.cpp
    ${PROJECT_SOURCE_DIR}/src/dbus/interaction_registry.cpp
    ${PROJECT_SOURCE_DIR}/src/dbus/secret_pipe.cpp
)

target_include_directories(dbus_agent_registry_tests PRIVATE
    ${PROJECT_SOURCE_DIR}/src
)

add_test(
    NAME dbus_agent_registry
    COMMAND dbus_agent_registry_tests
)

add_executable(crypto_tests
    crypto_test.cpp
)

target_include_directories(crypto_tests PRIVATE
    ${PROJECT_SOURCE_DIR}/src
    ${OPENSSL_INCLUDE_DIRS}
)

target_link_libraries(crypto_tests PRIVATE
    ${OPENSSL_LIBRARIES}
    vauth_storage
)

add_test(
    NAME crypto
    COMMAND crypto_tests
)

add_executable(authorization_tests
    authorization_test.cpp
)

target_link_libraries(authorization_tests PRIVATE
    vauth_storage
)

add_test(
    NAME authorization
    COMMAND authorization_tests
)

add_test(
    NAME daemon_cli
    COMMAND bash
        ${CMAKE_CURRENT_SOURCE_DIR}/daemon_cli_test.sh
        $<TARGET_FILE:vauthd>
)

add_test(
    NAME install_layout
    COMMAND bash
        ${CMAKE_CURRENT_SOURCE_DIR}/install_layout_test.sh
        ${CMAKE_COMMAND}
        ${CMAKE_BINARY_DIR}
        $<CONFIG>
        ${CMAKE_INSTALL_PREFIX}
        ${CMAKE_INSTALL_BINDIR}
        ${CMAKE_INSTALL_LIBEXECDIR}
        ${VAUTH_SYSTEMD_SYSTEM_UNIT_DIR}
        ${VAUTH_SYSUSERS_DIR}
        ${VAUTH_UDEV_RULES_DIR}
        ${VAUTH_DBUS_SYSTEM_POLICY_DIR}
        ${VAUTH_PAM_CONFIG_DIR}
        ${VAUTH_BUILD_UI}
        ${CMAKE_INSTALL_FULL_LIBEXECDIR}
)

find_program(SYSTEMD_ANALYZE_EXECUTABLE systemd-analyze)
if(SYSTEMD_ANALYZE_EXECUTABLE)
    add_test(
        NAME systemd_units
        COMMAND bash
            ${CMAKE_CURRENT_SOURCE_DIR}/systemd_units_test.sh
            ${SYSTEMD_ANALYZE_EXECUTABLE}
            ${CMAKE_BINARY_DIR}/generated/vauth.service
            ${CMAKE_BINARY_DIR}/generated/vauth-pam-verifier@.service
            ${PROJECT_SOURCE_DIR}/config/vauth-pam-verifier.socket
    )
endif()

find_program(SYSTEMD_SYSUSERS_EXECUTABLE systemd-sysusers)
if(SYSTEMD_SYSUSERS_EXECUTABLE)
    add_test(
        NAME sysusers_config
        COMMAND bash
            ${CMAKE_CURRENT_SOURCE_DIR}/sysusers_test.sh
            ${SYSTEMD_SYSUSERS_EXECUTABLE}
            ${PROJECT_SOURCE_DIR}/config/vauth.sysusers
    )
endif()

find_program(UDEVADM_EXECUTABLE udevadm)
if(UDEVADM_EXECUTABLE)
    add_test(
        NAME udev_rules
        COMMAND ${UDEVADM_EXECUTABLE}
            verify
            ${PROJECT_SOURCE_DIR}/config/70-vauth.rules
    )
endif()

add_executable(log_tests
    log_test.cpp
)

target_link_libraries(log_tests PRIVATE
    vauth_log
)

add_test(
    NAME log
    COMMAND log_tests
)

add_executable(store_security_integration_tests
    store_security_integration_test.cpp
    ${PROJECT_SOURCE_DIR}/src/cryptography/tpm.cpp
)

target_include_directories(store_security_integration_tests PRIVATE
    ${PROJECT_SOURCE_DIR}/src
    ${OPENSSL_INCLUDE_DIRS}
    ${TSS2_ESYS_INCLUDE_DIRS}
    ${TSS2_FAPI_INCLUDE_DIRS}
    ${TSS2_MU_INCLUDE_DIRS}
    ${TSS2_RC_INCLUDE_DIRS}
)

target_link_libraries(store_security_integration_tests PRIVATE
    ${TSS2_ESYS_LIBRARIES}
    ${TSS2_MU_LIBRARIES}
    vauthctl_commands
    vauth_storage
)

find_program(SWTPM_EXECUTABLE swtpm)
find_program(SWTPM_IOCTL_EXECUTABLE swtpm_ioctl)
find_program(TPM2_STARTUP_EXECUTABLE tpm2_startup)
find_program(TPM2_CLEAR_EXECUTABLE tpm2_clear)
find_program(TPM2_FLUSHCONTEXT_EXECUTABLE tpm2_flushcontext)
find_program(TPM2_NVDEFINE_EXECUTABLE tpm2_nvdefine)
find_program(TPM2_NVINCREMENT_EXECUTABLE tpm2_nvincrement)
find_program(TPM2_NVUNDEFINE_EXECUTABLE tpm2_nvundefine)
find_program(TSS2_PROVISION_EXECUTABLE tss2_provision)

if(
    SWTPM_EXECUTABLE AND
    SWTPM_IOCTL_EXECUTABLE AND
    TPM2_STARTUP_EXECUTABLE AND
    TPM2_CLEAR_EXECUTABLE AND
    TPM2_FLUSHCONTEXT_EXECUTABLE AND
    TPM2_NVDEFINE_EXECUTABLE AND
    TPM2_NVINCREMENT_EXECUTABLE AND
    TPM2_NVUNDEFINE_EXECUTABLE AND
    TSS2_PROVISION_EXECUTABLE
)
    add_test(
        NAME store_security_swtpm
        COMMAND bash
            ${CMAKE_CURRENT_SOURCE_DIR}/swtpm_integration_test.sh
            $<TARGET_FILE:store_security_integration_tests>
            /etc/tpm2-tss/fapi-profiles/
    )
endif()
