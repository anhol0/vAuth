include(GNUInstallDirs)

find_program(SYSTEMD_RUN_EXECUTABLE systemd-run REQUIRED)
set(VAUTHCTL_INSTALLED_PATH "${CMAKE_INSTALL_FULL_BINDIR}/vauthctl")
configure_file(
    src/managed_config.hpp.in
    "${PROJECT_BINARY_DIR}/generated/managed_config.hpp"
    @ONLY
)

add_library(vauthctl_options
    src/options.cpp
)

target_include_directories(vauthctl_options PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(vauthctl_options PUBLIC
    CLI11::CLI11
)

add_library(vauthctl_commands
    src/commands.cpp
)

target_include_directories(vauthctl_commands PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(vauthctl_commands PUBLIC
    vauth_log
    vauth_storage
    SDBusCpp::sdbus-c++
)

add_library(vauthctl_application
    src/application.cpp
)

target_include_directories(vauthctl_application PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(vauthctl_application PUBLIC
    vauthctl_options
)

add_library(vauthctl_managed_execution
    src/managed_execution.cpp
)

target_include_directories(vauthctl_managed_execution PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(vauthctl_managed_execution PUBLIC
    vauthctl_options
)

add_executable(vauthctl
    src/main.cpp
)

target_link_libraries(vauthctl PRIVATE
    vauthctl_application
    vauthctl_commands
    vauthctl_managed_execution
)

target_include_directories(vauthctl PRIVATE
    "${PROJECT_BINARY_DIR}/generated"
)

install(
    TARGETS vauthctl
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
)

if(BUILD_TESTING)
    add_executable(vauthctl_options_tests
        tests/options_test.cpp
    )

    target_include_directories(vauthctl_options_tests PRIVATE
        ${PROJECT_SOURCE_DIR}/tests
    )

    target_link_libraries(vauthctl_options_tests PRIVATE
        vauthctl_options
    )

    add_test(
        NAME vauthctl_options
        COMMAND vauthctl_options_tests
    )

    add_executable(vauthctl_commands_tests
        tests/commands_test.cpp
    )

    target_include_directories(vauthctl_commands_tests PRIVATE
        ${PROJECT_SOURCE_DIR}/tests
    )

    target_link_libraries(vauthctl_commands_tests PRIVATE
        vauthctl_commands
    )

    add_test(
        NAME vauthctl_commands
        COMMAND vauthctl_commands_tests
    )

    add_executable(vauthctl_application_tests
        tests/application_test.cpp
    )

    target_include_directories(vauthctl_application_tests PRIVATE
        ${PROJECT_SOURCE_DIR}/tests
    )

    target_link_libraries(vauthctl_application_tests PRIVATE
        vauthctl_application
    )

    add_test(
        NAME vauthctl_application
        COMMAND vauthctl_application_tests
    )

    add_executable(vauthctl_managed_execution_tests
        tests/managed_execution_test.cpp
    )

    target_include_directories(vauthctl_managed_execution_tests PRIVATE
        ${PROJECT_SOURCE_DIR}/tests
    )

    target_link_libraries(vauthctl_managed_execution_tests PRIVATE
        vauthctl_managed_execution
    )

    add_test(
        NAME vauthctl_managed_execution
        COMMAND vauthctl_managed_execution_tests
    )

    add_test(
        NAME vauthctl_cli
        COMMAND bash
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/cli_test.sh
            $<TARGET_FILE:vauthctl>
    )

    find_program(DBUS_DAEMON_EXECUTABLE dbus-daemon)
    if(DBUS_DAEMON_EXECUTABLE)
        add_executable(vauthctl_status_dbus_tests
            tests/status_dbus_test.cpp
        )

        target_include_directories(vauthctl_status_dbus_tests PRIVATE
            ${PROJECT_SOURCE_DIR}/tests
        )

        target_link_libraries(vauthctl_status_dbus_tests PRIVATE
            vauthctl_commands
        )

        add_test(
            NAME vauthctl_status_dbus
            COMMAND bash
                ${PROJECT_SOURCE_DIR}/tests/private_dbus_test.sh
                $<TARGET_FILE:vauthctl_status_dbus_tests>
                ${DBUS_DAEMON_EXECUTABLE}
        )
    endif()
endif()
