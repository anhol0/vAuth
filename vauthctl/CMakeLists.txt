add_library(vauthctl_options
    src/options.cpp
)

target_include_directories(vauthctl_options PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(vauthctl_options PUBLIC
    CLI11::CLI11
)

add_executable(vauthctl
    src/commands.cpp
    src/main.cpp
)

target_link_libraries(vauthctl PRIVATE
    vauth_log
    vauthctl_options
    vauth_storage
    SDBusCpp::sdbus-c++
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
endif()
