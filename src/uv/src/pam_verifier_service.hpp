#pragma once

#include <chrono>
#include <string>
#include <string_view>

namespace vauth::uv {

inline constexpr std::string_view PAM_VERIFIER_COMMAND = "pam-verifier";

int run_pam_verifier_service(
    int socket_fd,
    const std::string& pam_service,
    const std::string& pam_configuration_directory,
    std::chrono::steady_clock::duration timeout
);

}
