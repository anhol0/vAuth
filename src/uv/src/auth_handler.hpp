#pragma once

#include "verifier_protocol.hpp"

#include <string_view>

inline constexpr std::string_view VAUTH_AUTH_HANDLER_COMMAND =
    "vauth_auth_handler";

namespace vauth::uv {

[[nodiscard]] VerificationResult verification_result_from_pam_status(
    int pam_status
) noexcept;

} // namespace vauth::uv

int run_vauth_auth_handler(int argc, char** argv) noexcept;
