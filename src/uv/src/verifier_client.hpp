#pragma once

#include "sensitive_bytes.hpp"
#include "verifier_protocol.hpp"

#include <chrono>
#include <filesystem>
#include <functional>
#include <stop_token>

namespace vauth::uv {

inline constexpr auto PAM_VERIFIER_SOCKET_PATH =
    "/run/vauth-pam-verifier.sock";

VerificationResult run_verifier_service(
    const std::filesystem::path& socket_path,
    StartVerification start,
    std::stop_token stop,
    std::chrono::steady_clock::duration timeout,
    const std::function<void(const VerificationStatus&)>& status_callback,
    const std::function<SensitiveBytes(const SecretRequired&)>& secret_callback,
    const std::function<bool()>& cancellation_requested = {}
);

}
