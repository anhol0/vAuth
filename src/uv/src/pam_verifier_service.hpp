#pragma once

#include "session_validation.hpp"
#include "verifier_protocol.hpp"
#include "verifier_socket.hpp"

#include <chrono>
#include <functional>
#include <string>
#include <string_view>
#include <sys/types.h>

namespace vauth::uv {

inline constexpr std::string_view PAM_VERIFIER_COMMAND = "pam-verifier";
inline constexpr std::string_view VAUTH_DAEMON_ACCOUNT = "vauth";

void authorize_verifier_peer(
    const VerifierPeerCredentials& peer,
    uid_t expected_daemon_uid
);

void authorize_verification_session(
    const StartVerification& request,
    const vauth::LoginSessionProperties& session
);

using LoginSessionQuery = std::function<vauth::LoginSessionProperties(
    const std::string& session_id
)>;

// Runs one daemon connection and authenticates its peer. Production supplies
// the fixed daemon UID, logind query, and current executable; explicit
// dependencies keep the broker lifecycle testable without root or a login
// session.
int run_pam_verifier_connection(
    VerifierSocket connection,
    uid_t expected_daemon_uid,
    const std::string& verifier_program,
    const std::string& pam_service,
    const std::string& pam_configuration_directory,
    std::chrono::steady_clock::duration timeout,
    const LoginSessionQuery& query_session
);

int run_pam_verifier_service(
    int socket_fd,
    const std::string& pam_service,
    const std::string& pam_configuration_directory,
    std::chrono::steady_clock::duration timeout
);

}
