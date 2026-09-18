#pragma once

#include "sensitive_bytes.hpp"
#include "verifier_protocol.hpp"

#include <chrono>
#include <cstdint>
#include <functional>
#include <stop_token>
#include <string>
#include <sys/types.h>
#include <vector>

namespace vauth::uv {

// Arrange for this process to receive the PAM cancellation signal if the
// expected parent exits. The identity check closes the fork/exec-to-prctl race.
void arm_parent_death_signal(pid_t expected_parent);

// Runs a program in its own process group. Cancellation or timeout terminates
// and reaps the whole group before the corresponding exception is thrown.
int run_cancellable_program(
    const std::string& path,
    const std::vector<std::string>& arguments,
    std::stop_token stop,
    std::chrono::steady_clock::duration timeout,
    const std::function<bool()>& cancellation_requested = {}
);

// Runs the current PAM verifier child over one authenticated-by-inheritance
// SOCK_SEQPACKET connection. The child must complete the verifier protocol
// before a normal exit is accepted.
VerificationResult run_cancellable_verifier_program(
    const std::string& path,
    const std::vector<std::string>& arguments,
    StartVerification start,
    std::stop_token stop,
    std::chrono::steady_clock::duration timeout,
    const std::function<void(const VerificationStatus&)>& status_callback,
    const std::function<SensitiveBytes(const SecretRequired&)>& secret_callback,
    const std::function<bool()>& cancellation_requested = {}
);

}
