#pragma once

#include "sensitive_bytes.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <variant>

namespace vauth::uv {

inline constexpr uint8_t VERIFIER_PROTOCOL_VERSION = 1;
inline constexpr std::size_t VERIFIER_PROTOCOL_HEADER_SIZE = 2;
// All sizes are byte counts and exclude the fixed packet header. Display text
// is UTF-8. Empty display text requests a generic UI fallback.
inline constexpr std::size_t MAX_SESSION_ID_SIZE = 255;
inline constexpr std::size_t MAX_VERIFICATION_TEXT_SIZE = 512;
inline constexpr std::size_t MAX_VERIFICATION_SECRET_SIZE =
    MAX_SECRET_SIZE;
inline constexpr std::size_t MAX_VERIFIER_PACKET_SIZE =
    VERIFIER_PROTOCOL_HEADER_SIZE + std::max({
        sizeof(uint32_t) + MAX_SESSION_ID_SIZE,
        MAX_VERIFICATION_SECRET_SIZE,
        sizeof(uint8_t) + MAX_VERIFICATION_TEXT_SIZE,
        MAX_VERIFICATION_TEXT_SIZE
    });

// The verifier protocol is carried by one SOCK_SEQPACKET connection. Each
// encoded message occupies exactly one packet, including the fixed header.
struct StartVerification {
    uint32_t targetUid;
    std::string sessionId;

    bool operator==(const StartVerification&) const = default;
};

struct SecretResponse {
    // An opaque PAM response. It may be empty but must not contain a NUL.
    SensitiveBytes secret;
};

struct CancelVerification {
    bool operator==(const CancelVerification&) const = default;
};

enum class VerificationStatusKind : uint8_t {
    // PAM_TEXT_INFO and PAM_ERROR_MSG presentation categories. Neither value
    // is a terminal authentication result.
    information = 1,
    error = 2
};

struct VerificationStatus {
    VerificationStatusKind kind;
    std::string message;

    bool operator==(const VerificationStatus&) const = default;
};

struct SecretRequired {
    // A PAM_PROMPT_ECHO_OFF prompt. PAM may request another secret after a
    // response; each request and response is a separate one-shot exchange.
    std::string prompt;

    bool operator==(const SecretRequired&) const = default;
};

enum class VerificationResult : uint8_t {
    // "denied" is an authoritative negative authentication result. "error"
    // means verification could not produce an authentication decision.
    success = 1,
    denied = 2,
    error = 3
};

struct VerificationComplete {
    VerificationResult result;

    bool operator==(const VerificationComplete&) const = default;
};

using VerifierMessage = std::variant<
    StartVerification,
    SecretResponse,
    CancelVerification,
    VerificationStatus,
    SecretRequired,
    VerificationComplete
>;

class VerifierProtocolError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

[[nodiscard]] SensitiveBytes encode_verifier_message(
    const VerifierMessage& message
);

[[nodiscard]] VerifierMessage decode_verifier_message(
    std::span<const uint8_t> packet
);

}
