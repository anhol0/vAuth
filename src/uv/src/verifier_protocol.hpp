#pragma once

#include "auth_handler_status.hpp"
#include "sensitive_bytes.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <variant>
#include <vector>

namespace vauth::uv {

inline constexpr uint8_t VERIFIER_PROTOCOL_VERSION = 1;
inline constexpr std::size_t VERIFIER_PROTOCOL_HEADER_SIZE = 8;
inline constexpr std::size_t MAX_SESSION_ID_SIZE = 255;
inline constexpr std::size_t MAX_VERIFIER_PACKET_SIZE =
    VERIFIER_PROTOCOL_HEADER_SIZE + MAX_PASSWORD_SIZE;

// The verifier protocol is carried by one SOCK_SEQPACKET connection. Each
// encoded message occupies exactly one packet, including the fixed header.
struct StartVerification {
    uint32_t targetUid;
    std::string sessionId;

    bool operator==(const StartVerification&) const = default;
};

struct PasswordResponse {
    SensitiveBytes password;
};

struct CancelVerification {
    bool operator==(const CancelVerification&) const = default;
};

struct VerificationStatus {
    AuthHandlerStatus status;

    bool operator==(const VerificationStatus&) const = default;
};

enum class VerificationResult : uint8_t {
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
    PasswordResponse,
    CancelVerification,
    VerificationStatus,
    VerificationComplete
>;

class VerifierProtocolError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

[[nodiscard]] std::vector<uint8_t> encode_verifier_message(
    const VerifierMessage& message
);

[[nodiscard]] VerifierMessage decode_verifier_message(
    std::span<const uint8_t> packet
);

}
