#pragma once

#include "verifier_protocol.hpp"

#include <cstdint>
#include <stdexcept>
#include <variant>

namespace vauth::uv {

enum class VerifierMessageSender : uint8_t {
    daemon = 1,
    pam_verifier = 2
};

struct VerifierAwaitingStart {
    bool operator==(const VerifierAwaitingStart&) const = default;
};

struct VerifierVerifying {
    bool operator==(const VerifierVerifying&) const = default;
};

struct VerifierAwaitingSecret {
    bool operator==(const VerifierAwaitingSecret&) const = default;
};

struct VerifierCompleted {
    VerificationResult result;

    bool operator==(const VerifierCompleted&) const = default;
};

struct VerifierCancelled {
    bool operator==(const VerifierCancelled&) const = default;
};

using VerifierConversationState = std::variant<
    VerifierAwaitingStart,
    VerifierVerifying,
    VerifierAwaitingSecret,
    VerifierCompleted,
    VerifierCancelled
>;

class VerifierConversationError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

[[nodiscard]] VerifierConversationState advance_verifier_conversation(
    const VerifierConversationState& current,
    VerifierMessageSender sender,
    const VerifierMessage& message
);

[[nodiscard]] bool verifier_conversation_is_terminal(
    const VerifierConversationState& state
) noexcept;

}
