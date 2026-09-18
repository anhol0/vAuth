#include "verifier_conversation.hpp"

namespace vauth::uv {
namespace {

[[noreturn]] void invalid_transition() {
    throw VerifierConversationError(
        "invalid verifier conversation transition"
    );
}

bool is_valid(VerificationStatusKind kind) noexcept {
    switch(kind) {
        case VerificationStatusKind::information:
        case VerificationStatusKind::error:
            return true;
    }
    return false;
}

bool is_valid(VerificationResult result) noexcept {
    switch(result) {
        case VerificationResult::success:
        case VerificationResult::denied:
        case VerificationResult::error:
            return true;
    }
    return false;
}

void validate_message_enums(const VerifierMessage& message) {
    if(const auto* status = std::get_if<VerificationStatus>(&message)) {
        if(!is_valid(status->kind))
            invalid_transition();
    }
    if(const auto* complete = std::get_if<VerificationComplete>(&message)) {
        if(!is_valid(complete->result))
            invalid_transition();
    }
}

}

VerifierConversationState advance_verifier_conversation(
    const VerifierConversationState& current,
    VerifierMessageSender sender,
    const VerifierMessage& message
) {
    validate_message_enums(message);

    if(std::holds_alternative<VerifierAwaitingStart>(current)) {
        if(
            sender == VerifierMessageSender::daemon &&
            std::holds_alternative<StartVerification>(message)
        ) {
            return VerifierVerifying{};
        }
        invalid_transition();
    }

    if(std::holds_alternative<VerifierVerifying>(current)) {
        if(sender == VerifierMessageSender::daemon) {
            if(std::holds_alternative<CancelVerification>(message))
                return VerifierCancelled{};
            invalid_transition();
        }
        if(sender == VerifierMessageSender::pam_verifier) {
            if(std::holds_alternative<VerificationStatus>(message))
                return VerifierVerifying{};
            if(std::holds_alternative<SecretRequired>(message))
                return VerifierAwaitingSecret{};
            if(const auto* complete =
                std::get_if<VerificationComplete>(&message)
            ) {
                return VerifierCompleted{complete->result};
            }
        }
        invalid_transition();
    }

    if(std::holds_alternative<VerifierAwaitingSecret>(current)) {
        if(sender == VerifierMessageSender::daemon) {
            if(std::holds_alternative<SecretResponse>(message))
                return VerifierVerifying{};
            if(std::holds_alternative<CancelVerification>(message))
                return VerifierCancelled{};
            invalid_transition();
        }
        if(sender == VerifierMessageSender::pam_verifier) {
            const auto* complete = std::get_if<VerificationComplete>(&message);
            if(
                complete != nullptr &&
                complete->result == VerificationResult::error
            ) {
                return VerifierCompleted{complete->result};
            }
        }
        invalid_transition();
    }

    invalid_transition();
}

bool verifier_conversation_is_terminal(
    const VerifierConversationState& state
) noexcept {
    return
        std::holds_alternative<VerifierCompleted>(state) ||
        std::holds_alternative<VerifierCancelled>(state);
}

}
