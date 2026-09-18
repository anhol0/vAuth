#include "verifier_conversation.hpp"

#include <stdexcept>

namespace vauth::uv {

VerifierConversationState advance_verifier_conversation(
    const VerifierConversationState&,
    VerifierMessageSender,
    const VerifierMessage&
) {
    throw std::logic_error(
        "verifier conversation state machine is not implemented"
    );
}

bool verifier_conversation_is_terminal(
    const VerifierConversationState&
) noexcept {
    return false;
}

}
