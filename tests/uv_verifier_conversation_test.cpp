#include "test_runner.hpp"
#include "uv/src/verifier_conversation.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <string>
#include <utility>
#include <variant>

namespace {

#define CHECK(condition) do { \
    if(!(condition)) { \
        std::cerr << "CHECK failed at " << __FILE__ << ':' << __LINE__ \
                  << ": " #condition "\n"; \
        return false; \
    } \
} while(false)

vauth::uv::VerifierMessage start_message() {
    return vauth::uv::StartVerification{
        .targetUid = 1000,
        .sessionId = "c2"
    };
}

vauth::uv::VerifierMessage status_message(
    vauth::uv::VerificationStatusKind kind,
    std::string message
) {
    return vauth::uv::VerificationStatus{
        .kind = kind,
        .message = std::move(message)
    };
}

vauth::uv::VerifierMessage secret_required_message() {
    return vauth::uv::SecretRequired{.prompt = "Password:"};
}

vauth::uv::VerifierMessage secret_response_message() {
    constexpr std::array<uint8_t, 6> value{
        's', 'e', 'c', 'r', 'e', 't'
    };
    vauth::uv::SensitiveBytes secret(value.size());
    std::copy(
        value.begin(),
        value.end(),
        secret.writable_bytes().begin()
    );
    return vauth::uv::SecretResponse{.secret = std::move(secret)};
}

vauth::uv::VerifierMessage complete_message(
    vauth::uv::VerificationResult result
) {
    return vauth::uv::VerificationComplete{.result = result};
}

vauth::uv::VerifierMessage cancel_message() {
    return vauth::uv::CancelVerification{};
}

template<typename State>
bool is_state(const vauth::uv::VerifierConversationState& state) {
    return std::holds_alternative<State>(state);
}

bool rejects(
    const vauth::uv::VerifierConversationState& state,
    vauth::uv::VerifierMessageSender sender,
    const vauth::uv::VerifierMessage& message
) {
    try {
        static_cast<void>(vauth::uv::advance_verifier_conversation(
            state,
            sender,
            message
        ));
    } catch(const vauth::uv::VerifierConversationError&) {
        return true;
    } catch(...) {
        return false;
    }
    return false;
}

bool test_verification_without_secret() {
    using namespace vauth::uv;
    VerifierConversationState state = VerifierAwaitingStart{};
    state = advance_verifier_conversation(
        state,
        VerifierMessageSender::daemon,
        start_message()
    );
    CHECK(is_state<VerifierVerifying>(state));

    state = advance_verifier_conversation(
        state,
        VerifierMessageSender::pam_verifier,
        status_message(
            VerificationStatusKind::information,
            "Touch the security device"
        )
    );
    CHECK(is_state<VerifierVerifying>(state));
    state = advance_verifier_conversation(
        state,
        VerifierMessageSender::pam_verifier,
        status_message(
            VerificationStatusKind::error,
            "Authentication failed; try again"
        )
    );
    CHECK(is_state<VerifierVerifying>(state));

    state = advance_verifier_conversation(
        state,
        VerifierMessageSender::pam_verifier,
        complete_message(VerificationResult::success)
    );
    CHECK(is_state<VerifierCompleted>(state));
    CHECK(
        std::get<VerifierCompleted>(state).result ==
        VerificationResult::success
    );
    CHECK(verifier_conversation_is_terminal(state));
    return true;
}

bool test_verification_with_secret() {
    using namespace vauth::uv;
    VerifierConversationState state = VerifierAwaitingStart{};
    state = advance_verifier_conversation(
        state,
        VerifierMessageSender::daemon,
        start_message()
    );
    state = advance_verifier_conversation(
        state,
        VerifierMessageSender::pam_verifier,
        secret_required_message()
    );
    CHECK(is_state<VerifierAwaitingSecret>(state));

    state = advance_verifier_conversation(
        state,
        VerifierMessageSender::daemon,
        secret_response_message()
    );
    CHECK(is_state<VerifierVerifying>(state));
    state = advance_verifier_conversation(
        state,
        VerifierMessageSender::pam_verifier,
        status_message(
            VerificationStatusKind::information,
            "Checking the response"
        )
    );
    CHECK(is_state<VerifierVerifying>(state));

    state = advance_verifier_conversation(
        state,
        VerifierMessageSender::pam_verifier,
        complete_message(VerificationResult::denied)
    );
    CHECK(is_state<VerifierCompleted>(state));
    CHECK(
        std::get<VerifierCompleted>(state).result ==
        VerificationResult::denied
    );
    return true;
}

bool test_completion_from_each_active_state() {
    using namespace vauth::uv;
    for(const auto result : {
        VerificationResult::success,
        VerificationResult::denied,
        VerificationResult::error
    }) {
        const auto next = advance_verifier_conversation(
            VerifierVerifying{},
            VerifierMessageSender::pam_verifier,
            complete_message(result)
        );
        CHECK(is_state<VerifierCompleted>(next));
        CHECK(std::get<VerifierCompleted>(next).result == result);
    }

    const VerifierConversationState awaiting = VerifierAwaitingSecret{};
    const auto error = advance_verifier_conversation(
        awaiting,
        VerifierMessageSender::pam_verifier,
        complete_message(VerificationResult::error)
    );
    CHECK(is_state<VerifierCompleted>(error));
    CHECK(
        std::get<VerifierCompleted>(error).result ==
        VerificationResult::error
    );
    CHECK(rejects(
        awaiting,
        VerifierMessageSender::pam_verifier,
        complete_message(VerificationResult::success)
    ));
    CHECK(rejects(
        awaiting,
        VerifierMessageSender::pam_verifier,
        complete_message(VerificationResult::denied)
    ));
    return true;
}

bool test_cancellation_from_each_active_state() {
    using namespace vauth::uv;
    const std::array<VerifierConversationState, 2> active_states{
        VerifierVerifying{},
        VerifierAwaitingSecret{}
    };
    for(const auto& current : active_states) {
        const auto next = advance_verifier_conversation(
            current,
            VerifierMessageSender::daemon,
            cancel_message()
        );
        CHECK(is_state<VerifierCancelled>(next));
        CHECK(verifier_conversation_is_terminal(next));
    }
    return true;
}

bool test_messages_before_start_are_rejected() {
    using namespace vauth::uv;
    const VerifierConversationState state = VerifierAwaitingStart{};
    CHECK(rejects(
        state,
        VerifierMessageSender::pam_verifier,
        start_message()
    ));
    CHECK(rejects(
        state,
        VerifierMessageSender::pam_verifier,
        status_message(
            VerificationStatusKind::information,
            "Waiting for authentication"
        )
    ));
    CHECK(rejects(
        state,
        VerifierMessageSender::pam_verifier,
        secret_required_message()
    ));
    CHECK(rejects(
        state,
        VerifierMessageSender::pam_verifier,
        complete_message(VerificationResult::error)
    ));
    CHECK(rejects(
        state,
        VerifierMessageSender::daemon,
        secret_response_message()
    ));
    CHECK(rejects(
        state,
        VerifierMessageSender::daemon,
        cancel_message()
    ));
    return true;
}

bool test_wrong_sender_is_rejected() {
    using namespace vauth::uv;
    const VerifierConversationState state = VerifierVerifying{};
    CHECK(rejects(
        state,
        VerifierMessageSender::daemon,
        status_message(
            VerificationStatusKind::information,
            "Waiting for authentication"
        )
    ));
    CHECK(rejects(
        state,
        VerifierMessageSender::daemon,
        secret_required_message()
    ));
    CHECK(rejects(
        state,
        VerifierMessageSender::daemon,
        complete_message(VerificationResult::success)
    ));
    CHECK(rejects(
        state,
        VerifierMessageSender::pam_verifier,
        start_message()
    ));
    CHECK(rejects(
        state,
        VerifierMessageSender::pam_verifier,
        secret_response_message()
    ));
    CHECK(rejects(
        state,
        VerifierMessageSender::pam_verifier,
        cancel_message()
    ));
    return true;
}

bool test_secret_ordering_and_repeated_prompts() {
    using namespace vauth::uv;
    const VerifierConversationState verifying = VerifierVerifying{};
    const VerifierConversationState awaiting = VerifierAwaitingSecret{};

    CHECK(rejects(
        verifying,
        VerifierMessageSender::daemon,
        start_message()
    ));
    CHECK(rejects(
        verifying,
        VerifierMessageSender::daemon,
        secret_response_message()
    ));
    CHECK(rejects(
        awaiting,
        VerifierMessageSender::pam_verifier,
        status_message(
            VerificationStatusKind::error,
            "Authentication failed"
        )
    ));
    CHECK(rejects(
        awaiting,
        VerifierMessageSender::pam_verifier,
        secret_required_message()
    ));
    auto after = advance_verifier_conversation(
        awaiting,
        VerifierMessageSender::daemon,
        secret_response_message()
    );
    CHECK(is_state<VerifierVerifying>(after));
    after = advance_verifier_conversation(
        after,
        VerifierMessageSender::pam_verifier,
        secret_required_message()
    );
    CHECK(is_state<VerifierAwaitingSecret>(after));
    CHECK(rejects(
        verifying,
        VerifierMessageSender::daemon,
        secret_response_message()
    ));
    return true;
}

bool terminal_rejects_all_messages(
    const vauth::uv::VerifierConversationState& state
) {
    using namespace vauth::uv;
    CHECK(rejects(
        state,
        VerifierMessageSender::daemon,
        start_message()
    ));
    CHECK(rejects(
        state,
        VerifierMessageSender::daemon,
        secret_response_message()
    ));
    CHECK(rejects(
        state,
        VerifierMessageSender::daemon,
        cancel_message()
    ));
    CHECK(rejects(
        state,
        VerifierMessageSender::pam_verifier,
        status_message(
            VerificationStatusKind::information,
            "Waiting for authentication"
        )
    ));
    CHECK(rejects(
        state,
        VerifierMessageSender::pam_verifier,
        secret_required_message()
    ));
    CHECK(rejects(
        state,
        VerifierMessageSender::pam_verifier,
        complete_message(VerificationResult::success)
    ));
    return true;
}

bool test_terminal_states_reject_every_message() {
    using namespace vauth::uv;
    const VerifierConversationState completed = VerifierCompleted{
        VerificationResult::success
    };
    const VerifierConversationState cancelled = VerifierCancelled{};
    CHECK(verifier_conversation_is_terminal(completed));
    CHECK(verifier_conversation_is_terminal(cancelled));
    CHECK(terminal_rejects_all_messages(completed));
    CHECK(terminal_rejects_all_messages(cancelled));
    return true;
}

bool test_only_terminal_states_are_terminal() {
    using namespace vauth::uv;
    const std::array<VerifierConversationState, 3> active_states{
        VerifierAwaitingStart{},
        VerifierVerifying{},
        VerifierAwaitingSecret{}
    };
    for(const auto& state : active_states)
        CHECK(!verifier_conversation_is_terminal(state));
    CHECK(verifier_conversation_is_terminal(VerifierCompleted{
        VerificationResult::success
    }));
    CHECK(verifier_conversation_is_terminal(VerifierCancelled{}));
    return true;
}

bool test_invalid_enum_values_are_rejected() {
    using namespace vauth::uv;
    const VerifierConversationState state = VerifierVerifying{};
    CHECK(rejects(
        state,
        static_cast<VerifierMessageSender>(0xff),
        cancel_message()
    ));
    CHECK(rejects(
        state,
        VerifierMessageSender::pam_verifier,
        status_message(
            static_cast<VerificationStatusKind>(0xff),
            "Invalid"
        )
    ));
    CHECK(rejects(
        state,
        VerifierMessageSender::pam_verifier,
        complete_message(static_cast<VerificationResult>(0xff))
    ));
    return true;
}

} // namespace

int main() {
    test_support::Runner runner;
    runner.run(
        "verification without secret",
        test_verification_without_secret
    );
    runner.run("verification with secret", test_verification_with_secret);
    runner.run(
        "completion from each active state",
        test_completion_from_each_active_state
    );
    runner.run(
        "cancellation from each active state",
        test_cancellation_from_each_active_state
    );
    runner.run(
        "messages before start are rejected",
        test_messages_before_start_are_rejected
    );
    runner.run("wrong sender is rejected", test_wrong_sender_is_rejected);
    runner.run(
        "secret ordering and repeated prompts",
        test_secret_ordering_and_repeated_prompts
    );
    runner.run(
        "terminal states reject every message",
        test_terminal_states_reject_every_message
    );
    runner.run(
        "only terminal states are terminal",
        test_only_terminal_states_are_terminal
    );
    runner.run(
        "invalid enum values are rejected",
        test_invalid_enum_values_are_rejected
    );
    return runner.finish();
}
