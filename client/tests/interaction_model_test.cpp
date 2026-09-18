#include "interaction_model.hpp"
#include "test_runner.hpp"

#include <iostream>
#include <string>
#include <utility>

namespace {

#define CHECK(condition) do { \
    if(!(condition)) { \
        std::cerr << "CHECK failed at " << __FILE__ << ':' << __LINE__ \
                  << ": " #condition "\n"; \
        return false; \
    } \
} while(false)

vauth::client::InteractionEvent event(
    vauth::client::InteractionState state,
    uint64_t generation = 7,
    uint64_t request_id = 42,
    uint64_t prompt_id = 0,
    std::string message = {}
) {
    return {
        .generation = generation,
        .requestId = request_id,
        .promptId = prompt_id,
        .state = state,
        .operation = "make_credential",
        .relyingPartyId = "example.com",
        .message = std::move(message)
    };
}

bool test_state_parser_is_strict() {
    using vauth::client::InteractionState;
    CHECK(
        vauth::client::parse_interaction_state("verification_information") ==
        InteractionState::verification_information
    );
    CHECK(
        vauth::client::parse_interaction_state("verification_error") ==
        InteractionState::verification_error
    );
    CHECK(
        vauth::client::parse_interaction_state("secret_required") ==
        InteractionState::secret_required
    );
    CHECK(!vauth::client::parse_interaction_state("fingerprint_required"));
    CHECK(!vauth::client::parse_interaction_state("password_required"));
    CHECK(!vauth::client::parse_interaction_state("password-required"));
    CHECK(!vauth::client::parse_interaction_state(""));
    return true;
}

bool test_tracker_rejects_stale_and_foreign_events() {
    using vauth::client::InteractionState;
    vauth::client::InteractionTracker tracker(7);

    CHECK(!tracker.accept(event(InteractionState::presence_required, 6)));
    CHECK(!tracker.accept(event(InteractionState::presence_required, 7, 0)));
    CHECK(tracker.accept(event(InteractionState::presence_required)));
    CHECK(tracker.is_active(42));
    CHECK(!tracker.accept(event(
        InteractionState::secret_required,
        7,
        43,
        1,
        "Password:"
    )));
    CHECK(tracker.accept(event(InteractionState::presence_denied)));
    CHECK(!tracker.is_active(42));
    CHECK(!tracker.accept(event(InteractionState::presence_approved)));
    return true;
}

bool test_tracker_accepts_verification_sequence() {
    using vauth::client::InteractionState;
    vauth::client::InteractionTracker tracker(7);

    CHECK(tracker.accept(event(InteractionState::verification_started)));
    CHECK(tracker.accept(event(
        InteractionState::verification_information,
        7,
        42,
        0,
        "Touch the security device"
    )));
    CHECK(tracker.accept(event(
        InteractionState::verification_error,
        7,
        42,
        0,
        "No match; try again"
    )));
    CHECK(tracker.accept(event(
        InteractionState::secret_required,
        7,
        42,
        11,
        "Password:"
    )));
    CHECK(tracker.accept(event(
        InteractionState::verification_information,
        7,
        42,
        0,
        "Checking the response"
    )));
    CHECK(tracker.accept(event(
        InteractionState::secret_required,
        7,
        42,
        12,
        "One-time code:"
    )));
    CHECK(tracker.accept(event(InteractionState::verification_succeeded)));
    CHECK(!tracker.is_active(42));
    return true;
}

bool test_tracker_validates_prompt_ids() {
    using vauth::client::InteractionState;
    vauth::client::InteractionTracker tracker(7);

    CHECK(tracker.accept(event(InteractionState::verification_started)));
    CHECK(!tracker.accept(event(
        InteractionState::secret_required,
        7,
        42,
        0,
        "Password:"
    )));
    CHECK(tracker.accept(event(
        InteractionState::secret_required,
        7,
        42,
        19,
        "Password:"
    )));
    CHECK(!tracker.accept(event(
        InteractionState::verification_information,
        7,
        42,
        19,
        "Checking"
    )));
    CHECK(tracker.is_active(42));
    CHECK(tracker.accept(event(
        InteractionState::verification_information,
        7,
        42,
        0,
        "Checking"
    )));
    return true;
}

bool test_ui_model_maps_presence_and_secret() {
    using vauth::client::AnimationKind;
    using vauth::client::InteractionState;
    using vauth::client::ViewKind;
    vauth::client::UiModel model;

    const auto presence = model.apply(
        event(InteractionState::presence_required)
    );
    CHECK(presence.view == ViewKind::presence);
    CHECK(presence.title == "Create a passkey?");
    CHECK(presence.relyingPartyId == "example.com");
    CHECK(!presence.terminal);

    const auto secret = model.apply(
        event(
            InteractionState::secret_required,
            7,
            42,
            9,
            "Smart-card PIN:"
        )
    );
    CHECK(secret.view == ViewKind::secret);
    CHECK(secret.animation == AnimationKind::waiting);
    CHECK(secret.message == "Smart-card PIN:");
    CHECK(!secret.terminal);
    return true;
}

bool test_ui_model_maps_generic_verification_messages() {
    using vauth::client::AnimationKind;
    using vauth::client::InteractionState;
    using vauth::client::ViewKind;
    vauth::client::UiModel model;

    const auto information = model.apply(event(
        InteractionState::verification_information,
        7,
        42,
        0,
        "Touch the security device"
    ));
    CHECK(information.view == ViewKind::verification);
    CHECK(information.animation == AnimationKind::waiting);
    CHECK(information.message == "Touch the security device");
    CHECK(!information.terminal);

    const auto error = model.apply(event(
        InteractionState::verification_error,
        7,
        42,
        0,
        "No match; try again"
    ));
    CHECK(error.view == ViewKind::verification);
    CHECK(error.animation == AnimationKind::failure);
    CHECK(error.message == "No match; try again");
    CHECK(!error.terminal);
    return true;
}

bool test_ui_model_maps_terminal_states() {
    using vauth::client::AnimationKind;
    using vauth::client::InteractionState;
    using vauth::client::ViewKind;
    vauth::client::UiModel model;

    static_cast<void>(model.apply(
        event(
            InteractionState::verification_information,
            7,
            42,
            0,
            "Touch the security device"
        )
    ));
    const auto success = model.apply(
        event(InteractionState::verification_succeeded)
    );
    CHECK(success.view == ViewKind::verification);
    CHECK(success.animation == AnimationKind::success);
    CHECK(success.terminal);

    const auto timeout = model.apply(event(InteractionState::timed_out));
    CHECK(timeout.view == ViewKind::status);
    CHECK(timeout.title == "Timed out");
    CHECK(timeout.terminal);
    return true;
}

bool test_secret_failure_uses_failure_animation() {
    using vauth::client::AnimationKind;
    using vauth::client::InteractionState;
    using vauth::client::ViewKind;
    vauth::client::UiModel model;

    static_cast<void>(model.apply(
        event(InteractionState::verification_started)
    ));
    static_cast<void>(model.apply(
        event(
            InteractionState::secret_required,
            7,
            42,
            3,
            "Password:"
        )
    ));
    const auto failure = model.apply(
        event(InteractionState::verification_failed)
    );

    CHECK(failure.view == ViewKind::verification);
    CHECK(failure.animation == AnimationKind::failure);
    CHECK(failure.title == "Verification failed");
    CHECK(failure.terminal);
    return true;
}

} // namespace

int main() {
    test_support::Runner runner;
    runner.run("state parser is strict", test_state_parser_is_strict);
    runner.run(
        "tracker rejects stale and foreign events",
        test_tracker_rejects_stale_and_foreign_events
    );
    runner.run(
        "tracker accepts verification sequence",
        test_tracker_accepts_verification_sequence
    );
    runner.run(
        "tracker validates prompt IDs",
        test_tracker_validates_prompt_ids
    );
    runner.run(
        "UI model maps presence and secret",
        test_ui_model_maps_presence_and_secret
    );
    runner.run(
        "UI model maps generic verification messages",
        test_ui_model_maps_generic_verification_messages
    );
    runner.run(
        "UI model maps terminal states",
        test_ui_model_maps_terminal_states
    );
    runner.run(
        "secret failure uses failure animation",
        test_secret_failure_uses_failure_animation
    );
    return runner.finish();
}
