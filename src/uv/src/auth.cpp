#include "auth.hpp"

#include "auth_handler.hpp"
#include "cancellable_process.hpp"
#include "cancellation.hpp"
#include "keepalive.hpp"

#include <chrono>
#include <string>
#include <unistd.h>
#include <utility>

namespace {

constexpr auto USER_ACTION_TIMEOUT = std::chrono::seconds(30);

uint64_t publish_state(
    UserInteractionChannel& channel,
    const UserContext& user,
    const UserInteractionRequest& request,
    UserInteractionState state,
    std::string_view message = {}
) {
    return channel.publish_state(user, request, state, message);
}

bool context_is_still_current(
    UserContextProvider& provider,
    const UserContext& user
) {
    const auto current = provider.current_context();
    return current && current->binding() == user.binding();
}

class InteractionScope {
public:
    InteractionScope(
        UserInteractionChannel& channel,
        const UserContext& user,
        const UserInteractionRequest& request
    ) : channel_(channel), user_(user), request_(request) {
        request_.requestId = channel_.begin_interaction(user_, request_);
        if(request_.requestId == 0)
            throw UserInteractionUnavailable{};
    }

    ~InteractionScope() {
        channel_.end_interaction(user_, request_);
    }

    InteractionScope(const InteractionScope&) = delete;
    InteractionScope& operator=(const InteractionScope&) = delete;

    [[nodiscard]] const UserInteractionRequest& request() const noexcept {
        return request_;
    }

private:
    UserInteractionChannel& channel_;
    const UserContext& user_;
    UserInteractionRequest request_;
};

vauth::uv::VerificationResult authenticate_user(
    const std::string& username,
    const std::string& process_name,
    const std::string& confdir,
    std::stop_token stop,
    KeepaliveState& keepalive,
    UserInteractionChannel& interaction_channel,
    const UserContext& user,
    const UserInteractionRequest& request
) {
    if(!user.session)
        throw UserInteractionUnavailable{};
    UserActionKeepaliveGuard waiting_for_user(keepalive);
    const auto deadline = std::chrono::steady_clock::now() +
        USER_ACTION_TIMEOUT;
    auto secret_callback = [
        &interaction_channel,
        &user,
        &request,
        stop,
        deadline
    ](const vauth::uv::SecretRequired& required) {
        const auto now = std::chrono::steady_clock::now();
        if(now >= deadline)
            throw UserActionTimedOut{};
        const uint64_t prompt_id = publish_state(
            interaction_channel,
            user,
            request,
            UserInteractionState::secret_required,
            required.prompt
        );
        if(prompt_id == 0) {
            if(interaction_channel.cancellation_requested(user, request))
                throw UserInteractionCancelled{};
            throw UserInteractionUnavailable{};
        }
        return interaction_channel.wait_for_secret(
            user,
            request,
            prompt_id,
            stop,
            deadline - now
        );
    };
    return vauth::uv::run_cancellable_verifier_program(
        "/proc/self/exe",
        {
            std::string(VAUTH_AUTH_HANDLER_COMMAND),
            username,
            process_name,
            confdir,
            std::to_string(getpid())
        },
        vauth::uv::StartVerification{
            .targetUid = user.uid,
            .sessionId = user.session->sessionId
        },
        stop,
        USER_ACTION_TIMEOUT,
        [&interaction_channel, &user, &request](
            const vauth::uv::VerificationStatus& status
        ) {
            const auto state =
                status.kind == vauth::uv::VerificationStatusKind::information
                    ? UserInteractionState::verification_information
                    : UserInteractionState::verification_error;
            static_cast<void>(publish_state(
                interaction_channel,
                user,
                request,
                state,
                status.message
            ));
        },
        secret_callback,
        [&interaction_channel, &user, &request] {
            return interaction_channel.cancellation_requested(user, request);
        }
    );
}

}

PamUserInteraction::PamUserInteraction(
    std::string process_name,
    std::string configuration_directory,
    UserContextProvider& context_provider,
    UserInteractionChannel& interaction_channel
) :
    processName_(std::move(process_name)),
    configurationDirectory_(std::move(configuration_directory)),
    contextProvider_(context_provider),
    interactionChannel_(interaction_channel)
{}

UserContext PamUserInteraction::current_context(std::stop_token stop) {
    cancellation_point(stop);
    if(auto context = contextProvider_.current_context()) {
        cancellation_point(stop);
        return std::move(*context);
    }
    throw UserInteractionUnavailable{};
}

UserInteractionResult PamUserInteraction::request_presence(
    const UserContext& user,
    const UserInteractionRequest& request,
    std::stop_token stop,
    KeepaliveState& keepalive
) {
    InteractionScope interaction(interactionChannel_, user, request);
    const auto& active_request = interaction.request();
    publish_state(
        interactionChannel_,
        user,
        active_request,
        UserInteractionState::presence_required
    );
    try {
        UserActionKeepaliveGuard waiting_for_user(keepalive);
        const UserInteractionResult response =
            interactionChannel_.wait_for_presence(
                user,
                active_request,
                stop,
                USER_ACTION_TIMEOUT
            );
        if(response == UserInteractionResult::cancelled) {
            publish_state(
                interactionChannel_, user, active_request,
                UserInteractionState::cancelled
            );
            return UserInteractionResult::cancelled;
        }
        const bool approved =
            response == UserInteractionResult::approved &&
            context_is_still_current(contextProvider_, user);
        publish_state(
            interactionChannel_,
            user,
            active_request,
            approved
                ? UserInteractionState::presence_approved
                : UserInteractionState::presence_denied
        );
        return approved
            ? UserInteractionResult::approved
            : UserInteractionResult::denied;
    } catch(const UserInteractionCancelled&) {
        publish_state(
            interactionChannel_, user, active_request,
            UserInteractionState::cancelled
        );
        return UserInteractionResult::cancelled;
    } catch(const OperationCancelled&) {
        publish_state(
            interactionChannel_, user, active_request,
            UserInteractionState::cancelled
        );
        throw;
    } catch(const UserActionTimedOut&) {
        publish_state(
            interactionChannel_, user, active_request,
            UserInteractionState::timed_out
        );
        throw;
    }
}

UserInteractionResult PamUserInteraction::request_verification(
    const UserContext& user,
    const UserInteractionRequest& request,
    std::stop_token stop,
    KeepaliveState& keepalive
) {
    InteractionScope interaction(interactionChannel_, user, request);
    const auto& active_request = interaction.request();
    publish_state(
        interactionChannel_,
        user,
        active_request,
        UserInteractionState::verification_started
    );
    try {
        const bool approved = authenticate_user(
            user.name,
            processName_,
            configurationDirectory_,
            stop,
            keepalive,
            interactionChannel_,
            user,
            active_request
        ) == vauth::uv::VerificationResult::success &&
            context_is_still_current(contextProvider_, user);
        publish_state(
            interactionChannel_,
            user,
            active_request,
            approved
                ? UserInteractionState::verification_succeeded
                : UserInteractionState::verification_failed
        );
        return approved
            ? UserInteractionResult::approved
            : UserInteractionResult::denied;
    } catch(const UserInteractionCancelled&) {
        publish_state(
            interactionChannel_, user, active_request,
            UserInteractionState::cancelled
        );
        return UserInteractionResult::cancelled;
    } catch(const OperationCancelled&) {
        publish_state(
            interactionChannel_, user, active_request,
            UserInteractionState::cancelled
        );
        throw;
    } catch(const UserActionTimedOut&) {
        publish_state(
            interactionChannel_, user, active_request,
            UserInteractionState::timed_out
        );
        throw;
    }
}
