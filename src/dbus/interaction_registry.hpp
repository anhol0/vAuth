#pragma once

#include "uv/src/user_context.hpp"
#include "uv/src/user_interaction.hpp"
#include "uv/src/sensitive_bytes.hpp"

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <stop_token>

namespace vauth::dbus {

struct PendingInteraction {
    uint64_t requestId;
    UserContextBinding user;
    UserInteractionOperation operation;
    std::string relyingPartyId;
    std::optional<UserInteractionState> state;
    std::string message;
    uint64_t promptId = 0;
    std::optional<bool> presenceResponse;
    bool secretSubmitted = false;
    bool cancelRequested = false;
    bool responseClosed = false;
};

enum class PresenceWaitResult {
    approved,
    denied,
    client_cancelled,
    platform_cancelled,
    timed_out,
    invalidated
};

enum class SecretWaitStatus {
    provided,
    client_cancelled,
    platform_cancelled,
    timed_out,
    invalidated
};

struct SecretWaitResult {
    SecretWaitStatus status;
    vauth::uv::SensitiveBytes secret;
};

struct InteractionTransition {
    bool shouldPublish;
    uint64_t promptId;

    explicit operator bool() const noexcept {
        return shouldPublish;
    }
};

class InteractionRegistry {
public:
    [[nodiscard]] uint64_t begin(
        const UserContext& user,
        UserInteractionOperation operation,
        std::string_view relying_party_id
    );
    [[nodiscard]] InteractionTransition transition(
        const UserContext& user,
        uint64_t request_id,
        UserInteractionState state,
        std::string_view message = {}
    );
    void respond_to_presence(
        const UserContext& user,
        uint64_t request_id,
        bool approved
    );
    void submit_secret(
        const UserContext& user,
        uint64_t request_id,
        uint64_t prompt_id,
        vauth::uv::SensitiveBytes secret
    );
    void request_cancel(
        const UserContext& user,
        uint64_t request_id
    );
    [[nodiscard]] PresenceWaitResult wait_for_presence(
        const UserContext& user,
        uint64_t request_id,
        std::stop_token stop,
        std::chrono::steady_clock::duration timeout
    );
    [[nodiscard]] SecretWaitResult wait_for_secret(
        const UserContext& user,
        uint64_t request_id,
        uint64_t prompt_id,
        std::stop_token stop,
        std::chrono::steady_clock::duration timeout
    );
    [[nodiscard]] bool cancellation_requested(
        const UserContext& user,
        uint64_t request_id
    ) const noexcept;
    [[nodiscard]] bool end(
        const UserContext& user,
        uint64_t request_id
    ) noexcept;
    void clear_for(const UserContext& user) noexcept;
    [[nodiscard]] std::optional<PendingInteraction> current() const;

private:
    mutable std::mutex mutex_;
    std::condition_variable condition_;
    std::optional<PendingInteraction> current_;
    std::optional<vauth::uv::SensitiveBytes> secretResponse_;
    uint64_t nextRequestId_ = 1;
    uint64_t nextPromptId_ = 1;
};

}
