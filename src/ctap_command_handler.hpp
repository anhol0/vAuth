#pragma once

#include <stop_token>

#include "authentication/authenticate.hpp"
#include "response.hpp"

class CredentialKeyProvider;
class KeepaliveState;
class UserInteraction;

// Owns the continuation state for the daemon's serialized CTAP command stream.
// Call reset only when no worker is accessing the handler.
class CTAPCommandHandler {
public:
    CTAPPacket handle(
        UHIDReport& request,
        std::stop_token stop,
        CredentialStore& store,
        CredentialKeyProvider& key_provider,
        UserInteraction& user_interaction,
        KeepaliveState& keepalive
    );

    void reset() noexcept;

private:
    CTAPGetAssertionRequest getAssertion_;
};
