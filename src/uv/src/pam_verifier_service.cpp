#include "pam_verifier_service.hpp"

#include "auth_handler.hpp"
#include "cancellable_process.hpp"
#include "cancellation.hpp"
#include "verifier_conversation.hpp"
#include "verifier_socket.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <limits>
#include <poll.h>
#include <pwd.h>
#include <stdexcept>
#include <stop_token>
#include <string>
#include <system_error>
#include <unistd.h>
#include <utility>
#include <vector>

namespace vauth::uv {
namespace {

constexpr std::size_t MAX_ACCOUNT_BUFFER_SIZE = 1024 * 1024;

uid_t uid_for_username(std::string_view username) {
    const long suggested_size = sysconf(_SC_GETPW_R_SIZE_MAX);
    std::size_t buffer_size = suggested_size > 0
        ? static_cast<std::size_t>(suggested_size)
        : 16384;
    buffer_size = std::min(buffer_size, MAX_ACCOUNT_BUFFER_SIZE);

    while(true) {
        std::vector<char> buffer(buffer_size);
        passwd account{};
        passwd* result = nullptr;
        const std::string account_name(username);
        const int status = getpwnam_r(
            account_name.c_str(),
            &account,
            buffer.data(),
            buffer.size(),
            &result
        );
        if(status == 0 && result != nullptr)
            return account.pw_uid;
        if(status != ERANGE || buffer_size == MAX_ACCOUNT_BUFFER_SIZE) {
            if(status != 0) {
                throw std::system_error(
                    status,
                    std::generic_category(),
                    "resolve vAuth daemon account"
                );
            }
            throw std::runtime_error("vAuth daemon account does not exist");
        }
        buffer_size = std::min(buffer_size * 2, MAX_ACCOUNT_BUFFER_SIZE);
    }
}

std::string username_for_uid(uint32_t requested_uid) {
    if(
        static_cast<uintmax_t>(requested_uid) >
        static_cast<uintmax_t>(std::numeric_limits<uid_t>::max())
    ) {
        throw std::invalid_argument("verification UID is out of range");
    }
    const uid_t uid = static_cast<uid_t>(requested_uid);
    const long suggested_size = sysconf(_SC_GETPW_R_SIZE_MAX);
    std::size_t buffer_size = suggested_size > 0
        ? static_cast<std::size_t>(suggested_size)
        : 16384;
    buffer_size = std::min(buffer_size, MAX_ACCOUNT_BUFFER_SIZE);

    while(true) {
        std::vector<char> buffer(buffer_size);
        passwd account{};
        passwd* result = nullptr;
        const int status = getpwuid_r(
            uid,
            &account,
            buffer.data(),
            buffer.size(),
            &result
        );
        if(status == 0 && result != nullptr && account.pw_name != nullptr)
            return account.pw_name;
        if(status != ERANGE || buffer_size == MAX_ACCOUNT_BUFFER_SIZE) {
            if(status != 0) {
                throw std::system_error(
                    status,
                    std::generic_category(),
                    "resolve verification user"
                );
            }
            throw std::invalid_argument("verification UID has no user account");
        }
        buffer_size = std::min(buffer_size * 2, MAX_ACCOUNT_BUFFER_SIZE);
    }
}

class DaemonConversation {
public:
    explicit DaemonConversation(VerifierSocket socket)
        : socket_(std::move(socket)) {}

    [[nodiscard]] StartVerification receive_start() {
        VerifierMessage message = socket_.receive();
        state_ = advance_verifier_conversation(
            state_,
            VerifierMessageSender::daemon,
            message
        );
        auto* start = std::get_if<StartVerification>(&message);
        if(start == nullptr)
            throw VerifierConversationError("daemon did not start verification");
        return std::move(*start);
    }

    void send_status(const VerificationStatus& status) {
        send_from_verifier(status);
    }

    [[nodiscard]] SensitiveBytes request_secret(
        const SecretRequired& required
    ) {
        send_from_verifier(required);
        VerifierMessage response = socket_.receive();
        state_ = advance_verifier_conversation(
            state_,
            VerifierMessageSender::daemon,
            response
        );
        if(std::holds_alternative<CancelVerification>(response))
            throw UserInteractionCancelled{};
        auto* secret = std::get_if<SecretResponse>(&response);
        if(secret == nullptr) {
            throw VerifierConversationError(
                "daemon did not answer the verification prompt"
            );
        }
        return std::move(secret->secret);
    }

    [[nodiscard]] bool cancellation_requested() {
        if(verifier_conversation_is_terminal(state_))
            return std::holds_alternative<VerifierCancelled>(state_);

        pollfd descriptor{
            .fd = socket_.native_handle(),
            .events = POLLIN,
            .revents = 0
        };
        int result;
        do {
            result = poll(&descriptor, 1, 0);
        } while(result < 0 && errno == EINTR);
        if(result < 0) {
            throw std::system_error(
                errno,
                std::generic_category(),
                "poll verifier daemon connection"
            );
        }
        if(result == 0)
            return false;
        if((descriptor.revents & POLLIN) == 0) {
            throw VerifierSocketError(
                "verifier daemon connection closed"
            );
        }

        VerifierMessage message = socket_.receive();
        state_ = advance_verifier_conversation(
            state_,
            VerifierMessageSender::daemon,
            message
        );
        if(!std::holds_alternative<CancelVerification>(message)) {
            throw VerifierConversationError(
                "daemon sent a response when no secret was requested"
            );
        }
        return true;
    }

    void complete(VerificationResult result) {
        send_from_verifier(VerificationComplete{result});
    }

private:
    void send_from_verifier(VerifierMessage message) {
        socket_.send(message);
        state_ = advance_verifier_conversation(
            state_,
            VerifierMessageSender::pam_verifier,
            message
        );
    }

    VerifierSocket socket_;
    VerifierConversationState state_ = VerifierAwaitingStart{};
};

}

void authorize_verifier_peer(
    const VerifierPeerCredentials& peer,
    uid_t expected_daemon_uid
) {
    if(peer.pid <= 0)
        throw std::runtime_error("PAM verifier peer has no process ID");
    if(peer.uid != expected_daemon_uid) {
        throw std::runtime_error(
            "PAM verifier peer is not the vAuth daemon user"
        );
    }
}

void authorize_verification_session(
    const StartVerification& request,
    const vauth::LoginSessionProperties& session
) {
    if(request.sessionId.empty())
        throw std::invalid_argument("verification session ID is empty");
    if(
        static_cast<uintmax_t>(request.targetUid) >
        static_cast<uintmax_t>(std::numeric_limits<uid_t>::max())
    ) {
        throw std::invalid_argument("verification UID is out of range");
    }
    vauth::validate_active_local_session(
        session,
        static_cast<uid_t>(request.targetUid)
    );
}

int run_pam_verifier_service(
    int socket_fd,
    const std::string& pam_service,
    const std::string& pam_configuration_directory,
    std::chrono::steady_clock::duration timeout
) {
    VerifierSocket connection(socket_fd);
    return run_pam_verifier_connection(
        std::move(connection),
        uid_for_username(VAUTH_DAEMON_ACCOUNT),
        "/proc/self/exe",
        pam_service,
        pam_configuration_directory,
        timeout,
        [](const std::string& session_id) {
            return vauth::query_login_session(session_id);
        }
    );
}

int run_pam_verifier_connection(
    VerifierSocket connection,
    uid_t expected_daemon_uid,
    const std::string& verifier_program,
    const std::string& pam_service,
    const std::string& pam_configuration_directory,
    std::chrono::steady_clock::duration timeout,
    const LoginSessionQuery& query_session
) {
    if(timeout <= std::chrono::steady_clock::duration::zero())
        throw std::invalid_argument("PAM verifier timeout must be positive");
    if(!query_session)
        throw std::invalid_argument("PAM verifier session query is missing");

    authorize_verifier_peer(
        connection.peer_credentials(),
        expected_daemon_uid
    );
    DaemonConversation daemon(std::move(connection));
    StartVerification start = daemon.receive_start();
    std::string username;
    try {
        authorize_verification_session(
            start,
            query_session(start.sessionId)
        );
        username = username_for_uid(start.targetUid);
    } catch(...) {
        daemon.complete(VerificationResult::error);
        throw;
    }

    try {
        VerificationResult result = run_cancellable_verifier_program(
            verifier_program,
            {
                std::string(VAUTH_AUTH_HANDLER_COMMAND),
                username,
                pam_service,
                pam_configuration_directory,
                std::to_string(getpid())
            },
            start,
            {},
            timeout,
            [&daemon](const VerificationStatus& status) {
                daemon.send_status(status);
            },
            [&daemon](const SecretRequired& required) {
                return daemon.request_secret(required);
            },
            [&daemon] {
                return daemon.cancellation_requested();
            }
        );
        if(result == VerificationResult::success) {
            try {
                authorize_verification_session(
                    start,
                    query_session(start.sessionId)
                );
            } catch(...) {
                daemon.complete(VerificationResult::error);
                throw;
            }
        }
        daemon.complete(result);
        return 0;
    } catch(const UserInteractionCancelled&) {
        return 0;
    }
}

}
