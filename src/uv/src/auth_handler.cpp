#include "auth_handler.hpp"
#include "cancellable_process.hpp"
#include "sensitive_bytes.hpp"
#include "verifier_conversation.hpp"
#include "verifier_socket.hpp"

#include <security/_pam_types.h>
#include <security/pam_appl.h>

#include <charconv>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>
#include <strings.h>
#include <utility>

namespace {

struct ConversationContext {
    vauth::uv::VerifierSocket& socket;
    vauth::uv::VerifierConversationState state;
};

void send_verifier_message(
    ConversationContext& context,
    vauth::uv::VerifierMessage message
) {
    context.socket.send(message);
    context.state = vauth::uv::advance_verifier_conversation(
        context.state,
        vauth::uv::VerifierMessageSender::pam_verifier,
        message
    );
}

void free_responses(pam_response* responses, int count) noexcept {
    if(responses == nullptr)
        return;
    for(int i = 0; i < count; ++i) {
        if(responses[i].resp != nullptr) {
            explicit_bzero(responses[i].resp, std::strlen(responses[i].resp));
            std::free(responses[i].resp);
        }
    }
    std::free(responses);
}

int read_secret_response(
    ConversationContext& context,
    std::string_view prompt,
    char** response
) {
    if(response == nullptr)
        return PAM_CONV_ERR;
    send_verifier_message(
        context,
        vauth::uv::SecretRequired{std::string(prompt)}
    );
    vauth::uv::VerifierMessage message = context.socket.receive();
    context.state = vauth::uv::advance_verifier_conversation(
        context.state,
        vauth::uv::VerifierMessageSender::daemon,
        message
    );
    auto* supplied = std::get_if<vauth::uv::SecretResponse>(&message);
    if(supplied == nullptr)
        return PAM_CONV_ERR;

    char* copy = static_cast<char*>(std::calloc(supplied->secret.size() + 1, 1));
    if(copy == nullptr)
        return PAM_BUF_ERR;
    if(!supplied->secret.bytes().empty()) {
        std::memcpy(
            copy,
            supplied->secret.bytes().data(),
            supplied->secret.size()
        );
    }
    *response = copy;
    return PAM_SUCCESS;
}

int conversation(
    int message_count,
    const pam_message** messages,
    pam_response** response,
    void* user_data
) noexcept {
    if(
        message_count <= 0 ||
        message_count > PAM_MAX_NUM_MSG ||
        messages == nullptr ||
        response == nullptr
    ) {
        return PAM_CONV_ERR;
    }
    *response = nullptr;
    auto* context = static_cast<ConversationContext*>(user_data);
    if(context == nullptr)
        return PAM_CONV_ERR;

    auto* replies = static_cast<pam_response*>(
        std::calloc(static_cast<std::size_t>(message_count), sizeof(pam_response))
    );
    if(replies == nullptr)
        return PAM_BUF_ERR;

    try {
        for(int i = 0; i < message_count; ++i) {
            if(messages[i] == nullptr) {
                free_responses(replies, message_count);
                return PAM_CONV_ERR;
            }

            int rc = PAM_SUCCESS;
            switch(messages[i]->msg_style) {
                case PAM_PROMPT_ECHO_OFF:
                    rc = read_secret_response(
                        *context,
                        messages[i]->msg == nullptr ? "" : messages[i]->msg,
                        &replies[i].resp
                    );
                    break;
                case PAM_PROMPT_ECHO_ON:
                    // The daemon never obtains identity or other visible PAM
                    // responses from inherited standard input.
                    rc = PAM_CONV_ERR;
                    break;
                case PAM_TEXT_INFO:
                    send_verifier_message(
                        *context,
                        vauth::uv::VerificationStatus{
                            vauth::uv::VerificationStatusKind::information,
                            messages[i]->msg == nullptr ? "" : messages[i]->msg
                        }
                    );
                    break;
                case PAM_ERROR_MSG:
                    send_verifier_message(
                        *context,
                        vauth::uv::VerificationStatus{
                            vauth::uv::VerificationStatusKind::error,
                            messages[i]->msg == nullptr ? "" : messages[i]->msg
                        }
                    );
                    break;
                default:
                    rc = PAM_CONV_ERR;
                    break;
            }
            if(rc != PAM_SUCCESS) {
                free_responses(replies, message_count);
                return rc;
            }
        }
    } catch(...) {
        free_responses(replies, message_count);
        return PAM_CONV_ERR;
    }

    *response = replies;
    return PAM_SUCCESS;
}

class PamSession {
public:
    PamSession() = default;

    ~PamSession() {
        close(status_);
    }

    PamSession(const PamSession&) = delete;
    PamSession& operator=(const PamSession&) = delete;

    int start(
        const char* process_name,
        const char* username,
        const pam_conv* conv,
        const char* confdir
    ) noexcept {
        pam_handle_t* handle = nullptr;
        const int rc = pam_start_confdir(
            process_name,
            username,
            conv,
            confdir,
            &handle
        );
        handle_ = handle;
        status_ = rc;
        return rc;
    }

    pam_handle_t* get() noexcept {
        return handle_;
    }

    void set_status(int status) noexcept {
        status_ = status;
    }

    int close(int status) noexcept {
        if(handle_ == nullptr)
            return PAM_SUCCESS;
        pam_handle_t* handle = handle_;
        handle_ = nullptr;
        return pam_end(handle, status);
    }

private:
    pam_handle_t* handle_ = nullptr;
    int status_ = PAM_SYSTEM_ERR;
};

int authenticate(
    const char* username,
    const char* process_name,
    const char* confdir,
    ConversationContext& context
) {
    const pam_conv conv{&conversation, &context};
    PamSession session;
    int rc = session.start(
        process_name,
        username,
        &conv,
        confdir
    );
    if(rc == PAM_SUCCESS)
        rc = pam_authenticate(session.get(), 0);
    if(rc == PAM_SUCCESS)
        rc = pam_acct_mgmt(session.get(), 0);
    session.set_status(rc);

    const int end_rc = session.close(rc);
    if(rc == PAM_SUCCESS && end_rc != PAM_SUCCESS)
        return end_rc;
    return rc;
}

vauth::uv::VerificationResult verification_result(int pam_status) noexcept {
    if(pam_status == PAM_SUCCESS)
        return vauth::uv::VerificationResult::success;
    switch(pam_status) {
        case PAM_OPEN_ERR:
        case PAM_SYMBOL_ERR:
        case PAM_SERVICE_ERR:
        case PAM_SYSTEM_ERR:
        case PAM_BUF_ERR:
        case PAM_CONV_ERR:
        case PAM_ABORT:
        case PAM_MODULE_UNKNOWN:
        case PAM_BAD_ITEM:
            return vauth::uv::VerificationResult::error;
        default:
            return vauth::uv::VerificationResult::denied;
    }
}

}

int run_vauth_auth_handler(int argc, char** argv) noexcept {
    if(argc != 4 || argv == nullptr)
        return PAM_SYSTEM_ERR;

    try {
        pid_t expected_parent = 0;
        const std::string_view parent_text(argv[3]);
        const auto [end, error] = std::from_chars(
            parent_text.data(),
            parent_text.data() + parent_text.size(),
            expected_parent
        );
        if(
            error != std::errc{} ||
            end != parent_text.data() + parent_text.size()
        ) {
            return PAM_SYSTEM_ERR;
        }
        vauth::uv::arm_parent_death_signal(expected_parent);
        vauth::uv::VerifierSocket socket(vauth::uv::VERIFIER_SOCKET_FD);
        vauth::uv::VerifierConversationState state =
            vauth::uv::VerifierAwaitingStart{};
        vauth::uv::VerifierMessage start = socket.receive();
        state = vauth::uv::advance_verifier_conversation(
            state,
            vauth::uv::VerifierMessageSender::daemon,
            start
        );
        ConversationContext context{socket, std::move(state)};
        const int result = authenticate(argv[0], argv[1], argv[2], context);
        send_verifier_message(
            context,
            vauth::uv::VerificationComplete{verification_result(result)}
        );
        return result;
    } catch(...) {
        return PAM_SYSTEM_ERR;
    }
}
