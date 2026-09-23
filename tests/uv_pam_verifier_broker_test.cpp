#include "cancellation.hpp"
#include "test_runner.hpp"
#include "uv/src/auth_handler.hpp"
#include "uv/src/pam_verifier_service.hpp"
#include "uv/src/verifier_conversation.hpp"
#include "uv/src/verifier_socket.hpp"

#include <array>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <iostream>
#include <limits>
#include <optional>
#include <poll.h>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <utility>

namespace {

#define CHECK(condition) do { \
    if(!(condition)) { \
        std::cerr << "CHECK failed at " << __FILE__ << ':' << __LINE__ \
                  << ": " #condition "\n"; \
        return false; \
    } \
} while(false)

constexpr auto TEST_TIMEOUT = std::chrono::seconds(2);

vauth::LoginSessionProperties active_session() {
    return {
        .uid = getuid(),
        .active = true,
        .remote = false
    };
}

vauth::uv::StartVerification start_request() {
    if(
        static_cast<uintmax_t>(getuid()) >
        static_cast<uintmax_t>(std::numeric_limits<uint32_t>::max())
    ) {
        throw std::runtime_error("test UID exceeds the verifier protocol");
    }
    return {
        .targetUid = static_cast<uint32_t>(getuid()),
        .sessionId = "test-session"
    };
}

vauth::uv::VerifierMessage receive_with_timeout(
    vauth::uv::VerifierSocket& socket
) {
    pollfd descriptor{
        .fd = socket.native_handle(),
        .events = POLLIN,
        .revents = 0
    };
    int result;
    do {
        result = poll(
            &descriptor,
            1,
            static_cast<int>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    TEST_TIMEOUT
                ).count()
            )
        );
    } while(result < 0 && errno == EINTR);
    if(result < 0)
        throw std::runtime_error("poll test verifier connection");
    if(result == 0)
        throw std::runtime_error("test verifier connection timed out");
    return socket.receive();
}

pid_t worker_pid(const vauth::uv::VerifierMessage& message) {
    const auto* status = std::get_if<vauth::uv::VerificationStatus>(&message);
    if(status == nullptr || !status->message.starts_with("worker-pid="))
        throw std::runtime_error("worker did not report its process ID");

    const std::string_view value(status->message);
    pid_t result = -1;
    const auto digits = value.substr(std::string_view("worker-pid=").size());
    const auto parsed = std::from_chars(
        digits.data(),
        digits.data() + digits.size(),
        result
    );
    if(parsed.ec != std::errc{} || parsed.ptr != digits.data() + digits.size())
        throw std::runtime_error("worker reported an invalid process ID");
    return result;
}

bool child_was_reaped(pid_t child) {
    int status = 0;
    errno = 0;
    return waitpid(child, &status, WNOHANG) == -1 && errno == ECHILD;
}

class BrokerFixture {
public:
    BrokerFixture(
        std::string executable,
        std::string worker_mode,
        std::chrono::steady_clock::duration timeout,
        vauth::uv::LoginSessionQuery query_session =
            [](const std::string&) { return active_session(); }
    ) {
        std::array<int, 2> descriptors{-1, -1};
        if(
            socketpair(
                AF_UNIX,
                SOCK_SEQPACKET | SOCK_CLOEXEC,
                0,
                descriptors.data()
            ) != 0
        ) {
            throw std::runtime_error("create broker test socket pair");
        }

        try {
            client_.emplace(descriptors[0]);
        } catch(...) {
            static_cast<void>(close(descriptors[1]));
            throw;
        }

        try {
            broker_ = std::jthread([
                this,
                descriptor = descriptors[1],
                executable = std::move(executable),
                worker_mode = std::move(worker_mode),
                timeout,
                query_session = std::move(query_session)
            ] {
                try {
                    result_ = vauth::uv::run_pam_verifier_connection(
                        vauth::uv::VerifierSocket(descriptor),
                        getuid(),
                        executable,
                        worker_mode,
                        "/unused/test-pam-config",
                        timeout,
                        query_session
                    );
                } catch(...) {
                    error_ = std::current_exception();
                }
            });
        } catch(...) {
            static_cast<void>(close(descriptors[1]));
            throw;
        }
    }

    ~BrokerFixture() {
        client_.reset();
        if(broker_.joinable())
            broker_.join();
    }

    BrokerFixture(const BrokerFixture&) = delete;
    BrokerFixture& operator=(const BrokerFixture&) = delete;

    vauth::uv::VerifierSocket& client() {
        if(!client_)
            throw std::runtime_error("broker test client is disconnected");
        return *client_;
    }

    void disconnect() {
        client_.reset();
    }

    void join() {
        if(broker_.joinable())
            broker_.join();
    }

    [[nodiscard]] bool completed_successfully() {
        join();
        return !error_ && result_ == 0;
    }

    template<typename Exception>
    [[nodiscard]] bool failed_with() {
        join();
        if(!error_)
            return false;
        try {
            std::rethrow_exception(error_);
        } catch(const Exception&) {
            return true;
        } catch(...) {
            return false;
        }
    }

private:
    std::optional<vauth::uv::VerifierSocket> client_;
    std::jthread broker_;
    std::optional<int> result_;
    std::exception_ptr error_;
};

void send_start(BrokerFixture& fixture) {
    fixture.client().send(start_request());
}

int run_fake_worker(std::string_view mode) {
    using namespace vauth::uv;

    VerifierSocket socket(VERIFIER_SOCKET_FD);
    VerifierConversationState state = VerifierAwaitingStart{};
    VerifierMessage incoming = socket.receive();
    state = advance_verifier_conversation(
        state,
        VerifierMessageSender::daemon,
        incoming
    );
    if(!std::holds_alternative<StartVerification>(incoming))
        return 10;

    auto send = [&](VerifierMessage message) {
        socket.send(message);
        state = advance_verifier_conversation(
            state,
            VerifierMessageSender::pam_verifier,
            message
        );
    };

    send(VerificationStatus{
        VerificationStatusKind::information,
        "worker-pid=" + std::to_string(getpid())
    });

    if(mode == "success") {
        send(VerificationComplete{VerificationResult::success});
        return 0;
    }
    if(mode == "exit-without-completion")
        return 0;
    if(mode == "secret") {
        send(SecretRequired{"Password:"});
        incoming = socket.receive();
        state = advance_verifier_conversation(
            state,
            VerifierMessageSender::daemon,
            incoming
        );
        if(std::holds_alternative<CancelVerification>(incoming))
            return 1;
        if(!std::holds_alternative<SecretResponse>(incoming))
            return 11;
        send(VerificationComplete{VerificationResult::success});
        return 0;
    }
    if(mode == "blocked") {
        incoming = socket.receive();
        state = advance_verifier_conversation(
            state,
            VerifierMessageSender::daemon,
            incoming
        );
        return std::holds_alternative<CancelVerification>(incoming) ? 1 : 12;
    }
    return 13;
}

bool test_cancellation_while_worker_is_blocked(const std::string& executable) {
    BrokerFixture broker(executable, "blocked", TEST_TIMEOUT);
    send_start(broker);
    const pid_t child = worker_pid(receive_with_timeout(broker.client()));

    broker.client().send(vauth::uv::CancelVerification{});

    CHECK(broker.completed_successfully());
    CHECK(child_was_reaped(child));
    return true;
}

bool test_cancellation_while_secret_is_requested(
    const std::string& executable
) {
    BrokerFixture broker(executable, "secret", TEST_TIMEOUT);
    send_start(broker);
    const pid_t child = worker_pid(receive_with_timeout(broker.client()));
    CHECK(std::holds_alternative<vauth::uv::SecretRequired>(
        receive_with_timeout(broker.client())
    ));

    broker.client().send(vauth::uv::CancelVerification{});

    CHECK(broker.completed_successfully());
    CHECK(child_was_reaped(child));
    return true;
}

bool test_timeout_reaps_worker(const std::string& executable) {
    BrokerFixture broker(
        executable,
        "blocked",
        std::chrono::milliseconds(60)
    );
    send_start(broker);
    const pid_t child = worker_pid(receive_with_timeout(broker.client()));

    CHECK(broker.failed_with<UserActionTimedOut>());
    CHECK(child_was_reaped(child));
    return true;
}

bool test_disconnect_reaps_worker(const std::string& executable) {
    BrokerFixture broker(executable, "blocked", TEST_TIMEOUT);
    send_start(broker);
    const pid_t child = worker_pid(receive_with_timeout(broker.client()));

    broker.disconnect();

    CHECK(broker.failed_with<vauth::uv::VerifierSocketError>());
    CHECK(child_was_reaped(child));
    return true;
}

bool test_out_of_order_daemon_message_reaps_worker(
    const std::string& executable
) {
    BrokerFixture broker(executable, "blocked", TEST_TIMEOUT);
    send_start(broker);
    const pid_t child = worker_pid(receive_with_timeout(broker.client()));

    broker.client().send(vauth::uv::SecretResponse{
        .secret = vauth::uv::SensitiveBytes{}
    });

    CHECK(broker.failed_with<vauth::uv::VerifierConversationError>());
    CHECK(child_was_reaped(child));
    return true;
}

bool test_secret_callback_failure_reaps_worker(
    const std::string& executable
) {
    BrokerFixture broker(executable, "secret", TEST_TIMEOUT);
    send_start(broker);
    const pid_t child = worker_pid(receive_with_timeout(broker.client()));
    CHECK(std::holds_alternative<vauth::uv::SecretRequired>(
        receive_with_timeout(broker.client())
    ));

    broker.client().send(vauth::uv::VerificationStatus{
        vauth::uv::VerificationStatusKind::information,
        "not a secret response"
    });

    CHECK(broker.failed_with<vauth::uv::VerifierConversationError>());
    CHECK(child_was_reaped(child));
    return true;
}

bool test_worker_exit_without_completion_is_rejected(
    const std::string& executable
) {
    BrokerFixture broker(
        executable,
        "exit-without-completion",
        TEST_TIMEOUT
    );
    send_start(broker);
    const pid_t child = worker_pid(receive_with_timeout(broker.client()));

    CHECK(broker.failed_with<std::runtime_error>());
    CHECK(child_was_reaped(child));
    return true;
}

bool test_malformed_initial_packet_is_rejected(const std::string& executable) {
    BrokerFixture broker(executable, "blocked", TEST_TIMEOUT);
    constexpr std::array<uint8_t, 2> malformed{
        vauth::uv::VERIFIER_PROTOCOL_VERSION,
        0xff
    };
    CHECK(send(
        broker.client().native_handle(),
        malformed.data(),
        malformed.size(),
        MSG_NOSIGNAL
    ) == static_cast<ssize_t>(malformed.size()));

    CHECK(broker.failed_with<vauth::uv::VerifierProtocolError>());
    return true;
}

bool test_session_is_revalidated_after_success(
    const std::string& executable
) {
    std::size_t query_count = 0;
    BrokerFixture broker(
        executable,
        "success",
        TEST_TIMEOUT,
        [&query_count](const std::string&) {
            auto session = active_session();
            if(++query_count == 2)
                session.active = false;
            return session;
        }
    );
    send_start(broker);
    const pid_t child = worker_pid(receive_with_timeout(broker.client()));
    const auto completion = receive_with_timeout(broker.client());
    const auto* complete =
        std::get_if<vauth::uv::VerificationComplete>(&completion);

    CHECK(complete != nullptr);
    CHECK(complete->result == vauth::uv::VerificationResult::error);
    CHECK(broker.failed_with<std::runtime_error>());
    CHECK(query_count == 2);
    CHECK(child_was_reaped(child));
    return true;
}

} // namespace

int main(int argc, char** argv) {
    if(
        argc >= 4 &&
        std::string_view(argv[1]) == VAUTH_AUTH_HANDLER_COMMAND
    ) {
        try {
            return run_fake_worker(argv[3]);
        } catch(...) {
            return 20;
        }
    }

    if(argc != 1) {
        std::cerr << "Unexpected broker test arguments\n";
        return 2;
    }

    const std::string executable = std::filesystem::canonical(argv[0]);
    test_support::Runner runner;
    runner.run("cancellation while worker is blocked", [&] {
        return test_cancellation_while_worker_is_blocked(executable);
    });
    runner.run("cancellation while secret is requested", [&] {
        return test_cancellation_while_secret_is_requested(executable);
    });
    runner.run("timeout reaps worker", [&] {
        return test_timeout_reaps_worker(executable);
    });
    runner.run("disconnect reaps worker", [&] {
        return test_disconnect_reaps_worker(executable);
    });
    runner.run("out-of-order daemon message reaps worker", [&] {
        return test_out_of_order_daemon_message_reaps_worker(executable);
    });
    runner.run("secret callback failure reaps worker", [&] {
        return test_secret_callback_failure_reaps_worker(executable);
    });
    runner.run("worker exit without completion is rejected", [&] {
        return test_worker_exit_without_completion_is_rejected(executable);
    });
    runner.run("malformed initial packet is rejected", [&] {
        return test_malformed_initial_packet_is_rejected(executable);
    });
    runner.run("session is revalidated after success", [&] {
        return test_session_is_revalidated_after_success(executable);
    });
    return runner.finish();
}
