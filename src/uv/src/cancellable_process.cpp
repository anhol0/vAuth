#include "cancellable_process.hpp"

#include "cancellation.hpp"
#include "verifier_conversation.hpp"
#include "verifier_socket.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <fcntl.h>
#include <mutex>
#include <optional>
#include <poll.h>
#include <spawn.h>
#include <stdexcept>
#include <system_error>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

extern char** environ;

namespace vauth::uv {
namespace {

class UniqueFd {
public:
    UniqueFd() = default;
    explicit UniqueFd(int fd) noexcept : fd_(fd) {}

    ~UniqueFd() {
        if(fd_ >= 0)
            static_cast<void>(close(fd_));
    }

    UniqueFd(const UniqueFd&) = delete;
    UniqueFd& operator=(const UniqueFd&) = delete;

    UniqueFd(UniqueFd&& other) noexcept
        : fd_(std::exchange(other.fd_, -1)) {}

    UniqueFd& operator=(UniqueFd&& other) noexcept {
        if(this != &other) {
            if(fd_ >= 0)
                static_cast<void>(close(fd_));
            fd_ = std::exchange(other.fd_, -1);
        }
        return *this;
    }

    [[nodiscard]] int get() const noexcept {
        return fd_;
    }

    [[nodiscard]] int release() noexcept {
        return std::exchange(fd_, -1);
    }

    void reset(int fd = -1) noexcept {
        UniqueFd replacement(fd);
        *this = std::move(replacement);
    }

private:
    int fd_ = -1;
};

struct SocketPair {
    UniqueFd daemon;
    UniqueFd verifier;
};

SocketPair make_verifier_socket_pair() {
    std::array<int, 2> descriptors{-1, -1};
    if(
        socketpair(
            AF_UNIX,
            SOCK_SEQPACKET | SOCK_CLOEXEC,
            0,
            descriptors.data()
        ) != 0
    ) {
        throw std::system_error(
            errno,
            std::generic_category(),
            "create verifier socket pair"
        );
    }
    return {
        .daemon = UniqueFd(descriptors[0]),
        .verifier = UniqueFd(descriptors[1])
    };
}

void move_above_auth_descriptors(UniqueFd& descriptor) {
    if(
        descriptor.get() == VERIFIER_SOCKET_FD ||
        descriptor.get() == VERIFIER_SOCKET_FD + 1
    ) {
        const int duplicate = fcntl(
            descriptor.get(),
            F_DUPFD_CLOEXEC,
            VERIFIER_SOCKET_FD + 2
        );
        if(duplicate < 0) {
            throw std::system_error(
                errno,
                std::generic_category(),
                "duplicate authentication pipe descriptor"
            );
        }
        descriptor.reset(duplicate);
    }
}

class SpawnAttributes {
public:
    SpawnAttributes() {
        const int rc = posix_spawnattr_init(&attributes_);
        if(rc != 0)
            throw std::system_error(rc, std::generic_category(), "posix_spawnattr_init");
    }

    ~SpawnAttributes() {
        posix_spawnattr_destroy(&attributes_);
    }

    SpawnAttributes(const SpawnAttributes&) = delete;
    SpawnAttributes& operator=(const SpawnAttributes&) = delete;

    posix_spawnattr_t* get() noexcept {
        return &attributes_;
    }

private:
    posix_spawnattr_t attributes_{};
};

class SpawnFileActions {
public:
    explicit SpawnFileActions(int verifier_fd = -1) {
        int rc = posix_spawn_file_actions_init(&actions_);
        if(rc != 0)
            throw std::system_error(rc, std::generic_category(), "posix_spawn_file_actions_init");

        if(verifier_fd >= 0) {
            rc = posix_spawn_file_actions_adddup2(
                &actions_,
                verifier_fd,
                VERIFIER_SOCKET_FD
            );
            if(rc != 0) {
                posix_spawn_file_actions_destroy(&actions_);
                throw std::system_error(
                    rc,
                    std::generic_category(),
                    "posix_spawn_file_actions_adddup2"
                );
            }
        }

        int close_from = STDERR_FILENO + 1;
        if(verifier_fd >= 0)
            close_from = VERIFIER_SOCKET_FD + 1;
        rc = posix_spawn_file_actions_addclosefrom_np(
            &actions_,
            close_from
        );
        if(rc != 0) {
            posix_spawn_file_actions_destroy(&actions_);
            throw std::system_error(rc, std::generic_category(), "posix_spawn_file_actions_addclosefrom_np");
        }
    }

    ~SpawnFileActions() {
        posix_spawn_file_actions_destroy(&actions_);
    }

    SpawnFileActions(const SpawnFileActions&) = delete;
    SpawnFileActions& operator=(const SpawnFileActions&) = delete;

    posix_spawn_file_actions_t* get() noexcept {
        return &actions_;
    }

private:
    posix_spawn_file_actions_t actions_{};
};

class ChildProcess {
public:
    explicit ChildProcess(pid_t pid) noexcept : pid_(pid) {}

    ~ChildProcess() {
        terminate_and_reap();
    }

    ChildProcess(const ChildProcess&) = delete;
    ChildProcess& operator=(const ChildProcess&) = delete;

    std::optional<int> poll() {
        int status = 0;
        const pid_t result = waitpid(pid_, &status, WNOHANG);
        if(result == 0)
            return std::nullopt;
        if(result < 0) {
            if(errno == EINTR)
                return std::nullopt;
            throw std::system_error(errno, std::generic_category(), "waitpid");
        }

        pid_ = -1;
        if(WIFEXITED(status))
            return WEXITSTATUS(status);
        if(WIFSIGNALED(status))
            throw std::runtime_error("child process terminated by signal");
        throw std::runtime_error("child process returned an invalid status");
    }

    void terminate_and_reap() noexcept {
        if(pid_ <= 0)
            return;

        // pam_fprintd handles SIGINT and uses its normal return path to stop
        // verification and release the claimed device. Preserve that cleanup
        // opportunity before escalating to signals that bypass destructors.
        static_cast<void>(kill(-pid_, SIGINT));
        if(wait_for_exit(std::chrono::seconds(2)))
            return;

        static_cast<void>(kill(-pid_, SIGTERM));
        if(wait_for_exit(std::chrono::milliseconds(500)))
            return;

        int status = 0;
        static_cast<void>(kill(-pid_, SIGKILL));
        while(waitpid(pid_, &status, 0) < 0 && errno == EINTR) {}
        pid_ = -1;
    }

private:
    bool wait_for_exit(std::chrono::steady_clock::duration grace) noexcept {
        constexpr auto poll_interval = std::chrono::milliseconds(5);
        const auto deadline = std::chrono::steady_clock::now() + grace;
        int status = 0;
        while(std::chrono::steady_clock::now() < deadline) {
            const pid_t result = waitpid(pid_, &status, WNOHANG);
            if(result == pid_ || (result < 0 && errno == ECHILD)) {
                pid_ = -1;
                return true;
            }
            if(result < 0 && errno != EINTR)
                return false;
            std::this_thread::sleep_for(poll_interval);
        }
        return false;
    }

    pid_t pid_;
};

pid_t spawn_program(
    const std::string& path,
    const std::vector<std::string>& arguments,
    int verifier_fd = -1
) {
    std::vector<char*> argv;
    argv.reserve(arguments.size() + 2);
    argv.push_back(const_cast<char*>(path.c_str()));
    for(const std::string& argument : arguments)
        argv.push_back(const_cast<char*>(argument.c_str()));
    argv.push_back(nullptr);

    SpawnAttributes attributes;
    SpawnFileActions file_actions(verifier_fd);
    int rc = posix_spawnattr_setpgroup(attributes.get(), 0);
    if(rc != 0) {
        throw std::system_error(
            rc,
            std::generic_category(),
            "posix_spawnattr_setpgroup"
        );
    }

    sigset_t child_mask;
    if(sigemptyset(&child_mask) != 0)
        throw std::system_error(errno, std::generic_category(), "sigemptyset");
    rc = posix_spawnattr_setsigmask(attributes.get(), &child_mask);
    if(rc != 0) {
        throw std::system_error(
            rc,
            std::generic_category(),
            "posix_spawnattr_setsigmask"
        );
    }

    sigset_t child_defaults;
    if(
        sigemptyset(&child_defaults) != 0 ||
        sigaddset(&child_defaults, SIGINT) != 0 ||
        sigaddset(&child_defaults, SIGTERM) != 0
    ) {
        throw std::system_error(
            errno,
            std::generic_category(),
            "prepare child signals"
        );
    }
    rc = posix_spawnattr_setsigdefault(attributes.get(), &child_defaults);
    if(rc != 0) {
        throw std::system_error(
            rc,
            std::generic_category(),
            "posix_spawnattr_setsigdefault"
        );
    }

    constexpr short spawn_flags =
        POSIX_SPAWN_SETPGROUP |
        POSIX_SPAWN_SETSIGMASK |
        POSIX_SPAWN_SETSIGDEF;
    rc = posix_spawnattr_setflags(attributes.get(), spawn_flags);
    if(rc != 0) {
        throw std::system_error(
            rc,
            std::generic_category(),
            "posix_spawnattr_setflags"
        );
    }

    pid_t pid = -1;
    rc = posix_spawn(
        &pid,
        path.c_str(),
        file_actions.get(),
        attributes.get(),
        argv.data(),
        environ
    );
    if(rc != 0)
        throw std::system_error(rc, std::generic_category(), "posix_spawn");
    return pid;
}

}

void arm_parent_death_signal(pid_t expected_parent) {
    if(expected_parent <= 1)
        throw std::invalid_argument("invalid authentication parent process");
    if(prctl(PR_SET_PDEATHSIG, SIGINT) != 0) {
        throw std::system_error(
            errno,
            std::generic_category(),
            "prctl PR_SET_PDEATHSIG"
        );
    }
    if(getppid() != expected_parent) {
        static_cast<void>(prctl(PR_SET_PDEATHSIG, 0));
        throw std::runtime_error("authentication parent process exited");
    }
}

int run_cancellable_program(
    const std::string& path,
    const std::vector<std::string>& arguments,
    std::stop_token stop,
    std::chrono::steady_clock::duration timeout,
    const std::function<bool()>& cancellation_requested
) {
    cancellation_point(stop);
    if(cancellation_requested && cancellation_requested())
        throw UserInteractionCancelled{};
    if(path.empty())
        throw std::invalid_argument("child program path is empty");
    if(timeout <= std::chrono::steady_clock::duration::zero())
        throw std::invalid_argument("child program timeout must be positive");

    const auto deadline = std::chrono::steady_clock::now() + timeout;

    ChildProcess child(spawn_program(path, arguments));
    std::mutex wait_mutex;
    std::condition_variable wait_condition;
    std::stop_callback wake_on_cancel(stop, [&wait_condition] {
        wait_condition.notify_all();
    });
    std::unique_lock wait_lock(wait_mutex);

    while(true) {
        if(stop.stop_requested()) {
            child.terminate_and_reap();
            throw OperationCancelled{};
        }
        if(cancellation_requested && cancellation_requested()) {
            child.terminate_and_reap();
            throw UserInteractionCancelled{};
        }
        if(const auto status = child.poll())
            return *status;

        const auto now = std::chrono::steady_clock::now();
        if(now >= deadline) {
            child.terminate_and_reap();
            throw UserActionTimedOut{};
        }

        wait_condition.wait_until(
            wait_lock,
            std::min(
                deadline,
                now + std::chrono::milliseconds(20)
            ),
            [stop] { return stop.stop_requested(); }
        );
    }
}

VerificationResult run_cancellable_verifier_program(
    const std::string& path,
    const std::vector<std::string>& arguments,
    StartVerification start,
    std::stop_token stop,
    std::chrono::steady_clock::duration timeout,
    const std::function<void(const VerificationStatus&)>& status_callback,
    const std::function<SensitiveBytes(const SecretRequired&)>& secret_callback,
    const std::function<bool()>& cancellation_requested
) {
    cancellation_point(stop);
    if(cancellation_requested && cancellation_requested())
        throw UserInteractionCancelled{};
    if(path.empty())
        throw std::invalid_argument("child program path is empty");
    if(timeout <= std::chrono::steady_clock::duration::zero())
        throw std::invalid_argument("child program timeout must be positive");
    if(!secret_callback)
        throw std::invalid_argument("verifier secret callback is missing");

    const auto deadline = std::chrono::steady_clock::now() + timeout;
    auto sockets = make_verifier_socket_pair();
    move_above_auth_descriptors(sockets.daemon);
    move_above_auth_descriptors(sockets.verifier);
    VerifierSocket socket(sockets.daemon.release());
    ChildProcess child(spawn_program(
        path,
        arguments,
        sockets.verifier.get()
    ));
    sockets.verifier.reset();
    VerifierConversationState conversation = VerifierAwaitingStart{};
    VerifierMessage start_message = std::move(start);
    socket.send(start_message);
    conversation = advance_verifier_conversation(
        conversation,
        VerifierMessageSender::daemon,
        start_message
    );

    std::optional<VerificationResult> completion;
    auto receive_message = [&] {
        VerifierMessage message = socket.receive();
        conversation = advance_verifier_conversation(
            conversation,
            VerifierMessageSender::pam_verifier,
            message
        );
        if(const auto* status = std::get_if<VerificationStatus>(&message)) {
            if(status_callback)
                status_callback(*status);
            return;
        }
        if(const auto* required = std::get_if<SecretRequired>(&message)) {
            VerifierMessage response = SecretResponse{
                .secret = secret_callback(*required)
            };
            socket.send(response);
            conversation = advance_verifier_conversation(
                conversation,
                VerifierMessageSender::daemon,
                response
            );
            return;
        }
        if(const auto* complete = std::get_if<VerificationComplete>(&message)) {
            completion = complete->result;
            return;
        }
        throw VerifierConversationError(
            "verifier sent a daemon-only message"
        );
    };

    auto send_cancel = [&]() noexcept {
        if(verifier_conversation_is_terminal(conversation))
            return;
        try {
            VerifierMessage cancel = CancelVerification{};
            socket.send(cancel);
            conversation = advance_verifier_conversation(
                conversation,
                VerifierMessageSender::daemon,
                cancel
            );
        } catch(...) {
        }
    };

    std::mutex wait_mutex;
    std::condition_variable wait_condition;
    std::stop_callback wake_on_cancel(stop, [&wait_condition] {
        wait_condition.notify_all();
    });
    std::unique_lock wait_lock(wait_mutex);

    while(true) {
        while(!completion) {
            pollfd descriptor{
                .fd = socket.native_handle(),
                .events = POLLIN,
                .revents = 0
            };
            int poll_result;
            do {
                poll_result = poll(&descriptor, 1, 0);
            } while(poll_result < 0 && errno == EINTR);
            if(poll_result < 0) {
                throw std::system_error(
                    errno,
                    std::generic_category(),
                    "poll verifier socket"
                );
            }
            if((descriptor.revents & POLLIN) == 0)
                break;
            receive_message();
            if(completion)
                break;
        }

        if(stop.stop_requested()) {
            send_cancel();
            child.terminate_and_reap();
            throw OperationCancelled{};
        }
        if(cancellation_requested && cancellation_requested()) {
            send_cancel();
            child.terminate_and_reap();
            throw UserInteractionCancelled{};
        }
        if(const auto child_status = child.poll()) {
            if(!completion) {
                throw std::runtime_error(
                    "verifier exited without a completion message"
                );
            }
            const bool success_exit = *child_status == 0;
            const bool success_result =
                *completion == VerificationResult::success;
            if(success_exit != success_result) {
                throw std::runtime_error(
                    "verifier exit status contradicts its result"
                );
            }
            return *completion;
        }

        const auto now = std::chrono::steady_clock::now();
        if(now >= deadline) {
            send_cancel();
            child.terminate_and_reap();
            throw UserActionTimedOut{};
        }
        wait_condition.wait_until(
            wait_lock,
            std::min(deadline, now + std::chrono::milliseconds(20)),
            [stop] { return stop.stop_requested(); }
        );
    }
}

}
