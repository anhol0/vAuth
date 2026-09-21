#include "cancellation.hpp"
#include "test_runner.hpp"
#include "uv/src/verifier_client.hpp"
#include "uv/src/verifier_socket.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <sys/un.h>
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

class UniqueFd {
public:
    explicit UniqueFd(int fd = -1) noexcept : fd_(fd) {}
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

    [[nodiscard]] int get() const noexcept { return fd_; }

private:
    int fd_;
};

union UnixSocketAddress {
    sockaddr base;
    sockaddr_un local;
};

class TestListener {
public:
    TestListener() {
        std::array<char, 64> path_template{};
        constexpr std::string_view pattern =
            "/tmp/vauth-verifier-client-XXXXXX";
        std::ranges::copy(pattern, path_template.begin());
        const int temporary = mkstemp(path_template.data());
        if(temporary < 0)
            throw std::runtime_error("create verifier test path");
        static_cast<void>(close(temporary));
        path_ = path_template.data();
        if(unlink(path_.c_str()) != 0)
            throw std::runtime_error("prepare verifier test path");

        descriptor_ = UniqueFd(socket(
            AF_UNIX,
            SOCK_SEQPACKET | SOCK_CLOEXEC,
            0
        ));
        if(descriptor_.get() < 0)
            throw std::runtime_error("create verifier test listener");

        const std::string native_path = path_.string();
        UnixSocketAddress address{};
        address.local.sun_family = AF_UNIX;
        if(native_path.size() >= sizeof(address.local.sun_path))
            throw std::runtime_error("verifier test path is too long");
        std::memcpy(
            address.local.sun_path,
            native_path.c_str(),
            native_path.size() + 1
        );
        const auto size = static_cast<socklen_t>(
            offsetof(sockaddr_un, sun_path) + native_path.size() + 1
        );
        if(bind(descriptor_.get(), &address.base, size) != 0)
            throw std::runtime_error("bind verifier test listener");
        if(listen(descriptor_.get(), 1) != 0)
            throw std::runtime_error("listen on verifier test socket");
    }

    ~TestListener() {
        if(!path_.empty())
            static_cast<void>(unlink(path_.c_str()));
    }

    [[nodiscard]] const std::filesystem::path& path() const noexcept {
        return path_;
    }

    [[nodiscard]] vauth::uv::VerifierSocket accept_connection() const {
        int accepted;
        do {
            accepted = accept4(descriptor_.get(), nullptr, nullptr, SOCK_CLOEXEC);
        } while(accepted < 0 && errno == EINTR);
        if(accepted < 0)
            throw std::runtime_error("accept verifier test connection");
        return vauth::uv::VerifierSocket(accepted);
    }

private:
    std::filesystem::path path_;
    UniqueFd descriptor_;
};

vauth::uv::SensitiveBytes secret(std::string_view text) {
    vauth::uv::SensitiveBytes result(text.size());
    std::ranges::copy(text, result.writable_bytes().begin());
    return result;
}

bool test_complete_exchange() {
    using namespace vauth::uv;
    TestListener listener;
    std::atomic<bool> server_ok = false;
    std::jthread server([&] {
        try {
            VerifierSocket socket = listener.accept_connection();
            const VerifierMessage start_message = socket.receive();
            const auto* start = std::get_if<StartVerification>(&start_message);
            if(
                start == nullptr ||
                start->targetUid != 1000 ||
                start->sessionId != "session-2"
            ) {
                return;
            }
            socket.send(VerificationStatus{
                VerificationStatusKind::information,
                "Touch the security device"
            });
            socket.send(SecretRequired{"Password:"});
            VerifierMessage response = socket.receive();
            auto* supplied = std::get_if<SecretResponse>(&response);
            if(supplied == nullptr || supplied->secret.size() != 6)
                return;
            socket.send(VerificationComplete{VerificationResult::success});
            server_ok = true;
        } catch(...) {
        }
    });

    std::string status_message;
    std::string prompt;
    const auto result = run_verifier_service(
        listener.path(),
        StartVerification{1000, "session-2"},
        {},
        std::chrono::seconds(1),
        [&status_message](const VerificationStatus& status) {
            status_message = status.message;
        },
        [&prompt](const SecretRequired& required) {
            prompt = required.prompt;
            return secret("secret");
        }
    );
    server.join();

    CHECK(result == VerificationResult::success);
    CHECK(status_message == "Touch the security device");
    CHECK(prompt == "Password:");
    CHECK(server_ok);
    return true;
}

bool test_client_cancellation_is_forwarded() {
    using namespace vauth::uv;
    TestListener listener;
    std::atomic<bool> saw_cancel = false;
    std::jthread server([&] {
        try {
            VerifierSocket socket = listener.accept_connection();
            static_cast<void>(socket.receive());
            socket.send(VerificationStatus{
                VerificationStatusKind::information,
                "Waiting"
            });
            saw_cancel = std::holds_alternative<CancelVerification>(
                socket.receive()
            );
        } catch(...) {
        }
    });

    std::atomic<bool> cancel = false;
    bool cancelled = false;
    try {
        static_cast<void>(run_verifier_service(
            listener.path(),
            StartVerification{1000, "session-2"},
            {},
            std::chrono::seconds(1),
            [&cancel](const VerificationStatus&) { cancel = true; },
            [](const SecretRequired&) { return SensitiveBytes{}; },
            [&cancel] { return cancel.load(); }
        ));
    } catch(const UserInteractionCancelled&) {
        cancelled = true;
    }
    server.join();

    CHECK(cancelled);
    CHECK(saw_cancel);
    return true;
}

bool test_timeout_is_forwarded() {
    using namespace vauth::uv;
    TestListener listener;
    std::atomic<bool> saw_cancel = false;
    std::jthread server([&] {
        try {
            VerifierSocket socket = listener.accept_connection();
            static_cast<void>(socket.receive());
            saw_cancel = std::holds_alternative<CancelVerification>(
                socket.receive()
            );
        } catch(...) {
        }
    });

    bool timed_out = false;
    try {
        static_cast<void>(run_verifier_service(
            listener.path(),
            StartVerification{1000, "session-2"},
            {},
            std::chrono::milliseconds(30),
            {},
            [](const SecretRequired&) { return SensitiveBytes{}; }
        ));
    } catch(const UserActionTimedOut&) {
        timed_out = true;
    }
    server.join();

    CHECK(timed_out);
    CHECK(saw_cancel);
    return true;
}

}

int main() {
    test_support::Runner runner;
    runner.run("complete verifier service exchange", test_complete_exchange);
    runner.run(
        "client cancellation is forwarded",
        test_client_cancellation_is_forwarded
    );
    runner.run("timeout is forwarded", test_timeout_is_forwarded);
    return runner.finish();
}
