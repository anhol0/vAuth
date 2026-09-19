#include <sdbus-c++/sdbus-c++.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <fcntl.h>
#include <iostream>
#include <memory>
#include <mutex>
#include <span>
#include <stdexcept>
#include <string>
#include <string.h>
#include <string_view>
#include <system_error>
#include <unistd.h>
#include <utility>
#include <vector>

namespace {

constexpr char SERVICE[] = "org.lamellix.vAuth";
constexpr char PATH[] = "/org/lamellix/vAuth";
constexpr char INTERFACE[] = "org.lamellix.vAuth.UserInteraction1";

struct Event {
    uint64_t generation;
    uint64_t requestId;
    uint64_t promptId;
    std::string state;
    std::string operation;
    std::string relyingPartyId;
    std::string message;
};

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
    [[nodiscard]] int get() const noexcept { return fd_; }
    void reset() noexcept {
        if(fd_ >= 0)
            static_cast<void>(close(std::exchange(fd_, -1)));
    }

private:
    int fd_;
};

void write_all(int fd, std::span<const uint8_t> bytes) {
    std::size_t offset = 0;
    while(offset < bytes.size()) {
        const ssize_t count = write(
            fd, bytes.data() + offset, bytes.size() - offset
        );
        if(count > 0) {
            offset += static_cast<std::size_t>(count);
        } else if(count < 0 && errno == EINTR) {
            continue;
        } else {
            throw std::system_error(
                count < 0 ? errno : EIO,
                std::generic_category(),
                "write secret pipe"
            );
        }
    }
}

bool is_start(std::string_view state) {
    return state == "presence_required" || state == "verification_started";
}

bool is_terminal(std::string_view state) {
    return
        state == "presence_approved" ||
        state == "presence_denied" ||
        state == "verification_succeeded" ||
        state == "verification_failed" ||
        state == "cancelled" ||
        state == "timed_out";
}

bool is_known(std::string_view state) {
    return
        is_start(state) ||
        is_terminal(state) ||
        state == "verification_information" ||
        state == "verification_error" ||
        state == "secret_required";
}

void clear_secret(std::vector<uint8_t>& secret) noexcept {
    if(!secret.empty())
        explicit_bzero(secret.data(), secret.size());
    secret.clear();
}

class SecretClearGuard {
public:
    explicit SecretClearGuard(std::vector<uint8_t>& secret) noexcept
        : secret_(secret) {}
    ~SecretClearGuard() { clear_secret(secret_); }
    SecretClearGuard(const SecretClearGuard&) = delete;
    SecretClearGuard& operator=(const SecretClearGuard&) = delete;

private:
    std::vector<uint8_t>& secret_;
};

class Agent {
public:
    Agent()
        : connection_(sdbus::createSystemBusConnection()),
          proxy_(sdbus::createProxy(
              *connection_,
              sdbus::ServiceName{SERVICE},
              sdbus::ObjectPath{PATH}
          )) {
        stateSlot_ = proxy_->uponSignal("StateChanged")
            .onInterface(INTERFACE)
            .call(
                [this](
                    uint64_t generation,
                    uint64_t request_id,
                    uint64_t prompt_id,
                    const std::string& state,
                    const std::string& operation,
                    const std::string& relying_party_id,
                    const std::string& message
                ) {
                    std::lock_guard lock(mutex_);
                    events_.push_back({
                        generation,
                        request_id,
                        prompt_id,
                        state,
                        operation,
                        relying_party_id,
                        message
                    });
                    changed_.notify_one();
                },
                sdbus::return_slot
            );

        proxy_->callMethod("RegisterAgent")
            .onInterface(INTERFACE)
            .storeResultsTo(generation_);
        if(generation_ == 0)
            throw std::runtime_error("daemon returned generation zero");
        connection_->enterEventLoopAsync();
        std::cout << "registered generation " << generation_ << '\n';
    }

    ~Agent() {
        try {
            proxy_->callMethod("UnregisterAgent").onInterface(INTERFACE);
        } catch(...) {
        }
        try {
            connection_->leaveEventLoop();
        } catch(...) {
        }
    }

    Agent(const Agent&) = delete;
    Agent& operator=(const Agent&) = delete;

    void run() {
        while(true) {
            Event event = next_event();
            if(
                event.generation != generation_ ||
                event.requestId == 0 ||
                !is_known(event.state)
            ) {
                continue;
            }
            if(
                (event.state == "secret_required") !=
                (event.promptId != 0)
            ) {
                continue;
            }
            if(is_start(event.state)) {
                if(activeRequest_ != 0 && activeRequest_ != event.requestId)
                    continue;
                activeRequest_ = event.requestId;
            } else if(activeRequest_ != event.requestId) {
                continue;
            }

            std::cout << event.state << ": " << event.operation
                      << " for RP " << event.relyingPartyId << '\n';
            if(!event.message.empty())
                std::cout << event.message << '\n';

            if(event.state == "presence_required") {
                std::cout << "Approve? [y]es/[n]o/[c]ancel: " << std::flush;
                std::string answer;
                if(!std::getline(std::cin, answer) ||
                    (!answer.empty() && answer.front() == 'c')) {
                    cancel(event.requestId);
                } else {
                    const bool approved =
                        !answer.empty() && answer.front() == 'y';
                    respond_to_presence(event.requestId, approved);
                }
            } else if(event.state == "secret_required") {
                // A console string cannot be reliably erased. A real UI should
                // call submit_secret() with a protected mutable buffer.
                cancel(event.requestId);
            }

            if(is_terminal(event.state))
                activeRequest_ = 0;
        }
    }

    void submit_secret(
        uint64_t request_id,
        uint64_t prompt_id,
        std::vector<uint8_t>& secret
    ) {
        SecretClearGuard clearOnExit(secret);
        if(request_id == 0 || prompt_id == 0 || request_id != activeRequest_)
            throw std::runtime_error("interaction is not active");
        if(
            secret.size() > 1024 ||
            std::ranges::find(secret, uint8_t{0}) != secret.end()
        ) {
            throw std::invalid_argument(
                "secret must be at most 1024 bytes without NUL"
            );
        }

        std::array<int, 2> descriptors{};
        if(pipe2(descriptors.data(), O_CLOEXEC) != 0)
            throw std::system_error(errno, std::generic_category(), "pipe2");
        UniqueFd readEnd(descriptors[0]);
        UniqueFd writeEnd(descriptors[1]);

        write_all(writeEnd.get(), secret);
        writeEnd.reset();
        proxy_->callMethod("SubmitSecret")
            .onInterface(INTERFACE)
            .withArguments(
                generation_,
                request_id,
                prompt_id,
                sdbus::UnixFd{readEnd.get()}
            );
    }

private:
    Event next_event() {
        std::unique_lock lock(mutex_);
        changed_.wait(lock, [this] { return !events_.empty(); });
        Event event = std::move(events_.front());
        events_.pop_front();
        return event;
    }

    void respond_to_presence(uint64_t request_id, bool approved) {
        proxy_->callMethod("RespondToPresence")
            .onInterface(INTERFACE)
            .withArguments(generation_, request_id, approved);
    }

    void cancel(uint64_t request_id) {
        proxy_->callMethod("CancelInteraction")
            .onInterface(INTERFACE)
            .withArguments(generation_, request_id);
    }

    std::unique_ptr<sdbus::IConnection> connection_;
    std::unique_ptr<sdbus::IProxy> proxy_;
    sdbus::Slot stateSlot_;
    uint64_t generation_ = 0;
    uint64_t activeRequest_ = 0;
    std::mutex mutex_;
    std::condition_variable changed_;
    std::deque<Event> events_;
};

} // namespace

int main() {
    try {
        Agent agent;
        agent.run();
    } catch(const std::exception& error) {
        std::cerr << "vAuth agent example: " << error.what() << '\n';
        return 1;
    }
}
