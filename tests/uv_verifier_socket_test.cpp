#include "test_runner.hpp"
#include "uv/src/verifier_socket.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <fcntl.h>
#include <iostream>
#include <span>
#include <stdexcept>
#include <string>
#include <system_error>
#include <sys/socket.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace {

#define CHECK(condition) do { \
    if(!(condition)) { \
        std::cerr << "CHECK failed at " << __FILE__ << ':' << __LINE__ \
                  << ": " #condition "\n"; \
        return false; \
    } \
} while(false)

class TestFd {
public:
    TestFd() = default;
    explicit TestFd(int fd) noexcept : fd_(fd) {}

    ~TestFd() {
        reset();
    }

    TestFd(const TestFd&) = delete;
    TestFd& operator=(const TestFd&) = delete;

    TestFd(TestFd&& other) noexcept
        : fd_(std::exchange(other.fd_, -1)) {}

    TestFd& operator=(TestFd&& other) noexcept {
        if(this != &other) {
            reset();
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

    void reset() noexcept {
        if(fd_ >= 0)
            static_cast<void>(close(fd_));
        fd_ = -1;
    }

private:
    int fd_ = -1;
};

struct SocketPair {
    TestFd first;
    TestFd second;
};

SocketPair make_socket_pair(int type = SOCK_SEQPACKET) {
    std::array<int, 2> descriptors{-1, -1};
    if(socketpair(AF_UNIX, type | SOCK_CLOEXEC, 0, descriptors.data()) != 0) {
        throw std::system_error(
            errno,
            std::generic_category(),
            "socketpair"
        );
    }
    return {
        .first = TestFd(descriptors[0]),
        .second = TestFd(descriptors[1])
    };
}

template<typename Exception, typename Function>
bool throws_as(Function&& function) {
    try {
        std::forward<Function>(function)();
    } catch(const Exception&) {
        return true;
    } catch(...) {
        return false;
    }
    return false;
}

bool send_raw(int fd, std::span<const uint8_t> packet) {
    ssize_t count;
    do {
        count = ::send(fd, packet.data(), packet.size(), MSG_NOSIGNAL);
    } while(count < 0 && errno == EINTR);
    return count >= 0 && static_cast<std::size_t>(count) == packet.size();
}

vauth::uv::VerifierMessage secret_message(std::size_t size) {
    vauth::uv::SensitiveBytes secret(size);
    std::fill(
        secret.writable_bytes().begin(),
        secret.writable_bytes().end(),
        static_cast<uint8_t>('s')
    );
    return vauth::uv::SecretResponse{.secret = std::move(secret)};
}

bool test_every_message_type_round_trips_bidirectionally() {
    using namespace vauth::uv;
    auto pair = make_socket_pair();
    VerifierSocket daemon(pair.first.release());
    VerifierSocket verifier(pair.second.release());

    daemon.send(StartVerification{1000, "c2"});
    auto received = verifier.receive();
    const StartVerification expected_start{1000, "c2"};
    CHECK(std::get<StartVerification>(received) == expected_start);

    verifier.send(VerificationStatus{
        VerificationStatusKind::information,
        "Touch the security device"
    });
    received = daemon.receive();
    const VerificationStatus expected_status{
        VerificationStatusKind::information,
        "Touch the security device"
    };
    CHECK(
        std::get<VerificationStatus>(received) ==
        expected_status
    );

    verifier.send(SecretRequired{"Password:"});
    received = daemon.receive();
    CHECK(std::get<SecretRequired>(received) == SecretRequired{"Password:"});

    daemon.send(secret_message(6));
    received = verifier.receive();
    CHECK(std::get<SecretResponse>(received).secret.size() == 6);

    daemon.send(CancelVerification{});
    CHECK(std::holds_alternative<CancelVerification>(verifier.receive()));

    verifier.send(VerificationComplete{VerificationResult::denied});
    received = daemon.receive();
    CHECK(
        std::get<VerificationComplete>(received) ==
        VerificationComplete{VerificationResult::denied}
    );
    return true;
}

bool test_packet_boundaries_and_order_are_preserved() {
    using namespace vauth::uv;
    auto pair = make_socket_pair();
    VerifierSocket sender(pair.first.release());
    VerifierSocket receiver(pair.second.release());

    sender.send(VerificationStatus{
        VerificationStatusKind::information,
        "first"
    });
    sender.send(SecretRequired{"second"});
    sender.send(VerificationComplete{VerificationResult::success});

    const auto first = receiver.receive();
    const auto second = receiver.receive();
    const auto third = receiver.receive();
    CHECK(std::get<VerificationStatus>(first).message == "first");
    CHECK(std::get<SecretRequired>(second).prompt == "second");
    CHECK(
        std::get<VerificationComplete>(third).result ==
        VerificationResult::success
    );
    return true;
}

bool test_peer_credentials_come_from_the_kernel() {
    using namespace vauth::uv;
    auto pair = make_socket_pair();
    VerifierSocket socket(pair.first.release());
    const VerifierPeerCredentials peer = socket.peer_credentials();
    CHECK(peer.pid == getpid());
    CHECK(peer.uid == getuid());
    CHECK(peer.gid == getgid());
    return true;
}

bool test_maximum_sized_packets_round_trip() {
    using namespace vauth::uv;
    auto pair = make_socket_pair();
    VerifierSocket sender(pair.first.release());
    VerifierSocket receiver(pair.second.release());

    sender.send(secret_message(MAX_VERIFICATION_SECRET_SIZE));
    auto received = receiver.receive();
    CHECK(
        std::get<SecretResponse>(received).secret.size() ==
        MAX_VERIFICATION_SECRET_SIZE
    );

    const std::string text(MAX_VERIFICATION_TEXT_SIZE, 't');
    sender.send(VerificationStatus{
        VerificationStatusKind::information,
        text
    });
    received = receiver.receive();
    CHECK(std::get<VerificationStatus>(received).message == text);
    return true;
}

bool test_oversized_packet_is_rejected_as_truncated() {
    using namespace vauth::uv;
    auto pair = make_socket_pair();
    VerifierSocket receiver(pair.first.release());
    const std::vector<uint8_t> oversized(MAX_VERIFIER_PACKET_SIZE + 1, 'x');
    CHECK(send_raw(pair.second.get(), oversized));
    CHECK(throws_as<VerifierSocketError>([&] {
        static_cast<void>(receiver.receive());
    }));
    return true;
}

bool test_malformed_packet_propagates_protocol_error() {
    using namespace vauth::uv;
    auto pair = make_socket_pair();
    VerifierSocket receiver(pair.first.release());
    const std::array<uint8_t, 1> truncated_header{VERIFIER_PROTOCOL_VERSION};
    CHECK(send_raw(pair.second.get(), truncated_header));
    CHECK(throws_as<VerifierProtocolError>([&] {
        static_cast<void>(receiver.receive());
    }));
    return true;
}

bool test_empty_packet_is_rejected() {
    using namespace vauth::uv;
    auto pair = make_socket_pair();
    VerifierSocket receiver(pair.first.release());
    const std::span<const uint8_t> empty;
    CHECK(send_raw(pair.second.get(), empty));
    CHECK(throws_as<VerifierSocketError>([&] {
        static_cast<void>(receiver.receive());
    }));
    return true;
}

bool test_peer_closure_is_reported_while_receiving() {
    using namespace vauth::uv;
    auto pair = make_socket_pair();
    VerifierSocket receiver(pair.first.release());
    pair.second.reset();
    CHECK(throws_as<VerifierSocketError>([&] {
        static_cast<void>(receiver.receive());
    }));
    return true;
}

volatile std::sig_atomic_t sigpipe_count = 0;

void count_sigpipe(int) {
    sigpipe_count = 1;
}

class SigpipeHandler {
public:
    SigpipeHandler() {
        struct sigaction action{};
        action.sa_handler = count_sigpipe;
        sigemptyset(&action.sa_mask);
        if(sigaction(SIGPIPE, &action, &previous_) != 0) {
            throw std::system_error(
                errno,
                std::generic_category(),
                "sigaction"
            );
        }
    }

    ~SigpipeHandler() {
        static_cast<void>(sigaction(SIGPIPE, &previous_, nullptr));
    }

    SigpipeHandler(const SigpipeHandler&) = delete;
    SigpipeHandler& operator=(const SigpipeHandler&) = delete;

private:
    struct sigaction previous_{};
};

bool test_peer_closure_does_not_raise_sigpipe() {
    using namespace vauth::uv;
    auto pair = make_socket_pair();
    VerifierSocket sender(pair.first.release());
    pair.second.reset();
    sigpipe_count = 0;
    SigpipeHandler handler;
    CHECK(throws_as<std::system_error>([&] {
        sender.send(CancelVerification{});
    }));
    CHECK(sigpipe_count == 0);
    return true;
}

bool test_wrong_socket_type_is_rejected_and_closed() {
    using namespace vauth::uv;
    auto pair = make_socket_pair(SOCK_STREAM);
    const int adopted = pair.first.release();
    CHECK(throws_as<VerifierSocketError>([&] {
        VerifierSocket socket(adopted);
    }));
    errno = 0;
    const bool closed = fcntl(adopted, F_GETFD) < 0 && errno == EBADF;
    if(!closed)
        static_cast<void>(close(adopted));
    CHECK(closed);

    CHECK(throws_as<std::invalid_argument>([] {
        VerifierSocket socket(-1);
    }));

    const int unconnected = socket(
        AF_UNIX,
        SOCK_SEQPACKET | SOCK_CLOEXEC,
        0
    );
    if(unconnected < 0) {
        throw std::system_error(
            errno,
            std::generic_category(),
            "create unconnected verifier socket"
        );
    }
    CHECK(throws_as<VerifierSocketError>([&] {
        VerifierSocket socket(unconnected);
    }));
    errno = 0;
    const bool unconnected_closed =
        fcntl(unconnected, F_GETFD) < 0 && errno == EBADF;
    if(!unconnected_closed)
        static_cast<void>(close(unconnected));
    CHECK(unconnected_closed);
    return true;
}

bool test_move_and_descriptor_ownership() {
    using namespace vauth::uv;
    auto pair = make_socket_pair();
    TestFd adopted(pair.first.release());
    const int initial_flags = fcntl(adopted.get(), F_GETFD);
    CHECK(initial_flags >= 0);
    CHECK(fcntl(adopted.get(), F_SETFD, initial_flags & ~FD_CLOEXEC) == 0);
    VerifierSocket original(adopted.release());
    const int descriptor = original.native_handle();
    CHECK(descriptor >= 0);
    CHECK((fcntl(descriptor, F_GETFD) & FD_CLOEXEC) != 0);

    VerifierSocket moved(std::move(original));
    CHECK(original.native_handle() == -1);
    CHECK(moved.native_handle() == descriptor);

    auto replacement_pair = make_socket_pair();
    VerifierSocket replacement(replacement_pair.first.release());
    const int replaced_descriptor = replacement.native_handle();
    replacement = std::move(moved);
    CHECK(moved.native_handle() == -1);
    CHECK(replacement.native_handle() == descriptor);
    errno = 0;
    CHECK(
        fcntl(replaced_descriptor, F_GETFD) < 0 &&
        errno == EBADF
    );

    replacement.send(CancelVerification{});
    VerifierSocket peer(pair.second.release());
    CHECK(std::holds_alternative<CancelVerification>(peer.receive()));
    return true;
}

bool test_destruction_closes_descriptor() {
    using namespace vauth::uv;
    auto pair = make_socket_pair();
    const int descriptor = pair.first.release();
    {
        VerifierSocket socket(descriptor);
        CHECK(socket.native_handle() == descriptor);
    }
    errno = 0;
    CHECK(fcntl(descriptor, F_GETFD) < 0 && errno == EBADF);
    return true;
}

} // namespace

int main() {
    test_support::Runner runner;
    runner.run(
        "every message type round trips bidirectionally",
        test_every_message_type_round_trips_bidirectionally
    );
    runner.run(
        "packet boundaries and order are preserved",
        test_packet_boundaries_and_order_are_preserved
    );
    runner.run(
        "peer credentials come from the kernel",
        test_peer_credentials_come_from_the_kernel
    );
    runner.run(
        "maximum sized packets round trip",
        test_maximum_sized_packets_round_trip
    );
    runner.run(
        "oversized packet is rejected as truncated",
        test_oversized_packet_is_rejected_as_truncated
    );
    runner.run(
        "malformed packet propagates protocol error",
        test_malformed_packet_propagates_protocol_error
    );
    runner.run("empty packet is rejected", test_empty_packet_is_rejected);
    runner.run(
        "peer closure is reported while receiving",
        test_peer_closure_is_reported_while_receiving
    );
    runner.run(
        "peer closure does not raise SIGPIPE",
        test_peer_closure_does_not_raise_sigpipe
    );
    runner.run(
        "wrong socket type is rejected and closed",
        test_wrong_socket_type_is_rejected_and_closed
    );
    runner.run(
        "move and descriptor ownership",
        test_move_and_descriptor_ownership
    );
    runner.run(
        "destruction closes descriptor",
        test_destruction_closes_descriptor
    );
    return runner.finish();
}
