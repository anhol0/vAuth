#pragma once

#include "verifier_protocol.hpp"

#include <stdexcept>

namespace vauth::uv {

inline constexpr int VERIFIER_SOCKET_FD = 3;

class VerifierSocketError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// Owns one connected AF_UNIX SOCK_SEQPACKET descriptor. Construction adopts
// the descriptor, including when validation subsequently fails.
class VerifierSocket {
public:
    explicit VerifierSocket(int fd);
    ~VerifierSocket();

    VerifierSocket(const VerifierSocket&) = delete;
    VerifierSocket& operator=(const VerifierSocket&) = delete;

    VerifierSocket(VerifierSocket&& other) noexcept;
    VerifierSocket& operator=(VerifierSocket&& other) noexcept;

    void send(const VerifierMessage& message);
    [[nodiscard]] VerifierMessage receive();

    [[nodiscard]] int native_handle() const noexcept;

private:
    int fd_ = -1;
};

}
