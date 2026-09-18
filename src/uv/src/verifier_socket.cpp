#include "verifier_socket.hpp"

#include <cerrno>
#include <cstddef>
#include <fcntl.h>
#include <span>
#include <system_error>
#include <sys/socket.h>
#include <unistd.h>
#include <utility>

namespace vauth::uv {
namespace {

void close_descriptor(int& fd) noexcept {
    if(fd >= 0)
        static_cast<void>(close(fd));
    fd = -1;
}

void validate_socket(int fd) {
    const int descriptor_flags = fcntl(fd, F_GETFD);
    if(descriptor_flags < 0) {
        throw std::system_error(
            errno,
            std::generic_category(),
            "inspect verifier descriptor flags"
        );
    }
    if(
        (descriptor_flags & FD_CLOEXEC) == 0 &&
        fcntl(fd, F_SETFD, descriptor_flags | FD_CLOEXEC) != 0
    ) {
        throw std::system_error(
            errno,
            std::generic_category(),
            "set verifier descriptor close-on-exec"
        );
    }

    int type = 0;
    socklen_t type_size = sizeof(type);
    if(getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &type_size) != 0) {
        throw std::system_error(
            errno,
            std::generic_category(),
            "inspect verifier socket type"
        );
    }
    if(type != SOCK_SEQPACKET) {
        throw VerifierSocketError(
            "verifier descriptor is not a SOCK_SEQPACKET socket"
        );
    }

    sockaddr local_address{};
    socklen_t local_size = sizeof(local_address);
    if(getsockname(fd, &local_address, &local_size) != 0) {
        throw std::system_error(
            errno,
            std::generic_category(),
            "inspect verifier socket address"
        );
    }
    if(
        local_size < sizeof(local_address.sa_family) ||
        local_address.sa_family != AF_UNIX
    ) {
        throw VerifierSocketError(
            "verifier descriptor is not an AF_UNIX socket"
        );
    }

    sockaddr peer_address{};
    socklen_t peer_size = sizeof(peer_address);
    if(getpeername(fd, &peer_address, &peer_size) != 0) {
        if(errno == ENOTCONN) {
            throw VerifierSocketError(
                "verifier socket is not connected"
            );
        }
        throw std::system_error(
            errno,
            std::generic_category(),
            "inspect verifier socket peer"
        );
    }
    if(
        peer_size < sizeof(peer_address.sa_family) ||
        peer_address.sa_family != AF_UNIX
    ) {
        throw VerifierSocketError(
            "verifier peer is not an AF_UNIX socket"
        );
    }

}

void require_open(int fd) {
    if(fd < 0)
        throw VerifierSocketError("verifier socket has no descriptor");
}

}

VerifierSocket::VerifierSocket(int fd) : fd_(fd) {
    if(fd_ < 0)
        throw std::invalid_argument("verifier socket descriptor is invalid");
    try {
        validate_socket(fd_);
    } catch(...) {
        close_descriptor(fd_);
        throw;
    }
}

VerifierSocket::~VerifierSocket() {
    close_descriptor(fd_);
}

VerifierSocket::VerifierSocket(VerifierSocket&& other) noexcept
    : fd_(std::exchange(other.fd_, -1)) {}

VerifierSocket& VerifierSocket::operator=(
    VerifierSocket&& other
) noexcept {
    if(this != &other) {
        close_descriptor(fd_);
        fd_ = std::exchange(other.fd_, -1);
    }
    return *this;
}

void VerifierSocket::send(const VerifierMessage& message) {
    require_open(fd_);
    const SensitiveBytes packet = encode_verifier_message(message);

    ssize_t count;
    do {
        count = ::send(
            fd_,
            packet.bytes().data(),
            packet.size(),
            MSG_NOSIGNAL
        );
    } while(count < 0 && errno == EINTR);

    if(count < 0) {
        throw std::system_error(
            errno,
            std::generic_category(),
            "send verifier packet"
        );
    }
    if(static_cast<std::size_t>(count) != packet.size())
        throw VerifierSocketError("verifier packet was only partially sent");
}

VerifierMessage VerifierSocket::receive() {
    require_open(fd_);
    SensitiveBytes packet(MAX_VERIFIER_PACKET_SIZE);
    auto packet_bytes = packet.writable_bytes();
    iovec packet_buffer{
        .iov_base = packet_bytes.data(),
        .iov_len = packet_bytes.size()
    };
    msghdr header{};
    header.msg_iov = &packet_buffer;
    header.msg_iovlen = 1;

    ssize_t count;
    do {
        count = recvmsg(fd_, &header, 0);
    } while(count < 0 && errno == EINTR);

    if(count < 0) {
        throw std::system_error(
            errno,
            std::generic_category(),
            "receive verifier packet"
        );
    }
    if(count == 0) {
        throw VerifierSocketError(
            "verifier peer closed or sent an empty packet"
        );
    }
    if((header.msg_flags & MSG_TRUNC) != 0)
        throw VerifierSocketError("verifier packet was truncated");
    if((header.msg_flags & MSG_CTRUNC) != 0)
        throw VerifierSocketError("verifier ancillary data was truncated");

    const auto received_size = static_cast<std::size_t>(count);
    if(received_size > packet_bytes.size()) {
        throw VerifierSocketError(
            "verifier packet exceeds the receive buffer"
        );
    }
    return decode_verifier_message(std::span<const uint8_t>(
        packet_bytes.data(),
        received_size
    ));
}

int VerifierSocket::native_handle() const noexcept {
    return fd_;
}

}
