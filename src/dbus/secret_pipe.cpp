#include "secret_pipe.hpp"

#include <algorithm>
#include <cerrno>
#include <fcntl.h>
#include <stdexcept>
#include <system_error>
#include <sys/stat.h>
#include <unistd.h>

namespace vauth::dbus {

vauth::uv::SensitiveBytes read_secret_pipe(int fd) {
    if(fd < 0)
        throw std::invalid_argument("Secret pipe descriptor is invalid");

    struct stat status{};
    if(fstat(fd, &status) != 0) {
        throw std::system_error(
            errno,
            std::generic_category(),
            "inspect secret pipe"
        );
    }
    if(!S_ISFIFO(status.st_mode))
        throw std::invalid_argument("Secret descriptor is not a pipe");

    const int flags = fcntl(fd, F_GETFL);
    if(flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        throw std::system_error(
            errno,
            std::generic_category(),
            "make secret pipe nonblocking"
        );
    }

    vauth::uv::SensitiveBytes secret(vauth::uv::MAX_SECRET_SIZE + 1);
    std::size_t used = 0;
    while(true) {
        auto storage = secret.writable_bytes();
        const ssize_t count = read(
            fd,
            storage.data() + used,
            storage.size() - used
        );
        if(count > 0) {
            used += static_cast<std::size_t>(count);
            if(used > vauth::uv::MAX_SECRET_SIZE)
                throw std::invalid_argument("Secret is too long");
            continue;
        }
        if(count == 0)
            break;
        if(errno == EINTR)
            continue;
        if(errno == EAGAIN || errno == EWOULDBLOCK) {
            throw std::invalid_argument(
                "Secret pipe must be closed before submission"
            );
        }
        throw std::system_error(
            errno,
            std::generic_category(),
            "read secret pipe"
        );
    }

    secret.resize(used);
    if(std::ranges::find(secret.bytes(), uint8_t{0}) != secret.bytes().end())
        throw std::invalid_argument("Secret contains a NUL byte");
    return secret;
}

}
