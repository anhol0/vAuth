#include "authorization.hpp"
#include <fcntl.h>
#include <openssl/crypto.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {

class UniqueFd {
  public:
    explicit UniqueFd(int fd) noexcept : fd_(fd) {}
    ~UniqueFd() {
        if (fd_ >= 0) {
            ::close(fd_);
        }
    }

    UniqueFd(const UniqueFd &) = delete;
    UniqueFd &operator=(const UniqueFd &) = delete;

    [[nodiscard]] int get() const noexcept { return fd_; }

  private:
    int fd_;
};

} // namespace

void StoreAuthorization::read_authorization(
    const StoreAuthorizationInput &input
) {
    const int fd = ::open(
        input.path.c_str(),
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW
    );
    if (fd == -1) {
        throw std::system_error(errno, std::generic_category(),
                                "open database authorization credential");
    }
    UniqueFd file(fd);

    struct stat status{};
    if (::fstat(file.get(), &status) == -1) {
        throw std::system_error(errno, std::generic_category(),
                                "inspect database authorization credential");
    }
    if (!S_ISREG(status.st_mode) || status.st_nlink != 1) {
        throw std::runtime_error(
            "Database authorization credential must be a regular file with "
            "one link");
    }
    if (status.st_uid != ::geteuid() && status.st_uid != 0) {
        throw std::runtime_error(
            "Database authorization credential must be owned by root or the "
            "service user");
    }
    const mode_t mode = status.st_mode & 0777;
    const bool valid_mode = mode == 0400 || (
        input.origin == StoreAuthorizationOrigin::systemd_credential &&
        mode == 0440
    );
    if (!valid_mode) {
        throw std::runtime_error(
            input.origin == StoreAuthorizationOrigin::systemd_credential
                ? "Systemd database authorization credential must have mode "
                  "0400 or 0440"
                : "Database authorization credential must have mode 0400"
        );
    }
    if (status.st_size < 1 || status.st_size > 34) {
        throw std::runtime_error(
            "Database authorization credential has an invalid size");
    }

    size_ = static_cast<std::size_t>(status.st_size);
    std::size_t offset = 0;
    while (offset < size_) {
        const ssize_t count =
            ::read(file.get(), bytes_.data() + offset, size_ - offset);
        if (count == -1 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            throw std::runtime_error(
                "Could not read the database authorization credential");
        }
        offset += static_cast<std::size_t>(count);
    }

    if (size_ > 0 && bytes_[size_ - 1] == '\n') {
        bytes_[--size_] = '\0';
    }
    if (size_ > 0 && bytes_[size_ - 1] == '\r') {
        bytes_[--size_] = '\0';
    }
    if (size_ == 0 || size_ > 32 ||
        view().find('\0') != std::string_view::npos) {
        throw std::runtime_error(
            "Database authorization must contain 1 to 32 non-NUL bytes");
    }
}

StoreAuthorization::StoreAuthorization(const std::filesystem::path &path)
    : StoreAuthorization(StoreAuthorizationInput{
        .path = path,
        .origin = StoreAuthorizationOrigin::explicit_file,
    }) {}

StoreAuthorization::StoreAuthorization(
    const StoreAuthorizationInput &input
) {
    try {
        read_authorization(input);
    } catch (...) {
        OPENSSL_cleanse(bytes_.data(), bytes_.size());
        throw;
    }
}

StoreAuthorization::~StoreAuthorization() {
    OPENSSL_cleanse(bytes_.data(), bytes_.size());
}

[[nodiscard]] std::string_view StoreAuthorization::view() const noexcept {
    return {bytes_.data(), size_};
}

[[nodiscard]] StoreAuthorizationInput store_authorization_path(
    const std::optional<std::filesystem::path> &explicit_path) {
    if (explicit_path.has_value()) {
        return {
            .path = explicit_path.value(),
            .origin = StoreAuthorizationOrigin::explicit_file,
        };
    }

    const char *credential_directory = std::getenv("CREDENTIALS_DIRECTORY");
    if (credential_directory == nullptr || credential_directory[0] == '\0') {
        throw std::runtime_error(
            "No database authorization credential was provided; use "
            "--auth-file or the systemd vauth-db-auth credential");
    }
    return {
        .path = std::filesystem::path(credential_directory) / CREDENTIAL_NAME,
        .origin = StoreAuthorizationOrigin::systemd_credential,
    };
}
