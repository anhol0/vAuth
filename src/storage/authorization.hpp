#pragma once

#include <array>
#include <fcntl.h>
#include <filesystem>
#include <optional>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>

constexpr const char *CREDENTIAL_NAME = "vauth-db-auth";

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

class StoreAuthorization {
  public:
    explicit StoreAuthorization(std::filesystem::path &&path);
    ~StoreAuthorization();

    StoreAuthorization(const StoreAuthorization &) = delete;
    StoreAuthorization operator=(const StoreAuthorization &) = delete;
    StoreAuthorization(const StoreAuthorization &&) = delete;
    StoreAuthorization operator=(const StoreAuthorization &&) = delete;

    [[nodiscard]] std::string_view view() const noexcept;

  private:
    void read_authorization(const std::filesystem::path &path);
    std::array<char, 34> bytes_{};
    std::size_t size_ = 0;
};

[[nodiscard]] std::filesystem::path store_authorization_path(
    const std::optional<std::filesystem::path> &explicit_path);
