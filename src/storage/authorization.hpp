#pragma once

#include <array>
#include <filesystem>
#include <optional>
#include <string_view>

constexpr const char *CREDENTIAL_NAME = "vauth-db-auth";

class StoreAuthorization {
  public:
    explicit StoreAuthorization(const std::filesystem::path &path);
    ~StoreAuthorization();

    StoreAuthorization(const StoreAuthorization &) = delete;
    StoreAuthorization operator=(const StoreAuthorization &) = delete;
    StoreAuthorization(StoreAuthorization &&) = delete;
    StoreAuthorization operator=(StoreAuthorization &&) = delete;

    [[nodiscard]] std::string_view view() const noexcept;

  private:
    void read_authorization(const std::filesystem::path &path);
    std::array<char, 34> bytes_{};
    std::size_t size_ = 0;
};

[[nodiscard]] std::filesystem::path store_authorization_path(
    const std::optional<std::filesystem::path> &explicit_path);
