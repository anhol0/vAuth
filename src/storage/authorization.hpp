#pragma once

#include <array>
#include <filesystem>
#include <optional>
#include <string_view>

constexpr const char *CREDENTIAL_NAME = "vauth-db-auth";

enum class StoreAuthorizationOrigin {
    explicit_file,
    systemd_credential,
};

struct StoreAuthorizationInput {
    std::filesystem::path path;
    StoreAuthorizationOrigin origin = StoreAuthorizationOrigin::explicit_file;
};

class StoreAuthorization {
  public:
    explicit StoreAuthorization(const std::filesystem::path &path);
    explicit StoreAuthorization(const StoreAuthorizationInput &input);
    ~StoreAuthorization();

    StoreAuthorization(const StoreAuthorization &) = delete;
    StoreAuthorization operator=(const StoreAuthorization &) = delete;
    StoreAuthorization(StoreAuthorization &&) = delete;
    StoreAuthorization operator=(StoreAuthorization &&) = delete;

    [[nodiscard]] std::string_view view() const noexcept;

  private:
    void read_authorization(const StoreAuthorizationInput &input);
    std::array<char, 34> bytes_{};
    std::size_t size_ = 0;
};

[[nodiscard]] StoreAuthorizationInput store_authorization_path(
    const std::optional<std::filesystem::path> &explicit_path);
