#include <cerrno>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

#include "storage/authorization.hpp"
#include "test_runner.hpp"

namespace {

void check(bool condition, const char* expression, int line) {
    if(!condition) {
        throw std::runtime_error(
            "CHECK failed at line " + std::to_string(line) +
            ": " + expression
        );
    }
}

#define CHECK(expression) check((expression), #expression, __LINE__)

class TemporaryDirectory {
public:
    TemporaryDirectory() {
        auto name_template = (
            std::filesystem::temp_directory_path() /
            "vauth-authorization-test-XXXXXX"
        ).string();
        std::vector<char> writable_name(
            name_template.begin(), name_template.end()
        );
        writable_name.push_back('\0');

        const char* created = ::mkdtemp(writable_name.data());
        if(created == nullptr) {
            throw std::system_error(
                errno,
                std::generic_category(),
                "mkdtemp"
            );
        }
        path_ = created;
    }

    ~TemporaryDirectory() {
        std::error_code error;
        std::filesystem::remove_all(path_, error);
    }

    TemporaryDirectory(const TemporaryDirectory&) = delete;
    TemporaryDirectory& operator=(const TemporaryDirectory&) = delete;

    [[nodiscard]] const std::filesystem::path& path() const noexcept {
        return path_;
    }

    [[nodiscard]] std::filesystem::path write(
        std::string_view name,
        std::string_view contents,
        mode_t mode = 0400
    ) const {
        const auto result = path_ / name;
        std::ofstream file(result, std::ios::binary | std::ios::trunc);
        if(!file) {
            throw std::runtime_error("Could not create authorization test file");
        }
        file.write(contents.data(), static_cast<std::streamsize>(contents.size()));
        file.close();
        if(!file) {
            throw std::runtime_error("Could not write authorization test file");
        }
        if(::chmod(result.c_str(), mode) != 0) {
            throw std::system_error(
                errno,
                std::generic_category(),
                "chmod authorization test file"
            );
        }
        return result;
    }

private:
    std::filesystem::path path_;
};

class ScopedEnvironment {
public:
    ScopedEnvironment(const char* name, std::optional<std::string> value)
        : name_(name) {
        if(const char* current = std::getenv(name_.c_str()); current != nullptr) {
            original_ = current;
        }
        set(std::move(value));
    }

    ~ScopedEnvironment() {
        if(original_) {
            static_cast<void>(::setenv(
                name_.c_str(), original_->c_str(), 1
            ));
        } else {
            static_cast<void>(::unsetenv(name_.c_str()));
        }
    }

    ScopedEnvironment(const ScopedEnvironment&) = delete;
    ScopedEnvironment& operator=(const ScopedEnvironment&) = delete;

private:
    void set(const std::optional<std::string>& value) {
        const int result = value
            ? ::setenv(name_.c_str(), value->c_str(), 1)
            : ::unsetenv(name_.c_str());
        if(result != 0) {
            throw std::system_error(
                errno,
                std::generic_category(),
                "set authorization test environment"
            );
        }
    }

    std::string name_;
    std::optional<std::string> original_;
};

template<typename Function>
void expect_exception(Function&& function) {
    bool rejected = false;
    try {
        std::forward<Function>(function)();
    } catch(const std::exception&) {
        rejected = true;
    }
    CHECK(rejected);
}

void check_authorization(
    const TemporaryDirectory& temporary,
    std::string_view name,
    std::string_view contents,
    std::string_view expected
) {
    const auto path = temporary.write(name, contents);
    StoreAuthorization authorization(path);
    CHECK(authorization.view() == expected);
}

void test_explicit_authorization_path_takes_precedence() {
    ScopedEnvironment environment(
        "CREDENTIALS_DIRECTORY",
        std::string("/ignored/systemd/credentials")
    );
    const std::filesystem::path explicit_path = "/explicit/authorization";
    const auto input = store_authorization_path(explicit_path);
    CHECK(input.path == explicit_path);
    CHECK(input.origin == StoreAuthorizationOrigin::explicit_file);
}

void test_systemd_credential_path_is_resolved() {
    TemporaryDirectory temporary;
    ScopedEnvironment environment(
        "CREDENTIALS_DIRECTORY",
        temporary.path().string()
    );
    const auto input = store_authorization_path(std::nullopt);
    CHECK(input.path == temporary.path() / CREDENTIAL_NAME);
    CHECK(input.origin == StoreAuthorizationOrigin::systemd_credential);
}

void test_missing_systemd_credential_directory_is_rejected() {
    ScopedEnvironment environment("CREDENTIALS_DIRECTORY", std::nullopt);
    expect_exception([] {
        static_cast<void>(store_authorization_path(std::nullopt));
    });
}

void test_empty_systemd_credential_directory_is_rejected() {
    ScopedEnvironment environment("CREDENTIALS_DIRECTORY", std::string{});
    expect_exception([] {
        static_cast<void>(store_authorization_path(std::nullopt));
    });
}

void test_authorization_values_and_line_endings() {
    TemporaryDirectory temporary;
    check_authorization(temporary, "one-byte", "x", "x");
    check_authorization(temporary, "lf", "secret\n", "secret");
    check_authorization(temporary, "crlf", "secret\r\n", "secret");

    const std::string maximum(32, 'm');
    check_authorization(temporary, "maximum", maximum, maximum);
    check_authorization(temporary, "maximum-lf", maximum + "\n", maximum);
    check_authorization(
        temporary,
        "maximum-crlf",
        maximum + "\r\n",
        maximum
    );
}

void test_empty_authorization_is_rejected() {
    TemporaryDirectory temporary;
    const auto path = temporary.write("empty", "");
    expect_exception([&] { StoreAuthorization authorization(path); });
}

void test_line_ending_only_authorization_is_rejected() {
    TemporaryDirectory temporary;
    const auto lf = temporary.write("lf", "\n");
    const auto crlf = temporary.write("crlf", "\r\n");
    expect_exception([&] { StoreAuthorization authorization(lf); });
    expect_exception([&] { StoreAuthorization authorization(crlf); });
}

void test_embedded_nul_is_rejected() {
    TemporaryDirectory temporary;
    const std::string contents("ab\0cd", 5);
    const auto path = temporary.write("embedded-nul", contents);
    expect_exception([&] { StoreAuthorization authorization(path); });
}

void test_oversized_authorization_is_rejected() {
    TemporaryDirectory temporary;
    const auto untrimmed = temporary.write("untrimmed", std::string(33, 'x'));
    const auto too_large = temporary.write("too-large", std::string(35, 'x'));
    expect_exception([&] { StoreAuthorization authorization(untrimmed); });
    expect_exception([&] { StoreAuthorization authorization(too_large); });
}

void test_incorrect_mode_is_rejected() {
    TemporaryDirectory temporary;
    const auto path = temporary.write("wrong-mode", "secret", 0600);
    expect_exception([&] { StoreAuthorization authorization(path); });
}

void test_explicit_group_readable_file_is_rejected() {
    TemporaryDirectory temporary;
    const auto path = temporary.write("group-readable", "secret", 0440);
    expect_exception([&] { StoreAuthorization authorization(path); });
}

void test_systemd_group_readable_credential_is_accepted() {
    TemporaryDirectory temporary;
    const auto path = temporary.write("systemd-credential", "secret", 0440);
    StoreAuthorization authorization(StoreAuthorizationInput{
        .path = path,
        .origin = StoreAuthorizationOrigin::systemd_credential,
    });
    CHECK(authorization.view() == "secret");
}

void test_systemd_writable_credential_is_rejected() {
    TemporaryDirectory temporary;
    const auto path = temporary.write(
        "writable-systemd-credential",
        "secret",
        0640
    );
    expect_exception([&] {
        StoreAuthorization authorization(StoreAuthorizationInput{
            .path = path,
            .origin = StoreAuthorizationOrigin::systemd_credential,
        });
    });
}

void test_symlink_is_rejected() {
    TemporaryDirectory temporary;
    const auto target = temporary.write("target", "secret");
    const auto link = temporary.path() / "link";
    std::filesystem::create_symlink(target, link);
    expect_exception([&] { StoreAuthorization authorization(link); });
}

void test_multiple_hard_links_are_rejected() {
    TemporaryDirectory temporary;
    const auto target = temporary.write("target", "secret");
    const auto link = temporary.path() / "hard-link";
    std::filesystem::create_hard_link(target, link);
    expect_exception([&] { StoreAuthorization authorization(target); });
}

void test_non_regular_file_is_rejected() {
    TemporaryDirectory temporary;
    expect_exception([&] {
        StoreAuthorization authorization(temporary.path());
    });
}

void test_missing_file_is_rejected() {
    TemporaryDirectory temporary;
    const auto missing = temporary.path() / "missing";
    expect_exception([&] { StoreAuthorization authorization(missing); });
}

} // namespace

int main() {
    test_support::Runner runner;
    runner.run(
        "test_explicit_authorization_path_takes_precedence",
        test_explicit_authorization_path_takes_precedence
    );
    runner.run(
        "test_systemd_credential_path_is_resolved",
        test_systemd_credential_path_is_resolved
    );
    runner.run(
        "test_missing_systemd_credential_directory_is_rejected",
        test_missing_systemd_credential_directory_is_rejected
    );
    runner.run(
        "test_empty_systemd_credential_directory_is_rejected",
        test_empty_systemd_credential_directory_is_rejected
    );
    runner.run(
        "test_authorization_values_and_line_endings",
        test_authorization_values_and_line_endings
    );
    runner.run(
        "test_empty_authorization_is_rejected",
        test_empty_authorization_is_rejected
    );
    runner.run(
        "test_line_ending_only_authorization_is_rejected",
        test_line_ending_only_authorization_is_rejected
    );
    runner.run(
        "test_embedded_nul_is_rejected",
        test_embedded_nul_is_rejected
    );
    runner.run(
        "test_oversized_authorization_is_rejected",
        test_oversized_authorization_is_rejected
    );
    runner.run(
        "test_incorrect_mode_is_rejected",
        test_incorrect_mode_is_rejected
    );
    runner.run(
        "test_explicit_group_readable_file_is_rejected",
        test_explicit_group_readable_file_is_rejected
    );
    runner.run(
        "test_systemd_group_readable_credential_is_accepted",
        test_systemd_group_readable_credential_is_accepted
    );
    runner.run(
        "test_systemd_writable_credential_is_rejected",
        test_systemd_writable_credential_is_rejected
    );
    runner.run("test_symlink_is_rejected", test_symlink_is_rejected);
    runner.run(
        "test_multiple_hard_links_are_rejected",
        test_multiple_hard_links_are_rejected
    );
    runner.run(
        "test_non_regular_file_is_rejected",
        test_non_regular_file_is_rejected
    );
    runner.run("test_missing_file_is_rejected", test_missing_file_is_rejected);
    return runner.finish();
}
