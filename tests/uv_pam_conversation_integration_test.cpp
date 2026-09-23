#include "test_runner.hpp"
#include "uv/src/auth_handler.hpp"
#include "uv/src/cancellable_process.hpp"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
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

constexpr std::string_view PAM_SERVICE = "vauth-integration-test";

class TemporaryPamConfiguration {
public:
    explicit TemporaryPamConfiguration(const std::filesystem::path& module) {
        auto name = (
            std::filesystem::temp_directory_path() /
            "vauth-pam-integration-XXXXXX"
        ).string();
        std::vector<char> writable(name.begin(), name.end());
        writable.push_back('\0');
        const char* directory = mkdtemp(writable.data());
        if(directory == nullptr) {
            throw std::system_error(
                errno,
                std::generic_category(),
                "create test PAM configuration directory"
            );
        }
        path_ = directory;

        std::ofstream configuration(path_ / PAM_SERVICE);
        configuration << "auth required " << module.string() << '\n'
                      << "account required " << module.string() << '\n';
        configuration.close();
        if(!configuration) {
            std::error_code error;
            std::filesystem::remove_all(path_, error);
            throw std::runtime_error("write test PAM configuration");
        }
    }

    ~TemporaryPamConfiguration() {
        std::error_code error;
        std::filesystem::remove_all(path_, error);
    }

    TemporaryPamConfiguration(const TemporaryPamConfiguration&) = delete;
    TemporaryPamConfiguration& operator=(
        const TemporaryPamConfiguration&
    ) = delete;

    [[nodiscard]] const std::filesystem::path& path() const noexcept {
        return path_;
    }

private:
    std::filesystem::path path_;
};

vauth::uv::SensitiveBytes secret(std::string_view text) {
    vauth::uv::SensitiveBytes bytes(text.size());
    std::ranges::copy(text, bytes.writable_bytes().begin());
    return bytes;
}

struct PamRun {
    vauth::uv::VerificationResult result;
    std::vector<vauth::uv::VerificationStatus> statuses;
    std::string prompt;
};

PamRun run_pam(
    const std::string& executable,
    const TemporaryPamConfiguration& configuration,
    std::string_view response
) {
    using namespace vauth::uv;

    PamRun run{.result = VerificationResult::error};
    std::stop_source stop;
    run.result = run_cancellable_verifier_program(
        executable,
        {
            std::string(VAUTH_AUTH_HANDLER_COMMAND),
            "vauth-test-user",
            std::string(PAM_SERVICE),
            configuration.path().string(),
            std::to_string(getpid())
        },
        StartVerification{.targetUid = 0, .sessionId = "test-session"},
        stop.get_token(),
        std::chrono::seconds(2),
        [&run](const VerificationStatus& status) {
            run.statuses.push_back(status);
        },
        [&run, response](const SecretRequired& required) {
            run.prompt = required.prompt;
            return secret(response);
        }
    );
    return run;
}

bool test_real_pam_conversation_succeeds(
    const std::string& executable,
    const TemporaryPamConfiguration& configuration
) {
    using namespace vauth::uv;
    const PamRun run = run_pam(
        executable,
        configuration,
        "vauth-test-secret"
    );

    CHECK(run.result == VerificationResult::success);
    CHECK(run.prompt == "Test password:");
    CHECK(run.statuses.size() == 1);
    CHECK(run.statuses[0] == VerificationStatus(
        VerificationStatusKind::information,
        "Test PAM module is ready"
    ));
    return true;
}

bool test_real_pam_conversation_preserves_denial(
    const std::string& executable,
    const TemporaryPamConfiguration& configuration
) {
    using namespace vauth::uv;
    const PamRun run = run_pam(executable, configuration, "wrong-secret");

    CHECK(run.result == VerificationResult::denied);
    CHECK(run.prompt == "Test password:");
    CHECK(run.statuses.size() == 2);
    CHECK(run.statuses[0].kind == VerificationStatusKind::information);
    CHECK(run.statuses[1] == VerificationStatus(
        VerificationStatusKind::error,
        "Test PAM module rejected the response"
    ));
    return true;
}

} // namespace

int main(int argc, char** argv) {
    if(
        argc >= 2 &&
        std::string_view(argv[1]) == VAUTH_AUTH_HANDLER_COMMAND
    ) {
        return run_vauth_auth_handler(argc - 2, argv + 2);
    }

    if(argc != 2) {
        std::cerr << "Usage: uv_pam_conversation_integration_tests MODULE\n";
        return 2;
    }

    const std::string executable = std::filesystem::canonical(argv[0]);
    const TemporaryPamConfiguration configuration(
        std::filesystem::canonical(argv[1])
    );
    test_support::Runner runner;
    runner.run("real PAM conversation succeeds", [&] {
        return test_real_pam_conversation_succeeds(
            executable,
            configuration
        );
    });
    runner.run("real PAM conversation preserves denial", [&] {
        return test_real_pam_conversation_preserves_denial(
            executable,
            configuration
        );
    });
    return runner.finish();
}
