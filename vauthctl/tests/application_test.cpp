#include "application.hpp"
#include "test_runner.hpp"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

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

template<typename Exception, typename Function>
void check_throws(Function&& function) {
    bool thrown = false;
    try {
        function();
    } catch(const Exception&) {
        thrown = true;
    }
    CHECK(thrown);
}

struct Calls {
    unsigned int status = 0;
    unsigned int provision = 0;
    unsigned int clear = 0;
    unsigned int list = 0;
    unsigned int erase = 0;
    std::optional<std::filesystem::path> authorizationPath;
    std::optional<uint32_t> ownerUid;
    std::optional<std::string> rpId;
    std::optional<std::string> credentialId;
};

CommandOperations recording_operations(Calls& calls, int status_result = 0) {
    return {
        .status = [&calls, status_result] {
            ++calls.status;
            return status_result;
        },
        .provision = [&calls](const auto& authorization_path) {
            ++calls.provision;
            calls.authorizationPath = authorization_path;
        },
        .clear = [&calls](const auto& authorization_path) {
            ++calls.clear;
            calls.authorizationPath = authorization_path;
        },
        .list = [&calls](
            const auto& authorization_path,
            std::optional<uint32_t> owner_uid,
            const std::optional<std::string>& rp_id
        ) {
            ++calls.list;
            calls.authorizationPath = authorization_path;
            calls.ownerUid = owner_uid;
            calls.rpId = rp_id;
        },
        .erase = [&calls](
            const auto& authorization_path,
            uint32_t owner_uid,
            std::string_view credential_id
        ) {
            ++calls.erase;
            calls.authorizationPath = authorization_path;
            calls.ownerUid = owner_uid;
            calls.credentialId = credential_id;
        },
    };
}

Options options_for(Command command) {
    Options options;
    options.command = command;
    return options;
}

void check_only_called(unsigned int expected, const Calls& calls) {
    CHECK(calls.status + calls.provision + calls.clear + calls.list +
          calls.erase == 1);
    CHECK(expected == 1);
}

void test_status_dispatch_and_exit_code() {
    Calls calls;
    const auto operations = recording_operations(calls, 7);
    const int result = execute_command(
        options_for(Command::status),
        operations
    );

    CHECK(result == 7);
    check_only_called(calls.status, calls);
}

void test_provision_dispatch() {
    Calls calls;
    const auto operations = recording_operations(calls);
    auto options = options_for(Command::provision);
    options.authorizationPath = "/tmp/provision-auth";

    CHECK(execute_command(options, operations) == 0);
    check_only_called(calls.provision, calls);
    CHECK(calls.authorizationPath == options.authorizationPath);
}

void test_clear_dispatch() {
    Calls calls;
    const auto operations = recording_operations(calls);
    auto options = options_for(Command::credentialsClear);
    options.authorizationPath = "/tmp/clear-auth";
    options.confirmedDestroyAll = true;

    CHECK(execute_command(options, operations) == 0);
    check_only_called(calls.clear, calls);
    CHECK(calls.authorizationPath == options.authorizationPath);
}

void test_clear_requires_confirmation_before_dispatch() {
    Calls calls;
    const auto operations = recording_operations(calls);
    const Options options = options_for(Command::credentialsClear);

    check_throws<std::invalid_argument>([&] {
        static_cast<void>(execute_command(options, operations));
    });
    CHECK(calls.status + calls.provision + calls.clear + calls.list +
          calls.erase == 0);
}

void test_list_dispatch() {
    Calls calls;
    const auto operations = recording_operations(calls);
    auto options = options_for(Command::credentialsList);
    options.authorizationPath = "/tmp/list-auth";
    options.ownerUid = 1000;
    options.rpId = "example.com";

    CHECK(execute_command(options, operations) == 0);
    check_only_called(calls.list, calls);
    CHECK(calls.authorizationPath == options.authorizationPath);
    CHECK(calls.ownerUid == options.ownerUid);
    CHECK(calls.rpId == options.rpId);
}

void test_delete_dispatch() {
    Calls calls;
    const auto operations = recording_operations(calls);
    auto options = options_for(Command::credentialsDelete);
    options.authorizationPath = "/tmp/delete-auth";
    options.ownerUid = 1001;
    options.credentialId = std::string(64, 'a');

    CHECK(execute_command(options, operations) == 0);
    check_only_called(calls.erase, calls);
    CHECK(calls.authorizationPath == options.authorizationPath);
    CHECK(calls.ownerUid == options.ownerUid);
    CHECK(calls.credentialId == options.credentialId);
}

void test_delete_requires_owner_and_id_before_dispatch() {
    auto missing_id = options_for(Command::credentialsDelete);
    missing_id.ownerUid = 1000;
    auto missing_owner = options_for(Command::credentialsDelete);
    missing_owner.credentialId = std::string(64, 'a');
    for(const Options& options : std::vector<Options>{
        std::move(missing_id),
        std::move(missing_owner),
    }) {
        Calls calls;
        const auto operations = recording_operations(calls);
        check_throws<std::invalid_argument>([&] {
            static_cast<void>(execute_command(options, operations));
        });
        CHECK(calls.status + calls.provision + calls.clear + calls.list +
              calls.erase == 0);
    }
}

void test_operation_failure_propagates() {
    Calls calls;
    auto operations = recording_operations(calls);
    operations.provision = [](const auto&) {
        throw std::runtime_error("simulated provisioning failure");
    };

    check_throws<std::runtime_error>([&] {
        static_cast<void>(execute_command(
            options_for(Command::provision),
            operations
        ));
    });
    CHECK(calls.status + calls.provision + calls.clear + calls.list +
          calls.erase == 0);
}

} // namespace

int main() {
    test_support::Runner runner;
    runner.run(
        "test_status_dispatch_and_exit_code",
        test_status_dispatch_and_exit_code
    );
    runner.run("test_provision_dispatch", test_provision_dispatch);
    runner.run("test_clear_dispatch", test_clear_dispatch);
    runner.run(
        "test_clear_requires_confirmation_before_dispatch",
        test_clear_requires_confirmation_before_dispatch
    );
    runner.run("test_list_dispatch", test_list_dispatch);
    runner.run("test_delete_dispatch", test_delete_dispatch);
    runner.run(
        "test_delete_requires_owner_and_id_before_dispatch",
        test_delete_requires_owner_and_id_before_dispatch
    );
    runner.run(
        "test_operation_failure_propagates",
        test_operation_failure_propagates
    );
    return runner.finish();
}
