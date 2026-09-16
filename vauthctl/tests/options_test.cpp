#include <cstdint>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "options.hpp"
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

struct CapturedParse {
    ParseResult result;
    std::string standardOutput;
    std::string standardError;
};

CapturedParse parse(std::vector<std::string> arguments) {
    std::vector<char*> argv;
    argv.reserve(arguments.size());
    for(auto& argument : arguments) {
        argv.push_back(argument.data());
    }

    std::ostringstream output;
    std::ostringstream error;
    auto* previousOutput = std::cout.rdbuf(output.rdbuf());
    auto* previousError = std::cerr.rdbuf(error.rdbuf());

    ParseResult result;
    try {
        result = parse_options(static_cast<int>(argv.size()), argv.data());
    } catch(...) {
        std::cout.rdbuf(previousOutput);
        std::cerr.rdbuf(previousError);
        throw;
    }

    std::cout.rdbuf(previousOutput);
    std::cerr.rdbuf(previousError);
    return CapturedParse{
        .result = std::move(result),
        .standardOutput = output.str(),
        .standardError = error.str(),
    };
}

const Options& require_options(const CapturedParse& parsed) {
    CHECK(parsed.result.exitCode == 0);
    CHECK(parsed.result.options.has_value());
    return *parsed.result.options;
}

void test_help_exits_successfully_without_options() {
    const auto parsed = parse({"vauthctl", "--help"});
    CHECK(parsed.result.exitCode == 0);
    CHECK(!parsed.result.options.has_value());
    CHECK(!parsed.standardOutput.empty());
    CHECK(parsed.standardError.empty());
}

void test_missing_command_is_usage_error() {
    const auto parsed = parse({"vauthctl"});
    CHECK(parsed.result.exitCode == 2);
    CHECK(!parsed.result.options.has_value());
    CHECK(!parsed.standardError.empty());
}

void test_unknown_option_is_usage_error() {
    const auto parsed = parse({"vauthctl", "status", "--unknown"});
    CHECK(parsed.result.exitCode == 2);
    CHECK(!parsed.result.options.has_value());
}

void test_status_accepts_auth_file_before_command() {
    const auto parsed = parse({
        "vauthctl", "--auth-file", "/tmp/authorization", "status"
    });
    const auto& options = require_options(parsed);
    CHECK(options.command == Command::status);
    CHECK(options.authorizationPath.has_value());
    CHECK(*options.authorizationPath == "/tmp/authorization");
}

void test_status_accepts_auth_file_after_command() {
    const auto parsed = parse({
        "vauthctl", "status", "--auth-file", "/tmp/authorization"
    });
    const auto& options = require_options(parsed);
    CHECK(options.command == Command::status);
    CHECK(options.authorizationPath.has_value());
    CHECK(*options.authorizationPath == "/tmp/authorization");
}

void test_provision_is_selected() {
    const auto parsed = parse({"vauthctl", "provision"});
    CHECK(require_options(parsed).command == Command::provision);
}

void test_credentials_list_filters_are_parsed() {
    const auto parsed = parse({
        "vauthctl", "credentials", "list",
        "--owner", "1000", "--rp", "example.com"
    });
    const auto& options = require_options(parsed);
    CHECK(options.command == Command::credentialsList);
    CHECK(options.ownerUid == std::optional<uint32_t>(1000));
    CHECK(options.rpId == std::optional<std::string>("example.com"));
}

void test_credentials_delete_options_are_required() {
    const auto parsed = parse({"vauthctl", "credentials", "delete"});
    CHECK(parsed.result.exitCode == 2);
    CHECK(!parsed.result.options.has_value());
}

void test_credentials_delete_options_are_parsed() {
    const auto parsed = parse({
        "vauthctl", "credentials", "delete",
        "--owner", "1000", "--id", "aabbccdd"
    });
    const auto& options = require_options(parsed);
    CHECK(options.command == Command::credentialsDelete);
    CHECK(options.ownerUid == std::optional<uint32_t>(1000));
    CHECK(options.credentialId == std::optional<std::string>("aabbccdd"));
}

void test_invalid_owner_is_usage_error() {
    const auto parsed = parse({
        "vauthctl", "credentials", "list", "--owner", "not-a-uid"
    });
    CHECK(parsed.result.exitCode == 2);
    CHECK(!parsed.result.options.has_value());
}

void test_duplicate_owner_is_usage_error() {
    const auto parsed = parse({
        "vauthctl", "credentials", "list",
        "--owner", "1000", "--owner", "1001"
    });
    CHECK(parsed.result.exitCode == 2);
    CHECK(!parsed.result.options.has_value());
}

void test_clear_requires_confirmation() {
    const auto parsed = parse({"vauthctl", "credentials", "clear"});
    CHECK(parsed.result.exitCode == 2);
    CHECK(!parsed.result.options.has_value());
}

void test_clear_rejects_false_confirmation_override() {
    const auto parsed = parse({
        "vauthctl", "credentials", "clear",
        "--confirm-destroy-all=false"
    });
    CHECK(parsed.result.exitCode == 2);
    CHECK(!parsed.result.options.has_value());
}

void test_clear_confirmation_is_parsed() {
    const auto parsed = parse({
        "vauthctl", "credentials", "clear", "--confirm-destroy-all"
    });
    const auto& options = require_options(parsed);
    CHECK(options.command == Command::credentialsClear);
    CHECK(options.confirmedDestroyAll);
}

} // namespace

int main() {
    test_support::Runner runner;
    runner.run(
        "test_help_exits_successfully_without_options",
        test_help_exits_successfully_without_options
    );
    runner.run(
        "test_missing_command_is_usage_error",
        test_missing_command_is_usage_error
    );
    runner.run(
        "test_unknown_option_is_usage_error",
        test_unknown_option_is_usage_error
    );
    runner.run(
        "test_status_accepts_auth_file_before_command",
        test_status_accepts_auth_file_before_command
    );
    runner.run(
        "test_status_accepts_auth_file_after_command",
        test_status_accepts_auth_file_after_command
    );
    runner.run("test_provision_is_selected", test_provision_is_selected);
    runner.run(
        "test_credentials_list_filters_are_parsed",
        test_credentials_list_filters_are_parsed
    );
    runner.run(
        "test_credentials_delete_options_are_required",
        test_credentials_delete_options_are_required
    );
    runner.run(
        "test_credentials_delete_options_are_parsed",
        test_credentials_delete_options_are_parsed
    );
    runner.run(
        "test_invalid_owner_is_usage_error",
        test_invalid_owner_is_usage_error
    );
    runner.run(
        "test_duplicate_owner_is_usage_error",
        test_duplicate_owner_is_usage_error
    );
    runner.run(
        "test_clear_requires_confirmation",
        test_clear_requires_confirmation
    );
    runner.run(
        "test_clear_rejects_false_confirmation_override",
        test_clear_rejects_false_confirmation_override
    );
    runner.run(
        "test_clear_confirmation_is_parsed",
        test_clear_confirmation_is_parsed
    );
    return runner.finish();
}
