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

void test_subcommand_help_exits_successfully() {
    for(const std::vector<std::string>& arguments : {
        std::vector<std::string>{"vauthctl", "status", "--help"},
        std::vector<std::string>{"vauthctl", "provision", "--help"},
        std::vector<std::string>{"vauthctl", "credentials", "--help"},
        std::vector<std::string>{
            "vauthctl", "credentials", "list", "--help"
        },
        std::vector<std::string>{
            "vauthctl", "credentials", "delete", "--help"
        },
        std::vector<std::string>{
            "vauthctl", "credentials", "clear", "--help"
        },
    }) {
        const auto parsed = parse(arguments);
        CHECK(parsed.result.exitCode == 0);
        CHECK(!parsed.result.options.has_value());
        CHECK(!parsed.standardOutput.empty());
        CHECK(parsed.standardError.empty());
    }
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

void test_unknown_command_is_usage_error() {
    const auto parsed = parse({"vauthctl", "unknown"});
    CHECK(parsed.result.exitCode == 2);
    CHECK(!parsed.result.options.has_value());
}

void test_credentials_requires_subcommand() {
    const auto parsed = parse({"vauthctl", "credentials"});
    CHECK(parsed.result.exitCode == 2);
    CHECK(!parsed.result.options.has_value());
}

void test_multiple_commands_are_rejected() {
    const auto parsed = parse({"vauthctl", "status", "provision"});
    CHECK(parsed.result.exitCode == 2);
    CHECK(!parsed.result.options.has_value());
}

void test_status_rejects_auth_file_before_command() {
    const auto parsed = parse({
        "vauthctl", "--auth-file", "/tmp/authorization", "status"
    });
    CHECK(parsed.result.exitCode == 2);
    CHECK(!parsed.result.options.has_value());
}

void test_status_rejects_auth_file_after_command() {
    const auto parsed = parse({
        "vauthctl", "status", "--auth-file", "/tmp/authorization"
    });
    CHECK(parsed.result.exitCode == 2);
    CHECK(!parsed.result.options.has_value());
}

void test_provision_is_selected() {
    const auto parsed = parse({"vauthctl", "provision"});
    CHECK(require_options(parsed).command == Command::provision);
}

void test_provision_auth_file_is_parsed() {
    const auto parsed = parse({
        "vauthctl", "provision", "--auth-file", "/tmp/authorization"
    });
    const auto& options = require_options(parsed);
    CHECK(options.command == Command::provision);
    CHECK(options.authorizationPath == "/tmp/authorization");
}

void test_credentials_list_without_filters() {
    const auto parsed = parse({"vauthctl", "credentials", "list"});
    const auto& options = require_options(parsed);
    CHECK(options.command == Command::credentialsList);
    CHECK(!options.ownerUid.has_value());
    CHECK(!options.rpId.has_value());
    CHECK(!options.authorizationPath.has_value());
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

void test_credentials_list_auth_file_is_parsed() {
    const auto parsed = parse({
        "vauthctl", "credentials", "list",
        "--auth-file", "/tmp/authorization"
    });
    const auto& options = require_options(parsed);
    CHECK(options.command == Command::credentialsList);
    CHECK(options.authorizationPath == "/tmp/authorization");
}

void test_owner_uid_boundaries_are_parsed() {
    for(const auto& [text, expected] : {
        std::pair<std::string, uint32_t>{"0", 0},
        std::pair<std::string, uint32_t>{"4294967295", UINT32_MAX},
    }) {
        const auto parsed = parse({
            "vauthctl", "credentials", "list", "--owner", text
        });
        CHECK(require_options(parsed).ownerUid == expected);
    }
}

void test_credentials_delete_options_are_required() {
    const auto parsed = parse({"vauthctl", "credentials", "delete"});
    CHECK(parsed.result.exitCode == 2);
    CHECK(!parsed.result.options.has_value());
}

void test_credentials_delete_rejects_each_missing_option() {
    const std::string credential_id(64, 'a');
    for(const std::vector<std::string>& arguments : {
        std::vector<std::string>{
            "vauthctl", "credentials", "delete",
            "--id", credential_id
        },
        std::vector<std::string>{
            "vauthctl", "credentials", "delete",
            "--owner", "1000"
        },
    }) {
        const auto parsed = parse(arguments);
        CHECK(parsed.result.exitCode == 2);
        CHECK(!parsed.result.options.has_value());
    }
}

void test_credentials_delete_options_are_parsed() {
    const std::string credential_id(64, 'a');
    const auto parsed = parse({
        "vauthctl", "credentials", "delete",
        "--owner", "1000", "--id", credential_id
    });
    const auto& options = require_options(parsed);
    CHECK(options.command == Command::credentialsDelete);
    CHECK(options.ownerUid == std::optional<uint32_t>(1000));
    CHECK(options.credentialId == std::optional<std::string>(credential_id));
}

void test_credentials_delete_accepts_supported_id_boundaries() {
    for(const std::size_t length : {std::size_t{32}, std::size_t{2048}}) {
        const std::string credential_id(length, 'A');
        const auto parsed = parse({
            "vauthctl", "credentials", "delete",
            "--owner", "1000", "--id", credential_id
        });
        CHECK(require_options(parsed).credentialId == credential_id);
    }
}

void test_credentials_delete_rejects_invalid_id() {
    for(const std::string& credential_id : {
		std::string(30, 'a'),
		std::string(33, 'a'),
		std::string(2050, 'a'),
        std::string(64, 'g'),
    }) {
        const auto parsed = parse({
            "vauthctl", "credentials", "delete",
            "--owner", "1000", "--id", credential_id
        });
        CHECK(parsed.result.exitCode == 2);
        CHECK(!parsed.result.options.has_value());
    }
}

void test_credentials_delete_auth_file_is_parsed() {
    const std::string credential_id(64, 'A');
    const auto parsed = parse({
        "vauthctl", "credentials", "delete",
        "--owner", "1000", "--id", credential_id,
        "--auth-file", "/tmp/authorization"
    });
    const auto& options = require_options(parsed);
    CHECK(options.command == Command::credentialsDelete);
    CHECK(options.authorizationPath == "/tmp/authorization");
}

void test_invalid_owner_is_usage_error() {
    const auto parsed = parse({
        "vauthctl", "credentials", "list", "--owner", "not-a-uid"
    });
    CHECK(parsed.result.exitCode == 2);
    CHECK(!parsed.result.options.has_value());
}

void test_out_of_range_owner_is_usage_error() {
    for(const std::string owner : {"-1", "4294967296"}) {
        const auto parsed = parse({
            "vauthctl", "credentials", "list", "--owner", owner
        });
        CHECK(parsed.result.exitCode == 2);
        CHECK(!parsed.result.options.has_value());
    }
}

void test_duplicate_owner_is_usage_error() {
    const auto parsed = parse({
        "vauthctl", "credentials", "list",
        "--owner", "1000", "--owner", "1001"
    });
    CHECK(parsed.result.exitCode == 2);
    CHECK(!parsed.result.options.has_value());
}

void test_duplicate_filter_and_auth_options_are_usage_errors() {
    for(const std::vector<std::string>& arguments : {
        std::vector<std::string>{
            "vauthctl", "credentials", "list",
            "--rp", "first.example", "--rp", "second.example"
        },
        std::vector<std::string>{
            "vauthctl", "credentials", "list",
            "--auth-file", "/tmp/one", "--auth-file", "/tmp/two"
        },
    }) {
        const auto parsed = parse(arguments);
        CHECK(parsed.result.exitCode == 2);
        CHECK(!parsed.result.options.has_value());
    }
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

void test_clear_auth_file_is_parsed() {
    const auto parsed = parse({
        "vauthctl", "credentials", "clear",
        "--confirm-destroy-all",
        "--auth-file", "/tmp/authorization"
    });
    const auto& options = require_options(parsed);
    CHECK(options.command == Command::credentialsClear);
    CHECK(options.confirmedDestroyAll);
    CHECK(options.authorizationPath == "/tmp/authorization");
}

} // namespace

int main() {
    test_support::Runner runner;
    runner.run(
        "test_help_exits_successfully_without_options",
        test_help_exits_successfully_without_options
    );
    runner.run(
        "test_subcommand_help_exits_successfully",
        test_subcommand_help_exits_successfully
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
        "test_unknown_command_is_usage_error",
        test_unknown_command_is_usage_error
    );
    runner.run(
        "test_credentials_requires_subcommand",
        test_credentials_requires_subcommand
    );
    runner.run(
        "test_multiple_commands_are_rejected",
        test_multiple_commands_are_rejected
    );
    runner.run(
        "test_status_rejects_auth_file_before_command",
        test_status_rejects_auth_file_before_command
    );
    runner.run(
        "test_status_rejects_auth_file_after_command",
        test_status_rejects_auth_file_after_command
    );
    runner.run("test_provision_is_selected", test_provision_is_selected);
    runner.run(
        "test_provision_auth_file_is_parsed",
        test_provision_auth_file_is_parsed
    );
    runner.run(
        "test_credentials_list_without_filters",
        test_credentials_list_without_filters
    );
    runner.run(
        "test_credentials_list_filters_are_parsed",
        test_credentials_list_filters_are_parsed
    );
    runner.run(
        "test_credentials_list_auth_file_is_parsed",
        test_credentials_list_auth_file_is_parsed
    );
    runner.run(
        "test_owner_uid_boundaries_are_parsed",
        test_owner_uid_boundaries_are_parsed
    );
    runner.run(
        "test_credentials_delete_options_are_required",
        test_credentials_delete_options_are_required
    );
    runner.run(
        "test_credentials_delete_rejects_each_missing_option",
        test_credentials_delete_rejects_each_missing_option
    );
    runner.run(
        "test_credentials_delete_options_are_parsed",
        test_credentials_delete_options_are_parsed
    );
    runner.run(
        "test_credentials_delete_accepts_supported_id_boundaries",
        test_credentials_delete_accepts_supported_id_boundaries
    );
    runner.run(
        "test_credentials_delete_rejects_invalid_id",
        test_credentials_delete_rejects_invalid_id
    );
    runner.run(
        "test_credentials_delete_auth_file_is_parsed",
        test_credentials_delete_auth_file_is_parsed
    );
    runner.run(
        "test_invalid_owner_is_usage_error",
        test_invalid_owner_is_usage_error
    );
    runner.run(
        "test_out_of_range_owner_is_usage_error",
        test_out_of_range_owner_is_usage_error
    );
    runner.run(
        "test_duplicate_owner_is_usage_error",
        test_duplicate_owner_is_usage_error
    );
    runner.run(
        "test_duplicate_filter_and_auth_options_are_usage_errors",
        test_duplicate_filter_and_auth_options_are_usage_errors
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
    runner.run(
        "test_clear_auth_file_is_parsed",
        test_clear_auth_file_is_parsed
    );
    return runner.finish();
}
