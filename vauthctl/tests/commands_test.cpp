#include "commands.hpp"
#include "log.hpp"
#include "test_runner.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <optional>
#include <sstream>
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

bool contains(std::string_view text, std::string_view expected) {
    return text.find(expected) != std::string_view::npos;
}

std::size_t occurrences(std::string_view text, std::string_view value) {
    std::size_t count = 0;
    std::size_t position = 0;
    while((position = text.find(value, position)) != std::string_view::npos) {
        ++count;
        position += value.size();
    }
    return count;
}

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

struct RenderedStatus {
    int exitCode;
    std::string output;
};

RenderedStatus render_status(const StatusReport& report) {
    std::ostringstream output;
    const int exit_code = print_status(report, output);
    return {
        .exitCode = exit_code,
        .output = output.str(),
    };
}

CredentialSummary credential(
    uint8_t id_byte,
    uint32_t owner_uid,
    std::string rp_id,
    std::string user_name,
    std::string display_name,
    bool discoverable
) {
    return {
        .id = std::vector<uint8_t>(32, id_byte),
        .ownerUid = owner_uid,
        .rpId = std::move(rp_id),
        .userName = std::move(user_name),
        .userDisplayName = std::move(display_name),
        .signCount = 0,
        .discoverable = discoverable,
        .creationOrder = 1,
    };
}

std::string render_credentials(
    const std::vector<CredentialSummary>& credentials,
    std::optional<uint32_t> owner_uid = std::nullopt,
    std::optional<std::string> rp_id = std::nullopt
) {
    std::ostringstream output;
    print_credentials(credentials, owner_uid, rp_id, output);
    return output.str();
}

void test_healthy_status() {
    const auto rendered = render_status(StatusReport{
        .daemonRunning = true,
        .systemdService = SystemdServiceState{
            .status = "active",
            .sub = "running",
        },
        .agentAvailable = true,
    });

    CHECK(rendered.exitCode == 0);
    CHECK(contains(rendered.output, "Daemon status:\n"));
    CHECK(contains(
        rendered.output,
        vauth::log::colorize(vauth::log::Color::green, "● running")
    ));
    CHECK(contains(rendered.output, "Systemd service status:\n"));
    CHECK(contains(
        rendered.output,
        vauth::log::colorize(
            vauth::log::Color::green,
            "● active (running)"
        )
    ));
    CHECK(contains(rendered.output, "UI agent status:\n"));
    CHECK(contains(
        rendered.output,
        vauth::log::colorize(
            vauth::log::Color::green,
            "● agent connected"
        )
    ));
}

void test_running_daemon_without_agent() {
    const auto rendered = render_status(StatusReport{
        .daemonRunning = true,
        .systemdService = SystemdServiceState{
            .status = "active",
            .sub = "running",
        },
        .agentAvailable = false,
    });

    CHECK(rendered.exitCode == 0);
    CHECK(contains(
        rendered.output,
        vauth::log::colorize(
            vauth::log::Color::red,
            "● agent not connected"
        )
    ));
}

void test_unavailable_agent_status() {
    const auto rendered = render_status(StatusReport{
        .daemonRunning = true,
        .systemdService = std::nullopt,
        .agentAvailable = std::nullopt,
    });

    CHECK(rendered.exitCode == 0);
    CHECK(contains(
        rendered.output,
        vauth::log::colorize(
            vauth::log::Color::red,
            "● status unavailable"
        )
    ));
}

void test_stopped_daemon_status() {
    const auto rendered = render_status(StatusReport{
        .daemonRunning = false,
        .systemdService = std::nullopt,
        .agentAvailable = std::nullopt,
    });

    CHECK(rendered.exitCode == 1);
    CHECK(contains(
        rendered.output,
        vauth::log::colorize(vauth::log::Color::red, "● not running")
    ));
    CHECK(contains(
        rendered.output,
        vauth::log::colorize(
            vauth::log::Color::bright_black,
            "● unit not loaded"
        )
    ));
    CHECK(contains(
        rendered.output,
        vauth::log::colorize(
            vauth::log::Color::red,
            "● unavailable (daemon not running)"
        )
    ));
}

void test_systemd_status_colors() {
    struct Case {
        SystemdServiceState state;
        vauth::log::Color color;
    };
    const std::vector<Case> cases{
        {{"failed", "failed"}, vauth::log::Color::red},
        {{"inactive", "dead"}, vauth::log::Color::bright_black},
        {{"activating", "start"}, vauth::log::Color::yellow},
        {{"reloading", "reload"}, vauth::log::Color::yellow},
        {{"deactivating", "stop"}, vauth::log::Color::yellow},
        {{"active", "exited"}, vauth::log::Color::yellow},
    };

    for(const auto& test_case : cases) {
        const auto rendered = render_status(StatusReport{
            .daemonRunning = true,
            .systemdService = test_case.state,
            .agentAvailable = true,
        });
        const std::string description =
            "● " + test_case.state.status + " (" + test_case.state.sub + ')';
        CHECK(contains(
            rendered.output,
            vauth::log::colorize(test_case.color, description)
        ));
    }
}

void test_collect_status_queries_running_daemon() {
    unsigned int daemon_queries = 0;
    unsigned int systemd_queries = 0;
    unsigned int agent_queries = 0;
    const StatusReport report = collect_status(StatusQueries{
        .daemonRunning = [&] {
            ++daemon_queries;
            return true;
        },
        .systemdService = [&]() -> std::optional<SystemdServiceState> {
            ++systemd_queries;
            return SystemdServiceState{"active", "running"};
        },
        .agentAvailable = [&]() -> std::optional<bool> {
            ++agent_queries;
            return false;
        },
    });

    CHECK(daemon_queries == 1);
    CHECK(systemd_queries == 1);
    CHECK(agent_queries == 1);
    CHECK(report.daemonRunning);
    CHECK(report.systemdService.has_value());
    CHECK(report.systemdService->status == "active");
    CHECK(report.systemdService->sub == "running");
    CHECK(report.agentAvailable == false);
}

void test_collect_status_skips_agent_for_stopped_daemon() {
    unsigned int agent_queries = 0;
    const StatusReport report = collect_status(StatusQueries{
        .daemonRunning = [] { return false; },
        .systemdService = [] {
            return std::optional<SystemdServiceState>{};
        },
        .agentAvailable = [&]() -> std::optional<bool> {
            ++agent_queries;
            return true;
        },
    });

    CHECK(!report.daemonRunning);
    CHECK(!report.systemdService.has_value());
    CHECK(!report.agentAvailable.has_value());
    CHECK(agent_queries == 0);
}

void test_collect_status_handles_daemon_disappearance() {
    const StatusReport report = collect_status(StatusQueries{
        .daemonRunning = [] { return true; },
        .systemdService = [] {
            return std::optional<SystemdServiceState>{
                SystemdServiceState{"active", "running"}
            };
        },
        .agentAvailable = [] { return std::optional<bool>{}; },
    });

    CHECK(!report.daemonRunning);
    CHECK(report.systemdService.has_value());
    CHECK(!report.agentAvailable.has_value());
}

void test_collect_status_propagates_query_failure() {
    check_throws<std::runtime_error>([] {
        static_cast<void>(collect_status(StatusQueries{
            .daemonRunning = [] { return true; },
            .systemdService = []() ->
                std::optional<SystemdServiceState> {
                throw std::runtime_error("simulated systemd failure");
            },
            .agentAvailable = [] { return std::optional<bool>{true}; },
        }));
    });
}

void test_credential_table() {
    const std::vector<CredentialSummary> credentials{
        credential(0xAB, 1000, "example.com", "alice", "Alice", true),
        credential(0xCD, 1001, "other.example", "bob", "", false),
    };

    const std::string output = render_credentials(credentials);
    std::string first_id;
    std::string second_id;
    for(int index = 0; index < 32; ++index) {
        first_id += "AB";
        second_id += "CD";
    }
    CHECK(occurrences(output, "CREDENTIAL ID") == 1);
    CHECK(contains(output, "example.com"));
    CHECK(contains(output, "Alice"));
    CHECK(contains(output, "discoverable"));
    CHECK(contains(output, first_id));
    CHECK(contains(output, "other.example"));
    CHECK(contains(output, "bob"));
    CHECK(contains(output, "non-discoverable"));
    CHECK(contains(output, second_id));
}

void test_empty_credential_table() {
    const std::string output = render_credentials({});
    CHECK(!contains(output, "CREDENTIAL ID"));
    CHECK(contains(output, "No credentials available"));
}

void test_credential_filters() {
    const std::vector<CredentialSummary> credentials{
        credential(0x11, 1000, "example.com", "alice", "Alice", true),
        credential(0x22, 1001, "other.example", "bob", "Bob", true),
    };

    const std::string owner_output = render_credentials(credentials, 1000);
    CHECK(contains(owner_output, "Filtering by owner UID = 1000"));
    CHECK(contains(owner_output, "example.com"));
    CHECK(!contains(owner_output, "other.example"));

    const std::string rp_output = render_credentials(
        credentials,
        std::nullopt,
        std::string{"other.example"}
    );
    CHECK(contains(
        rp_output,
        "Filtering by Relying Party ID = other.example"
    ));
    CHECK(!contains(rp_output, "example.com"));
    CHECK(contains(rp_output, "other.example"));

    const std::string combined_output = render_credentials(
        credentials,
        1001,
        std::string{"other.example"}
    );
    CHECK(contains(combined_output, "other.example"));
    CHECK(!contains(combined_output, "Alice"));

    const std::string no_match = render_credentials(
        credentials,
        2000,
        std::string{"missing.example"}
    );
    CHECK(!contains(no_match, "CREDENTIAL ID"));
    CHECK(contains(
        no_match,
        "No credentials with Relying Party ID: missing.example and with Owner UID: 2000 available"
    ));
}

void test_credential_output_is_terminal_safe_and_bounded() {
    const std::string unsafe_rp = "evil\x1b[31m\n.example";
    const std::string long_rp(50, 'r');
    const std::string long_user(40, 'u');
    const std::vector<CredentialSummary> credentials{
        credential(0x33, 1000, unsafe_rp, "fallback", "A\tB\nC", true),
        credential(0x44, 1000, long_rp, long_user, "", true),
    };

    const std::string output = render_credentials(credentials);
    CHECK(output.find('\x1b') == std::string::npos);
    CHECK(contains(output, "evil?[31m?.example"));
    CHECK(contains(output, "A?B?C"));
    CHECK(!contains(output, long_rp));
    CHECK(!contains(output, long_user));
    CHECK(contains(output, std::string(28, 'r') + "..."));
    CHECK(contains(output, std::string(20, 'u') + "..."));

    const std::string filtered = render_credentials(
        credentials,
        std::nullopt,
        unsafe_rp
    );
    CHECK(contains(
        filtered,
        "Filtering by Relying Party ID = evil?[31m?.example"
    ));
}

void test_decode_credential_id() {
    std::string encoded;
    encoded.reserve(64);
    for(int index = 0; index < 32; ++index)
        encoded += index % 2 == 0 ? "aB" : "Cd";

    const auto decoded = decode_credential_id(encoded);
    CHECK(decoded.size() == 32);
    for(std::size_t index = 0; index < decoded.size(); ++index)
        CHECK(decoded[index] == (index % 2 == 0 ? 0xAB : 0xCD));

    CHECK(decode_credential_id(std::string(32, '0')).size() == 16);
    CHECK(decode_credential_id(std::string(2048, 'f')).size() == 1024);
}

void test_decode_credential_id_rejects_invalid_input() {
    check_throws<std::invalid_argument>([] {
		static_cast<void>(decode_credential_id(std::string(30, 'a')));
    });
    check_throws<std::invalid_argument>([] {
		static_cast<void>(decode_credential_id(std::string(33, 'a')));
    });
    check_throws<std::invalid_argument>([] {
		static_cast<void>(decode_credential_id(std::string(2050, 'a')));
    });
    check_throws<std::invalid_argument>([] {
        static_cast<void>(decode_credential_id(std::string(64, 'g')));
    });
}

} // namespace

int main() {
    test_support::Runner runner;
    runner.run("test_healthy_status", test_healthy_status);
    runner.run(
        "test_running_daemon_without_agent",
        test_running_daemon_without_agent
    );
    runner.run("test_unavailable_agent_status", test_unavailable_agent_status);
    runner.run("test_stopped_daemon_status", test_stopped_daemon_status);
    runner.run("test_systemd_status_colors", test_systemd_status_colors);
    runner.run(
        "test_collect_status_queries_running_daemon",
        test_collect_status_queries_running_daemon
    );
    runner.run(
        "test_collect_status_skips_agent_for_stopped_daemon",
        test_collect_status_skips_agent_for_stopped_daemon
    );
    runner.run(
        "test_collect_status_handles_daemon_disappearance",
        test_collect_status_handles_daemon_disappearance
    );
    runner.run(
        "test_collect_status_propagates_query_failure",
        test_collect_status_propagates_query_failure
    );
    runner.run("test_credential_table", test_credential_table);
    runner.run("test_empty_credential_table", test_empty_credential_table);
    runner.run("test_credential_filters", test_credential_filters);
    runner.run(
        "test_credential_output_is_terminal_safe_and_bounded",
        test_credential_output_is_terminal_safe_and_bounded
    );
    runner.run("test_decode_credential_id", test_decode_credential_id);
    runner.run(
        "test_decode_credential_id_rejects_invalid_input",
        test_decode_credential_id_rejects_invalid_input
    );
    return runner.finish();
}
