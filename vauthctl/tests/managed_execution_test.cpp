#include "managed_execution.hpp"
#include "test_runner.hpp"

#include <algorithm>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

void check(bool condition, const char* expression, int line) {
	if(!condition) {
		throw std::runtime_error(
			"CHECK failed at line " + std::to_string(line) + ": " + expression
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

const vauthctl::ManagedExecutionConfig config{
	.systemdRunPath = "/usr/bin/systemd-run",
	.executablePath = "/usr/bin/vauthctl",
	.fapiSystemDirectory = "/var/lib/tpm2-tss/system/keystore",
};

bool contains(const std::vector<std::string>& arguments, const std::string& value) {
	return std::find(arguments.begin(), arguments.end(), value) != arguments.end();
}

std::size_t executable_position(const std::vector<std::string>& arguments) {
	const auto iterator = std::find(
		arguments.begin(), arguments.end(), config.executablePath
	);
	CHECK(iterator != arguments.end());
	return static_cast<std::size_t>(iterator - arguments.begin());
}

void check_common_sandbox(const std::vector<std::string>& arguments) {
	CHECK(arguments.front() == config.systemdRunPath);
	CHECK(contains(arguments, "--wait"));
	CHECK(contains(arguments, "--pipe"));
	CHECK(contains(arguments, "--collect"));
	CHECK(contains(arguments, "--uid=vauth"));
	CHECK(contains(arguments, "--gid=vauth"));
	CHECK(contains(arguments, "--property=SupplementaryGroups=tss"));
	CHECK(contains(arguments, "--property=StateDirectory=vauth"));
	CHECK(contains(
		arguments,
		"--property=LoadCredentialEncrypted=vauth-db-auth:/etc/credstore.encrypted/vauth-db-auth"
	));
	CHECK(contains(arguments, "--property=NoNewPrivileges=yes"));
	CHECK(contains(arguments, "--property=ProtectSystem=strict"));
	CHECK(contains(
		arguments,
		"--property=ReadWritePaths=/var/lib/tpm2-tss/system/keystore"
	));
	CHECK(contains(arguments, "--property=DevicePolicy=closed"));
	CHECK(contains(arguments, "--property=DeviceAllow=/dev/tpmrm0 rw"));
	CHECK(contains(arguments, "--property=InaccessiblePaths=/etc/credstore.encrypted"));
}

void test_provision_arguments() {
	Options options;
	options.command = Command::provision;
	const auto arguments = vauthctl::build_managed_arguments(options, config);
	check_common_sandbox(arguments);
	const std::size_t position = executable_position(arguments);
	CHECK(arguments.size() == position + 3);
	CHECK(arguments[position + 1] == "--managed");
	CHECK(arguments[position + 2] == "provision");
}

void test_list_preserves_each_argument_boundary() {
	Options options;
	options.command = Command::credentialsList;
	options.ownerUid = 1000;
	options.rpId = "RP with spaces;$(touch /tmp/not-executed)";
	const auto arguments = vauthctl::build_managed_arguments(options, config);
	const std::size_t position = executable_position(arguments);
	const std::vector<std::string> expected{
		"--managed", "credentials", "list", "--owner", "1000", "--rp",
		*options.rpId,
	};
	CHECK(std::vector<std::string>(arguments.begin() + position + 1, arguments.end()) == expected);
}

void test_delete_and_clear_arguments() {
	Options erase;
	erase.command = Command::credentialsDelete;
	erase.ownerUid = 42;
	erase.credentialId = std::string(64, 'a');
	auto arguments = vauthctl::build_managed_arguments(erase, config);
	auto position = executable_position(arguments);
	CHECK(std::vector<std::string>(arguments.begin() + position + 1, arguments.end()) ==
		(std::vector<std::string>{
			"--managed", "credentials", "delete", "--owner", "42", "--id",
			*erase.credentialId,
		}));

	Options clear;
	clear.command = Command::credentialsClear;
	clear.confirmedDestroyAll = true;
	arguments = vauthctl::build_managed_arguments(clear, config);
	position = executable_position(arguments);
	CHECK(std::vector<std::string>(arguments.begin() + position + 1, arguments.end()) ==
		(std::vector<std::string>{
			"--managed", "credentials", "clear", "--confirm-destroy-all",
		}));
}

void test_invalid_commands_and_paths_are_rejected() {
	Options status;
	status.command = Command::status;
	check_throws<std::invalid_argument>([&] {
		static_cast<void>(vauthctl::build_managed_arguments(status, config));
	});

	Options erase;
	erase.command = Command::credentialsDelete;
	check_throws<std::invalid_argument>([&] {
		static_cast<void>(vauthctl::build_managed_arguments(erase, config));
	});

	auto relativeConfig = config;
	relativeConfig.executablePath = "vauthctl";
	Options provision;
	provision.command = Command::provision;
	check_throws<std::invalid_argument>([&] {
		static_cast<void>(vauthctl::build_managed_arguments(provision, relativeConfig));
	});
}

void test_managed_context_validation() {
	vauthctl::validate_managed_context(999, 999, "/run/credentials/unit");
	check_throws<std::runtime_error>([] {
		vauthctl::validate_managed_context(0, 999, "/run/credentials/unit");
	});
	check_throws<std::runtime_error>([] {
		vauthctl::validate_managed_context(999, 999, "");
	});
	check_throws<std::runtime_error>([] {
		vauthctl::validate_managed_context(999, 999, "relative/path");
	});
}

void test_child_exit_status_is_propagated() {
	Options options;
	options.command = Command::provision;
	auto processConfig = config;
	processConfig.systemdRunPath = "/bin/true";
	CHECK(vauthctl::run_managed_command(options, processConfig) == 0);

	processConfig.systemdRunPath = "/bin/false";
	CHECK(vauthctl::run_managed_command(options, processConfig) == 1);

	processConfig.systemdRunPath = "/not/a/real/systemd-run";
	check_throws<std::system_error>([&] {
		static_cast<void>(vauthctl::run_managed_command(options, processConfig));
	});
}

} // namespace

int main() {
	test_support::Runner runner;
	runner.run("provision arguments", test_provision_arguments);
	runner.run("list argument boundaries", test_list_preserves_each_argument_boundary);
	runner.run("delete and clear arguments", test_delete_and_clear_arguments);
	runner.run("invalid managed inputs", test_invalid_commands_and_paths_are_rejected);
	runner.run("managed context", test_managed_context_validation);
	runner.run("child exit status", test_child_exit_status_is_propagated);
	return runner.finish();
}
