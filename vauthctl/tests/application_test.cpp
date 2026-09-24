#include "application.hpp"
#include "test_runner.hpp"

#include <cstdint>
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

struct Calls {
	unsigned int status = 0;
	unsigned int managed = 0;
	unsigned int provision = 0;
	unsigned int clear = 0;
	unsigned int list = 0;
	unsigned int erase = 0;
	std::optional<Options> managedOptions;
	std::optional<uint32_t> ownerUid;
	std::optional<std::string> rpId;
	std::optional<std::string> credentialId;
};

CommandOperations recording_operations(Calls& calls, int statusResult = 0) {
	return {
		.status = [&calls, statusResult] {
			++calls.status;
			return statusResult;
		},
		.managed = [&calls](const Options& options) {
			++calls.managed;
			calls.managedOptions = options;
			return 23;
		},
		.provision = [&calls] { ++calls.provision; },
		.clear = [&calls] { ++calls.clear; },
		.list = [&calls](
			std::optional<uint32_t> ownerUid,
			const std::optional<std::string>& rpId
		) {
			++calls.list;
			calls.ownerUid = ownerUid;
			calls.rpId = rpId;
		},
		.erase = [&calls](uint32_t ownerUid, std::string_view credentialId) {
			++calls.erase;
			calls.ownerUid = ownerUid;
			calls.credentialId = credentialId;
		},
	};
}

Options options_for(Command command, bool managed = false) {
	Options options;
	options.command = command;
	options.managed = managed;
	return options;
}

unsigned int total_calls(const Calls& calls) {
	return calls.status + calls.managed + calls.provision + calls.clear +
		calls.list + calls.erase;
}

void test_status_dispatch_and_exit_code() {
	Calls calls;
	const auto operations = recording_operations(calls, 7);
	CHECK(execute_command(options_for(Command::status), operations) == 7);
	CHECK(calls.status == 1);
	CHECK(total_calls(calls) == 1);
}

void test_public_privileged_commands_use_managed_execution() {
	std::vector<Options> inputs;
	inputs.push_back(options_for(Command::provision));
	auto list = options_for(Command::credentialsList);
	list.ownerUid = 1000;
	list.rpId = "example.com";
	inputs.push_back(list);
	auto erase = options_for(Command::credentialsDelete);
	erase.ownerUid = 1001;
	erase.credentialId = std::string(64, 'a');
	inputs.push_back(erase);
	auto clear = options_for(Command::credentialsClear);
	clear.confirmedDestroyAll = true;
	inputs.push_back(clear);

	for(const Options& options : inputs) {
		Calls calls;
		const auto operations = recording_operations(calls);
		CHECK(execute_command(options, operations) == 23);
		CHECK(calls.managed == 1);
		CHECK(calls.managedOptions.has_value());
		CHECK(calls.managedOptions->command == options.command);
		CHECK(total_calls(calls) == 1);
	}
}

void test_managed_commands_dispatch_directly() {
	{
		Calls calls;
		const auto operations = recording_operations(calls);
		CHECK(execute_command(options_for(Command::provision, true), operations) == 0);
		CHECK(calls.provision == 1);
		CHECK(total_calls(calls) == 1);
	}
	{
		Calls calls;
		const auto operations = recording_operations(calls);
		auto options = options_for(Command::credentialsList, true);
		options.ownerUid = 1000;
		options.rpId = "example.com";
		CHECK(execute_command(options, operations) == 0);
		CHECK(calls.list == 1);
		CHECK(calls.ownerUid == options.ownerUid);
		CHECK(calls.rpId == options.rpId);
		CHECK(total_calls(calls) == 1);
	}
	{
		Calls calls;
		const auto operations = recording_operations(calls);
		auto options = options_for(Command::credentialsDelete, true);
		options.ownerUid = 1001;
		options.credentialId = std::string(64, 'b');
		CHECK(execute_command(options, operations) == 0);
		CHECK(calls.erase == 1);
		CHECK(calls.ownerUid == options.ownerUid);
		CHECK(calls.credentialId == options.credentialId);
		CHECK(total_calls(calls) == 1);
	}
	{
		Calls calls;
		const auto operations = recording_operations(calls);
		auto options = options_for(Command::credentialsClear, true);
		options.confirmedDestroyAll = true;
		CHECK(execute_command(options, operations) == 0);
		CHECK(calls.clear == 1);
		CHECK(total_calls(calls) == 1);
	}
}

void test_invalid_destructive_options_fail_before_dispatch() {
	auto missingId = options_for(Command::credentialsDelete);
	missingId.ownerUid = 1000;
	auto missingOwner = options_for(Command::credentialsDelete);
	missingOwner.credentialId = std::string(64, 'a');
	const auto unconfirmedClear = options_for(Command::credentialsClear);

	for(const Options& options : std::vector<Options>{
		std::move(missingId), std::move(missingOwner), unconfirmedClear
	}) {
		Calls calls;
		const auto operations = recording_operations(calls);
		check_throws<std::invalid_argument>([&] {
			static_cast<void>(execute_command(options, operations));
		});
		CHECK(total_calls(calls) == 0);
	}
}

void test_status_rejects_managed_mode() {
	Calls calls;
	const auto operations = recording_operations(calls);
	check_throws<std::invalid_argument>([&] {
		static_cast<void>(execute_command(options_for(Command::status, true), operations));
	});
	CHECK(total_calls(calls) == 0);
}

void test_operation_failure_propagates() {
	Calls calls;
	auto operations = recording_operations(calls);
	operations.provision = [] { throw std::runtime_error("simulated failure"); };
	check_throws<std::runtime_error>([&] {
		static_cast<void>(execute_command(options_for(Command::provision, true), operations));
	});
}

} // namespace

int main() {
	test_support::Runner runner;
	runner.run("status dispatch", test_status_dispatch_and_exit_code);
	runner.run("public privileged dispatch", test_public_privileged_commands_use_managed_execution);
	runner.run("managed direct dispatch", test_managed_commands_dispatch_directly);
	runner.run("invalid destructive options", test_invalid_destructive_options_fail_before_dispatch);
	runner.run("managed status rejected", test_status_rejects_managed_mode);
	runner.run("operation failure", test_operation_failure_propagates);
	return runner.finish();
}
