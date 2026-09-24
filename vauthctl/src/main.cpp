#include "application.hpp"
#include "commands.hpp"
#include "log.hpp"
#include "managed_config.hpp"
#include "managed_execution.hpp"
#include "options.hpp"

#include <cstdint>
#include <exception>
#include <iostream>
#include <optional>
#include <sdbus-c++/Error.h>
#include <sdbus-c++/IConnection.h>
#include <string>
#include <string_view>

int main(int argc, char** argv) {
	const ParseResult parsed = parse_options(argc, argv);
	if(!parsed.options)
		return parsed.exitCode;

	try {
		const vauthctl::ManagedExecutionConfig managedConfig{
			.systemdRunPath = std::string(vauthctl::systemdRunPath),
			.executablePath = std::string(vauthctl::installedExecutablePath),
			.fapiSystemDirectory = std::string(vauthctl::fapiSystemDirectory),
		};
		const CommandOperations operations{
			.status =
				[] {
					auto connection = sdbus::createSystemBusConnection();
					return get_status(*connection);
				},
			.managed = [&managedConfig](const Options& options) {
				return vauthctl::run_managed_command(options, managedConfig);
			},
			.provision = [] {
				vauthctl::require_managed_execution_context();
				provision(std::nullopt);
			},
			.clear = [] {
				vauthctl::require_managed_execution_context();
				store_clear(std::nullopt);
			},
			.list = [](std::optional<uint32_t> owner_uid,
					   const std::optional<std::string>& rp_id
					) {
				vauthctl::require_managed_execution_context();
				credential_list(std::nullopt, owner_uid, rp_id);
			},
			.erase =
				[](uint32_t owner_uid, std::string_view credential_id) {
					vauthctl::require_managed_execution_context();
					erase_credential(std::nullopt, owner_uid, credential_id);
				},
		};
		return execute_command(*parsed.options, operations);
	} catch(const sdbus::Error& error) {
		std::cerr << "D-Bus error: " << error.getName() << ": "
				  << error.getMessage() << "(" << error.what() << ")\n";
		return 1;
	} catch(const std::exception& e) {
		vauth::log::error("vauthctl", e.what());
		return 1;
	}
}
