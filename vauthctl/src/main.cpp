#include "application.hpp"
#include "commands.hpp"
#include "log.hpp"
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
		const CommandOperations operations{
			.status =
				[] {
					auto connection = sdbus::createSystemBusConnection();
					return get_status(*connection);
				},
			.provision = [](const auto& authorization_path
						 ) { provision(authorization_path); },
			.clear = [](const auto& authorization_path
					 ) { store_clear(authorization_path); },
			.list = [](const auto& authorization_path,
					   std::optional<uint32_t> owner_uid,
					   const std::optional<std::string>& rp_id
					) { credential_list(authorization_path, owner_uid, rp_id); },
			.erase =
				[](const auto& authorization_path, uint32_t owner_uid, std::string_view credential_id) {
					erase_credential(authorization_path, owner_uid, credential_id);
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
