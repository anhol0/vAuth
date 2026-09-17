#include "commands.hpp"
#include "log.hpp"
#include "options.hpp"

#include <exception>
#include <iostream>
#include <sdbus-c++/Error.h>
#include <sdbus-c++/IConnection.h>

int main(int argc, char** argv) {
	const ParseResult parsed = parse_options(argc, argv);
	if(!parsed.options)
		return parsed.exitCode;

	auto authPath			 = parsed.options->authorizationPath;
	auto rpId				 = parsed.options->rpId;
	auto ownerId			 = parsed.options->ownerUid;
	auto credId				 = parsed.options->credentialId;
	auto confirmedDestroyAll = parsed.options->confirmedDestroyAll;

	try {
		switch(parsed.options->command) {
		case Command::status: {
			auto connection = sdbus::createSystemBusConnection();
			bool result		= get_status(*connection);
			return result;
		}
		case Command::provision: {
			provision(authPath);
			return 0;
		}
		case Command::credentialsClear:
			if(!confirmedDestroyAll) {
				vauth::log::error("vauthctl", "clear operation has to be confirmed with --confirm-destroy-all");
				return 1;
			}
			store_clear(authPath);
			return 0;
		case Command::credentialsList:
			credential_list(authPath, ownerId, rpId);
			return 0;
		case Command::credentialsDelete:
			if(!(ownerId && credId)) {
				vauth::log::error("vauthctl", "for erase operation you have to provide Owner ID and Credential ID with --owner <id> --id <id> respectively");
				return 1;
			}
			erase_credential(authPath, ownerId.value(), credId.value());
			return 0;
		}
	} catch(const sdbus::Error& error) {
		std::cerr << "D-Bus error: " << error.getName() << ": "
				  << error.getMessage() << "(" << error.what() << ")\n";
		return 1;
	} catch(const std::exception& e) {
		vauth::log::error("vauthctl", e.what());
		return 1;
	}

	return 0;
}
