#include "application.hpp"

#include <stdexcept>

int execute_command(
	const Options& options,
	const CommandOperations& operations
) {
	if(options.command == Command::credentialsClear &&
	   !options.confirmedDestroyAll) {
		throw std::invalid_argument(
			"clear operation has to be confirmed with --confirm-destroy-all"
		);
	}
	if(options.command == Command::credentialsDelete &&
	   (!options.ownerUid || !options.credentialId)) {
		throw std::invalid_argument(
			"for erase operation you have to provide Owner ID and Credential ID "
			"with --owner <id> --id <id> respectively"
		);
	}

	if(options.command == Command::status) {
		if(options.managed)
			throw std::invalid_argument("status cannot run as a managed operation");
		return operations.status();
	}

	if(!options.managed)
		return operations.managed(options);

	switch(options.command) {
	case Command::provision:
		operations.provision();
		return 0;
	case Command::credentialsClear:
		operations.clear();
		return 0;
	case Command::credentialsList:
		operations.list(options.ownerUid, options.rpId);
		return 0;
	case Command::credentialsDelete:
		operations.erase(*options.ownerUid, *options.credentialId);
		return 0;
	case Command::status:
		break;
	}

	throw std::invalid_argument("Unknown vauthctl command");
}
