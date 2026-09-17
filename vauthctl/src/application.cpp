#include "application.hpp"

#include <stdexcept>

int execute_command(
	const Options& options,
	const CommandOperations& operations
) {
	switch(options.command) {
	case Command::status:
		return operations.status();
	case Command::provision:
		operations.provision(options.authorizationPath);
		return 0;
	case Command::credentialsClear:
		if(!options.confirmedDestroyAll) {
			throw std::invalid_argument(
				"clear operation has to be confirmed with "
				"--confirm-destroy-all"
			);
		}
		operations.clear(options.authorizationPath);
		return 0;
	case Command::credentialsList:
		operations.list(
			options.authorizationPath,
			options.ownerUid,
			options.rpId
		);
		return 0;
	case Command::credentialsDelete:
		if(!options.ownerUid || !options.credentialId) {
			throw std::invalid_argument(
				"for erase operation you have to provide Owner ID and "
				"Credential ID with --owner <id> --id <id> respectively"
			);
		}
		operations.erase(
			options.authorizationPath,
			*options.ownerUid,
			*options.credentialId
		);
		return 0;
	}

	throw std::invalid_argument("Unknown vauthctl command");
}
