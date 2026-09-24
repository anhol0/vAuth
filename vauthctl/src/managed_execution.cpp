#include "managed_execution.hpp"

#include <cerrno>
#include <cstdlib>
#include <filesystem>
#include <limits>
#include <pwd.h>
#include <spawn.h>
#include <stdexcept>
#include <string>
#include <sys/wait.h>
#include <system_error>
#include <unistd.h>

extern char** environ;

namespace vauthctl {
namespace {

void append_command_arguments(std::vector<std::string>& arguments, const Options& options) {
	arguments.emplace_back("--managed");

	switch(options.command) {
	case Command::provision: arguments.emplace_back("provision"); return;
	case Command::credentialsList:
		arguments.emplace_back("credentials");
		arguments.emplace_back("list");
		if(options.ownerUid) {
			arguments.emplace_back("--owner");
			arguments.push_back(std::to_string(*options.ownerUid));
		}
		if(options.rpId) {
			arguments.emplace_back("--rp");
			arguments.push_back(*options.rpId);
		}
		return;
	case Command::credentialsDelete:
		if(!options.ownerUid || !options.credentialId)
			throw std::invalid_argument("delete requires an owner and "
										"credential ID");
		arguments.emplace_back("credentials");
		arguments.emplace_back("delete");
		arguments.emplace_back("--owner");
		arguments.push_back(std::to_string(*options.ownerUid));
		arguments.emplace_back("--id");
		arguments.push_back(*options.credentialId);
		return;
	case Command::credentialsClear:
		if(!options.confirmedDestroyAll)
			throw std::invalid_argument("clear requires explicit confirmation");
		arguments.emplace_back("credentials");
		arguments.emplace_back("clear");
		arguments.emplace_back("--confirm-destroy-all");
		return;
	case Command::status:
		throw std::invalid_argument("status is not a managed operation");
	}

	throw std::invalid_argument("Unknown vauthctl command");
}

uid_t vauth_uid() {
	long suggested_size = ::sysconf(_SC_GETPW_R_SIZE_MAX);
	if(suggested_size < 0)
		suggested_size = 16 * 1024;
	if(static_cast<unsigned long>(suggested_size) >
	   std::numeric_limits<std::size_t>::max()) {
		throw std::runtime_error("Password database buffer size is invalid");
	}

	std::vector<char> buffer(static_cast<std::size_t>(suggested_size));
	passwd entry{};
	passwd* result = nullptr;
	const int error = ::getpwnam_r("vauth", &entry, buffer.data(), buffer.size(), &result);
	if(error != 0)
		throw std::system_error(error, std::generic_category(), "look up vauth user");
	if(result == nullptr)
		throw std::runtime_error("The vauth system user does not exist");
	return entry.pw_uid;
}

} // namespace

std::vector<std::string>
build_managed_arguments(const Options& options, const ManagedExecutionConfig& config) {
	if(config.systemdRunPath.empty() || config.executablePath.empty() ||
	   config.fapiSystemDirectory.empty()) {
		throw std::invalid_argument("Managed execution paths must not be empty");
	}
	if(!std::filesystem::path(config.systemdRunPath).is_absolute() ||
	   !std::filesystem::path(config.executablePath).is_absolute() ||
	   !std::filesystem::path(config.fapiSystemDirectory).is_absolute()) {
		throw std::invalid_argument("Managed execution paths must be absolute");
	}

	std::vector<std::string> arguments{
		config.systemdRunPath,
		"--wait",
		"--pipe",
		"--collect",
		"--quiet",
		"--service-type=oneshot",
		"--uid=vauth",
		"--gid=vauth",
		"--property=SupplementaryGroups=tss",
		"--property=StateDirectory=vauth",
		"--property=StateDirectoryMode=0700",
		"--property=LoadCredentialEncrypted=vauth-db-auth:/etc/"
		"credstore.encrypted/vauth-db-auth",
		"--property=UMask=0077",
		"--property=NoNewPrivileges=yes",
		"--property=CapabilityBoundingSet=",
		"--property=AmbientCapabilities=",
		"--property=PrivateTmp=yes",
		"--property=PrivateNetwork=yes",
		"--property=PrivateIPC=yes",
		"--property=ProtectHome=yes",
		"--property=ProtectSystem=strict",
		"--property=ReadWritePaths=" + config.fapiSystemDirectory,
		"--property=InaccessiblePaths=/etc/credstore.encrypted",
		"--property=ProtectClock=yes",
		"--property=ProtectControlGroups=yes",
		"--property=ProtectHostname=yes",
		"--property=ProtectKernelLogs=yes",
		"--property=ProtectKernelModules=yes",
		"--property=ProtectKernelTunables=yes",
		"--property=ProtectProc=invisible",
		"--property=ProcSubset=pid",
		"--property=DevicePolicy=closed",
		"--property=DeviceAllow=/dev/tpmrm0 rw",
		"--property=RestrictAddressFamilies=AF_UNIX",
		"--property=RestrictNamespaces=yes",
		"--property=RestrictRealtime=yes",
		"--property=RestrictSUIDSGID=yes",
		"--property=LockPersonality=yes",
		"--property=MemoryDenyWriteExecute=yes",
		"--property=SystemCallArchitectures=native",
		"--property=SystemCallFilter=~@clock @cpu-emulation @debug @module "
		"@mount @obsolete @raw-io @reboot @swap",
		"--property=SystemCallErrorNumber=EPERM",
		"--property=KeyringMode=private",
		"--property=RemoveIPC=yes",
		"--property=LimitCORE=0",
		config.executablePath,
	};
	append_command_arguments(arguments, options);
	return arguments;
}

int run_managed_command(const Options& options, const ManagedExecutionConfig& config) {
	auto arguments = build_managed_arguments(options, config);
	std::vector<char*> argumentPointers;
	argumentPointers.reserve(arguments.size() + 1);
	for(auto& argument : arguments)
		argumentPointers.push_back(argument.data());
	argumentPointers.push_back(nullptr);

	pid_t child			 = -1;
	const int spawnError = ::posix_spawn(
		&child,
		config.systemdRunPath.c_str(),
		nullptr,
		nullptr,
		argumentPointers.data(),
		environ
	);
	if(spawnError != 0) {
		throw std::system_error(spawnError, std::generic_category(), "start privileged vauthctl operation");
	}

	int status = 0;
	while(::waitpid(child, &status, 0) == -1) {
		if(errno == EINTR)
			continue;
		throw std::system_error(errno, std::generic_category(), "wait for privileged vauthctl operation");
	}

	if(WIFEXITED(status))
		return WEXITSTATUS(status);
	if(WIFSIGNALED(status))
		return 128 + WTERMSIG(status);
	throw std::runtime_error("Privileged vauthctl operation ended unexpectedly");
}

void validate_managed_context(uid_t effectiveUid, uid_t vauthUid, std::string_view credentialsDirectory) {
	if(effectiveUid != vauthUid)
		throw std::runtime_error("Managed vauthctl operation must run as the "
								 "vauth user");
	if(credentialsDirectory.empty()) {
		throw std::runtime_error("Managed vauthctl operation requires systemd "
								 "credentials");
	}
	if(!std::filesystem::path(credentialsDirectory).is_absolute()) {
		throw std::runtime_error("CREDENTIALS_DIRECTORY must be an absolute "
								 "path");
	}
}

void require_managed_execution_context() {
	const char* credentialsDirectory = std::getenv("CREDENTIALS_DIRECTORY");
	validate_managed_context(
		::geteuid(),
		vauth_uid(),
		credentialsDirectory == nullptr ? std::string_view{} : std::string_view(credentialsDirectory)
	);
}

} // namespace vauthctl
