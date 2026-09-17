#pragma once

#include "credentials/credential.hpp"

#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <ostream>
#include <sdbus-c++/IConnection.h>
#include <span>
#include <string>
#include <string_view>
#include <vector>

struct SystemdServiceState {
	std::string status;
	std::string sub;
};

struct StatusReport {
	bool daemonRunning = false;
	std::optional<SystemdServiceState> systemdService;
	std::optional<bool> agentAvailable;
};

struct StatusQueries {
	std::function<bool()> daemonRunning;
	std::function<std::optional<SystemdServiceState>()> systemdService;
	// A disengaged result means that the daemon disappeared during the query.
	std::function<std::optional<bool>()> agentAvailable;
};

[[nodiscard]] StatusReport collect_status(const StatusQueries& queries);
[[nodiscard]] int print_status(const StatusReport& report, std::ostream& output);
void print_credentials(
	std::span<const CredentialSummary> credentials,
	const std::optional<uint32_t>& ownerUid,
	const std::optional<std::string>& rp,
	std::ostream& output
);
[[nodiscard]] std::vector<uint8_t> decode_credential_id(std::string_view credentialId);

[[nodiscard]] int get_status(sdbus::IConnection& connection);
void provision(const std::optional<std::filesystem::path> authorizationPath);
void store_clear(const std::optional<std::filesystem::path> authorizationPath);
void store_clear(const std::optional<std::filesystem::path> authorizationPath, const std::filesystem::path& storePath);
void credential_list(
	const std::optional<std::filesystem::path> authorizationPath,
	const std::optional<uint32_t> ownerUid,
	const std::optional<std::string> rp
);
void credential_list(
	const std::optional<std::filesystem::path> authorizationPath,
	const std::optional<uint32_t> ownerUid,
	const std::optional<std::string> rp,
	const std::filesystem::path& storePath
);
void erase_credential(
	const std::optional<std::filesystem::path> authorizationPath,
	const uint32_t ownerUid,
	const std::string_view credentialId
);
void erase_credential(
	const std::optional<std::filesystem::path> authorizationPath,
	uint32_t ownerUid,
	std::string_view credentialId,
	const std::filesystem::path& storePath
);
