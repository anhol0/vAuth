#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <sdbus-c++/IConnection.h>
#include <string>
#include <string_view>

struct SystemdServiceState {
	std::string status;
	std::string sub;
};

[[nodiscard]] bool get_status(sdbus::IConnection& connection);
void provision(const std::optional<std::filesystem::path> authorizationPath);
void store_clear(const std::optional<std::filesystem::path> authorizationPath);
void credential_list(
	const std::optional<std::filesystem::path> authorizationPath,
	const std::optional<uint32_t> ownerUid,
	const std::optional<std::string> rp
);
void erase_credential(
	const std::optional<std::filesystem::path> authorizationPath,
	const uint32_t ownerUid,
	const std::string_view credentialId
);
