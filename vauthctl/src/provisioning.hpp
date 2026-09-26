#pragma once

#include <array>
#include <filesystem>
#include <iosfwd>
#include <string_view>

namespace vauthctl {

class ProvisioningAuthorization final {
public:
	ProvisioningAuthorization();
	~ProvisioningAuthorization();

	ProvisioningAuthorization(const ProvisioningAuthorization&) = delete;
	ProvisioningAuthorization& operator=(const ProvisioningAuthorization&) = delete;
	ProvisioningAuthorization(ProvisioningAuthorization&&) = delete;
	ProvisioningAuthorization& operator=(ProvisioningAuthorization&&) = delete;

	[[nodiscard]] std::string_view view() const noexcept;

private:
	std::array<char, 33> bytes_{};
};

struct ProvisioningConfig {
	std::filesystem::path systemdCredsPath;
	std::filesystem::path encryptedCredentialPath;
};

void ensure_provisioning_authorization(
	const ProvisioningConfig& config,
	std::istream& input,
	std::ostream& output,
	bool interactive
);

} // namespace vauthctl
