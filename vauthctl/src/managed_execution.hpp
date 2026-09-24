#pragma once

#include "options.hpp"

#include <string>
#include <string_view>
#include <sys/types.h>
#include <vector>

namespace vauthctl {

struct ManagedExecutionConfig {
	std::string systemdRunPath;
	std::string executablePath;
	std::string fapiSystemDirectory;
};

[[nodiscard]] std::vector<std::string> build_managed_arguments(
	const Options& options,
	const ManagedExecutionConfig& config
);
[[nodiscard]] int run_managed_command(
	const Options& options,
	const ManagedExecutionConfig& config
);

void validate_managed_context(
	uid_t effectiveUid,
	uid_t vauthUid,
	std::string_view credentialsDirectory
);
void require_managed_execution_context();

} // namespace vauthctl
