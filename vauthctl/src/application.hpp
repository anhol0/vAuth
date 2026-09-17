#pragma once

#include "options.hpp"

#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

struct CommandOperations {
	std::function<int()> status;
	std::function<void(const std::optional<std::filesystem::path>&)> provision;
	std::function<void(const std::optional<std::filesystem::path>&)> clear;
	std::function<void(const std::optional<std::filesystem::path>&, std::optional<uint32_t>, const std::optional<std::string>&)> list;
	std::function<void(const std::optional<std::filesystem::path>&, uint32_t, std::string_view)> erase;
};

[[nodiscard]] int execute_command(const Options& options, const CommandOperations& operations);
