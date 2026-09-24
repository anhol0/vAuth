#pragma once

#include "options.hpp"

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

struct CommandOperations {
	std::function<int()> status;
	std::function<int(const Options&)> managed;
	std::function<void()> provision;
	std::function<void()> clear;
	std::function<void(std::optional<uint32_t>, const std::optional<std::string>&)> list;
	std::function<void(uint32_t, std::string_view)> erase;
};

[[nodiscard]] int execute_command(const Options& options, const CommandOperations& operations);
