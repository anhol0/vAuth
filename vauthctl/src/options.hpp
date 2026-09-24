#pragma once

#include <cstdint>
#include <optional>
#include <string>

enum class Command {
    status,
    provision,
    credentialsList,
    credentialsDelete,
    credentialsClear,
};

struct Options {
    Command command = Command::status;
    bool managed = false;
    std::optional<uint32_t> ownerUid;
    std::optional<std::string> rpId;
    std::optional<std::string> credentialId;
    bool confirmedDestroyAll = false;
};

struct ParseResult {
    std::optional<Options> options;
    int exitCode = 0;
};

[[nodiscard]] ParseResult parse_options(int argc, char** argv);
