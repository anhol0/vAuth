#include "log.hpp"

#include <iostream>
#include <ostream>
#include <string_view>
#include <syncstream>

namespace vauth::log {
namespace {

constexpr std::string_view ANSI_DEFAULT = "\x1b[39m";
constexpr std::string_view ANSI_BLACK = "\x1b[30m";
constexpr std::string_view ANSI_RED = "\x1b[31m";
constexpr std::string_view ANSI_GREEN = "\x1b[32m";
constexpr std::string_view ANSI_YELLOW = "\x1b[33m";
constexpr std::string_view ANSI_BLUE = "\x1b[34m";
constexpr std::string_view ANSI_MAGENTA = "\x1b[35m";
constexpr std::string_view ANSI_CYAN = "\x1b[36m";
constexpr std::string_view ANSI_WHITE = "\x1b[37m";
constexpr std::string_view ANSI_BRIGHT_BLACK = "\x1b[90m";
constexpr std::string_view ANSI_BRIGHT_RED = "\x1b[91m";
constexpr std::string_view ANSI_BRIGHT_GREEN = "\x1b[92m";
constexpr std::string_view ANSI_BRIGHT_YELLOW = "\x1b[93m";
constexpr std::string_view ANSI_BRIGHT_BLUE = "\x1b[94m";
constexpr std::string_view ANSI_BRIGHT_MAGENTA = "\x1b[95m";
constexpr std::string_view ANSI_BRIGHT_CYAN = "\x1b[96m";
constexpr std::string_view ANSI_BRIGHT_WHITE = "\x1b[97m";
constexpr std::string_view ANSI_RESET = "\x1b[0m";

std::string_view color_code(Color color) noexcept {
    switch(color) {
        case Color::default_color: return ANSI_DEFAULT;
        case Color::black: return ANSI_BLACK;
        case Color::red: return ANSI_RED;
        case Color::green: return ANSI_GREEN;
        case Color::yellow: return ANSI_YELLOW;
        case Color::blue: return ANSI_BLUE;
        case Color::magenta: return ANSI_MAGENTA;
        case Color::cyan: return ANSI_CYAN;
        case Color::white: return ANSI_WHITE;
        case Color::bright_black: return ANSI_BRIGHT_BLACK;
        case Color::bright_red: return ANSI_BRIGHT_RED;
        case Color::bright_green: return ANSI_BRIGHT_GREEN;
        case Color::bright_yellow: return ANSI_BRIGHT_YELLOW;
        case Color::bright_blue: return ANSI_BRIGHT_BLUE;
        case Color::bright_magenta: return ANSI_BRIGHT_MAGENTA;
        case Color::bright_cyan: return ANSI_BRIGHT_CYAN;
        case Color::bright_white: return ANSI_BRIGHT_WHITE;
    }
    return ANSI_DEFAULT;
}

}

std::string colorize(Color color, std::string_view text) {
    const std::string_view code = color_code(color);
    std::string result;
    result.reserve(code.size() + text.size() + ANSI_RESET.size());
    result.append(code);
    result.append(text);
    result.append(ANSI_RESET);
    return result;
}

void error(std::string_view source, std::string_view message) noexcept {
    try {
        std::osyncstream output(std::cerr);
        output << ANSI_RED << source << ": " << message << ANSI_RESET << '\n';
    } catch(...) {
        // Logging must not obscure the original failure.
    }
}

void debug(Color color, std::string_view message) noexcept {
    try {
        std::osyncstream output(std::clog);
        output << colorize(color, message) << '\n';
    } catch(...) {
        // Debug logging must not affect daemon behavior.
    }
}

}
