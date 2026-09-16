#pragma once

#include <string>
#include <string_view>

namespace vauth::log {

enum class Color {
    default_color,
    black,
    red,
    green,
    yellow,
    blue,
    magenta,
    purple = magenta,
    cyan,
    white,
    bright_black,
    bright_red,
    bright_green,
    bright_yellow,
    bright_blue,
    bright_magenta,
    bright_purple = bright_magenta,
    bright_cyan,
    bright_white,
};

[[nodiscard]] std::string colorize(Color color, std::string_view text);
void error(std::string_view source, std::string_view message) noexcept;
void debug(Color color, std::string_view message) noexcept;

}
