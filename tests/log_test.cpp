#include "log.hpp"
#include "test_runner.hpp"

#include <array>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>

namespace {

void check(bool condition, const char* expression, int line) {
    if(!condition) {
        throw std::runtime_error(
            "CHECK failed at line " + std::to_string(line) +
            ": " + expression
        );
    }
}

#define CHECK(expression) check((expression), #expression, __LINE__)

class StreamCapture {
public:
    explicit StreamCapture(std::ostream& stream)
        : stream_(stream), previous_(stream.rdbuf(output_.rdbuf())) {}

    ~StreamCapture() {
        stream_.rdbuf(previous_);
    }

    StreamCapture(const StreamCapture&) = delete;
    StreamCapture& operator=(const StreamCapture&) = delete;

    [[nodiscard]] std::string take() {
        std::string result = output_.str();
        output_.str({});
        output_.clear();
        return result;
    }

private:
    std::ostream& stream_;
    std::streambuf* previous_;
    std::ostringstream output_;
};

void test_all_colors() {
    const std::array colors{
        std::pair{vauth::log::Color::default_color, "\x1b[39m"},
        std::pair{vauth::log::Color::black, "\x1b[30m"},
        std::pair{vauth::log::Color::red, "\x1b[31m"},
        std::pair{vauth::log::Color::green, "\x1b[32m"},
        std::pair{vauth::log::Color::yellow, "\x1b[33m"},
        std::pair{vauth::log::Color::blue, "\x1b[34m"},
        std::pair{vauth::log::Color::magenta, "\x1b[35m"},
        std::pair{vauth::log::Color::cyan, "\x1b[36m"},
        std::pair{vauth::log::Color::white, "\x1b[37m"},
        std::pair{vauth::log::Color::bright_black, "\x1b[90m"},
        std::pair{vauth::log::Color::bright_red, "\x1b[91m"},
        std::pair{vauth::log::Color::bright_green, "\x1b[92m"},
        std::pair{vauth::log::Color::bright_yellow, "\x1b[93m"},
        std::pair{vauth::log::Color::bright_blue, "\x1b[94m"},
        std::pair{vauth::log::Color::bright_magenta, "\x1b[95m"},
        std::pair{vauth::log::Color::bright_cyan, "\x1b[96m"},
        std::pair{vauth::log::Color::bright_white, "\x1b[97m"},
    };

    StreamCapture capture(std::clog);
    for(const auto& [color, code] : colors) {
        vauth::log::debug(color, "message");
        CHECK(capture.take() == std::string(code) + "message\x1b[0m\n");
    }

    vauth::log::debug(vauth::log::Color::purple, "purple");
    CHECK(capture.take() == "\x1b[35mpurple\x1b[0m\n");
}

void test_error() {
    StreamCapture capture(std::cerr);
    vauth::log::error("vauth", "failed");
    CHECK(capture.take() == "\x1b[31mvauth: failed\x1b[0m\n");
}

void test_colorize() {
    CHECK(
        vauth::log::colorize(vauth::log::Color::green, "active") ==
        "\x1b[32mactive\x1b[0m"
    );
    CHECK(
        vauth::log::colorize(vauth::log::Color::bright_red, {}) ==
        "\x1b[91m\x1b[0m"
    );
}

}

int main() {
    test_support::Runner runner;
    runner.run("all ANSI foreground colors", test_all_colors);
    runner.run("error output", test_error);
    runner.run("colorized output", test_colorize);
    return runner.finish();
}
