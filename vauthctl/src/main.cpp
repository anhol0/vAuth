#include "options.hpp"

int main(int argc, char** argv) {
    const ParseResult parsed = parse_options(argc, argv);
    if(!parsed.options) {
        return parsed.exitCode;
    }

    // Command dispatch will be added with the command implementations.
    return 0;
}
