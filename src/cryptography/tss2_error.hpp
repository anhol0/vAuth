#pragma once
#include <stdexcept>
#include <string>
#include <string_view>

#include <tss2/tss2_common.h>
#include <tss2/tss2_rc.h>

[[noreturn]] inline void throw_tss_error(TSS2_RC result,
                                         std::string_view operation) {
    const char *description = Tss2_RC_Decode(result);
    throw std::runtime_error(
        std::string(operation) + " failed: " +
        (description != nullptr ? description : "unknown TSS2 error"));
}

void inline tss_check(TSS2_RC result, const char *operation) {
    if (result != TSS2_RC_SUCCESS) {
        throw_tss_error(result, std::string_view(operation));
    }
}
