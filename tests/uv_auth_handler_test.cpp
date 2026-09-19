#include "test_runner.hpp"
#include "uv/src/auth_handler.hpp"

#include <iostream>
#include <security/_pam_types.h>

namespace {

#define CHECK(condition) do { \
    if(!(condition)) { \
        std::cerr << "CHECK failed at " << __FILE__ << ':' << __LINE__ \
                  << ": " #condition "\n"; \
        return false; \
    } \
} while(false)

bool test_authentication_and_account_rejections_are_denied() {
    using vauth::uv::VerificationResult;
    for(const int status : {
        PAM_PERM_DENIED,
        PAM_AUTH_ERR,
        PAM_CRED_INSUFFICIENT,
        PAM_USER_UNKNOWN,
        PAM_MAXTRIES,
        PAM_NEW_AUTHTOK_REQD,
        PAM_ACCT_EXPIRED
    }) {
        CHECK(
            vauth::uv::verification_result_from_pam_status(status) ==
            VerificationResult::denied
        );
    }
    return true;
}

bool test_operational_failures_are_errors() {
    using vauth::uv::VerificationResult;
    for(const int status : {
        PAM_OPEN_ERR,
        PAM_SERVICE_ERR,
        PAM_SYSTEM_ERR,
        PAM_BUF_ERR,
        PAM_CONV_ERR,
        PAM_AUTHINFO_UNAVAIL,
        PAM_ABORT,
        PAM_MODULE_UNKNOWN,
        PAM_BAD_ITEM,
        0x7fffffff
    }) {
        CHECK(
            vauth::uv::verification_result_from_pam_status(status) ==
            VerificationResult::error
        );
    }
    return true;
}

bool test_success_is_preserved() {
    return vauth::uv::verification_result_from_pam_status(PAM_SUCCESS) ==
        vauth::uv::VerificationResult::success;
}

} // namespace

int main() {
    test_support::Runner runner;
    runner.run(
        "authentication and account rejections are denied",
        test_authentication_and_account_rejections_are_denied
    );
    runner.run(
        "operational failures are errors",
        test_operational_failures_are_errors
    );
    runner.run("success is preserved", test_success_is_preserved);
    return runner.finish();
}
