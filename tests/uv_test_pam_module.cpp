#include <security/pam_ext.h>
#include <security/pam_modules.h>

#include <cstdlib>
#include <cstring>
#include <strings.h>

namespace {

constexpr const char* EXPECTED_SECRET = "vauth-test-secret";

}

PAM_EXTERN int pam_sm_authenticate(
    pam_handle_t* handle,
    int,
    int,
    const char**
) {
    int result = pam_info(handle, "Test PAM module is ready");
    if(result != PAM_SUCCESS)
        return result;

    char* response = nullptr;
    result = pam_prompt(
        handle,
        PAM_PROMPT_ECHO_OFF,
        &response,
        "%s",
        "Test password:"
    );
    if(result != PAM_SUCCESS)
        return result;
    if(response == nullptr)
        return PAM_CONV_ERR;

    const bool accepted = std::strcmp(response, EXPECTED_SECRET) == 0;
    explicit_bzero(response, std::strlen(response));
    std::free(response);
    if(accepted)
        return PAM_SUCCESS;

    result = pam_error(handle, "Test PAM module rejected the response");
    return result == PAM_SUCCESS ? PAM_AUTH_ERR : result;
}

PAM_EXTERN int pam_sm_setcred(
    pam_handle_t*,
    int,
    int,
    const char**
) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(
    pam_handle_t*,
    int,
    int,
    const char**
) {
    return PAM_SUCCESS;
}
