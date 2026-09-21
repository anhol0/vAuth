#include "session_validation.hpp"

#include <stdexcept>
#include <system_error>
#include <systemd/sd-login.h>

namespace vauth {
namespace {

[[noreturn]] void throw_login_error(int result, const char* operation) {
    throw std::system_error(
        -result,
        std::generic_category(),
        operation
    );
}

} // namespace

LoginSessionProperties query_login_session(const std::string& session_id) {
    if(session_id.empty())
        throw std::invalid_argument("Login session ID must not be empty");

    uid_t uid = 0;
    const int uid_result = sd_session_get_uid(session_id.c_str(), &uid);
    if(uid_result < 0)
        throw_login_error(uid_result, "resolve login session user");

    const int active = sd_session_is_active(session_id.c_str());
    if(active < 0)
        throw_login_error(active, "inspect login session activity");

    const int remote = sd_session_is_remote(session_id.c_str());
    if(remote < 0)
        throw_login_error(remote, "inspect login session locality");

    return {
        .uid = uid,
        .active = active > 0,
        .remote = remote > 0
    };
}

void validate_active_local_session(
    const LoginSessionProperties& session,
    uid_t expected_uid
) {
    if(session.uid != expected_uid)
        throw std::runtime_error("Login session belongs to another user");
    if(!session.active)
        throw std::runtime_error("Login session is not active");
    if(session.remote)
        throw std::runtime_error("Remote login sessions are not allowed");
}

void require_active_local_session(
    const std::string& session_id,
    uid_t expected_uid
) {
    validate_active_local_session(
        query_login_session(session_id),
        expected_uid
    );
}

bool is_active_local_session(
    const std::string& session_id,
    uid_t expected_uid
) noexcept {
    try {
        require_active_local_session(session_id, expected_uid);
        return true;
    } catch(...) {
        return false;
    }
}

} // namespace vauth
