#pragma once

#include <string>
#include <sys/types.h>

namespace vauth {

struct LoginSessionProperties {
    uid_t uid;
    bool active;
    bool remote;
};

[[nodiscard]] LoginSessionProperties query_login_session(
    const std::string& session_id
);

void validate_active_local_session(
    const LoginSessionProperties& session,
    uid_t expected_uid
);

void require_active_local_session(
    const std::string& session_id,
    uid_t expected_uid
);

[[nodiscard]] bool is_active_local_session(
    const std::string& session_id,
    uid_t expected_uid
) noexcept;

} // namespace vauth
