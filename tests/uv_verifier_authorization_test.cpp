#include "session_validation.hpp"
#include "test_runner.hpp"
#include "uv/src/pam_verifier_service.hpp"

#include <iostream>
#include <stdexcept>
#include <unistd.h>
#include <utility>

namespace {

#define CHECK(condition) do { \
    if(!(condition)) { \
        std::cerr << "CHECK failed at " << __FILE__ << ':' << __LINE__ \
                  << ": " #condition "\n"; \
        return false; \
    } \
} while(false)

template<typename Function>
bool rejects(Function&& function) {
    try {
        std::forward<Function>(function)();
    } catch(const std::exception&) {
        return true;
    }
    return false;
}

vauth::uv::StartVerification request() {
    return {
        .targetUid = 1000,
        .sessionId = "session-2"
    };
}

vauth::LoginSessionProperties session() {
    return {
        .uid = 1000,
        .active = true,
        .remote = false
    };
}

bool test_expected_daemon_peer_is_authorized() {
    const uid_t daemon_uid = 999;
    vauth::uv::authorize_verifier_peer(
        {
            .pid = getpid(),
            .uid = daemon_uid,
            .gid = 999
        },
        daemon_uid
    );
    return true;
}

bool test_wrong_daemon_peer_is_rejected() {
    CHECK(rejects([] {
        vauth::uv::authorize_verifier_peer(
            {
                .pid = getpid(),
                .uid = 1000,
                .gid = 1000
            },
            999
        );
    }));
    CHECK(rejects([] {
        vauth::uv::authorize_verifier_peer(
            {
                .pid = 0,
                .uid = 999,
                .gid = 999
            },
            999
        );
    }));
    return true;
}

bool test_active_local_matching_session_is_authorized() {
    vauth::uv::authorize_verification_session(request(), session());
    return true;
}

bool test_wrong_session_owner_is_rejected() {
    auto properties = session();
    properties.uid = 1001;
    CHECK(rejects([&] {
        vauth::uv::authorize_verification_session(request(), properties);
    }));
    return true;
}

bool test_empty_session_id_is_rejected() {
    auto invalid_request = request();
    invalid_request.sessionId.clear();
    CHECK(rejects([&] {
        vauth::uv::authorize_verification_session(
            invalid_request,
            session()
        );
    }));
    return true;
}

bool test_inactive_session_is_rejected() {
    auto properties = session();
    properties.active = false;
    CHECK(rejects([&] {
        vauth::uv::authorize_verification_session(request(), properties);
    }));
    return true;
}

bool test_remote_session_is_rejected() {
    auto properties = session();
    properties.remote = true;
    CHECK(rejects([&] {
        vauth::uv::authorize_verification_session(request(), properties);
    }));
    return true;
}

} // namespace

int main() {
    test_support::Runner runner;
    runner.run(
        "expected daemon peer is authorized",
        test_expected_daemon_peer_is_authorized
    );
    runner.run(
        "wrong daemon peer is rejected",
        test_wrong_daemon_peer_is_rejected
    );
    runner.run(
        "active local matching session is authorized",
        test_active_local_matching_session_is_authorized
    );
    runner.run(
        "wrong session owner is rejected",
        test_wrong_session_owner_is_rejected
    );
    runner.run(
        "empty session ID is rejected",
        test_empty_session_id_is_rejected
    );
    runner.run(
        "inactive session is rejected",
        test_inactive_session_is_rejected
    );
    runner.run(
        "remote session is rejected",
        test_remote_session_is_rejected
    );
    return runner.finish();
}
