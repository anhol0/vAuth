#include "dbus/peer_credentials.hpp"
#include "test_runner.hpp"

#include <sdbus-c++/sdbus-c++.h>

#include <atomic>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
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

constexpr std::string_view SERVICE =
    "org.lamellix.vAuth.PeerCredentialsTest";
constexpr std::string_view OBJECT =
    "/org/lamellix/vAuth/PeerCredentialsTest";
constexpr std::string_view INTERFACE =
    "org.lamellix.vAuth.PeerCredentialsTest";
constexpr std::string_view LOGIN_SERVICE = "org.freedesktop.login1";
constexpr std::string_view LOGIN_MANAGER_PATH =
    "/org/freedesktop/login1";
constexpr std::string_view LOGIN_MANAGER_INTERFACE =
    "org.freedesktop.login1.Manager";
constexpr std::string_view LOGIN_SESSION_PATH =
    "/org/freedesktop/login1/session/test";
constexpr std::string_view LOGIN_SESSION_INTERFACE =
    "org.freedesktop.login1.Session";

bool test_authenticated_peer_credentials(const std::string& address) {
    std::atomic<uint32_t> queried_pid = 0;
    auto logind = sdbus::createSessionBusConnectionWithAddress(address);
    logind->requestName(sdbus::ServiceName{std::string(LOGIN_SERVICE)});
    auto login_manager = sdbus::createObject(
        *logind,
        sdbus::ObjectPath{std::string(LOGIN_MANAGER_PATH)}
    );
    auto get_session = sdbus::registerMethod("GetSessionByPID");
    get_session.implementedAs([&](uint32_t pid) {
        queried_pid.store(pid);
        return sdbus::ObjectPath{std::string(LOGIN_SESSION_PATH)};
    });
    auto login_manager_slot = login_manager->addVTable(
        std::move(get_session)
    ).forInterface(
        std::string(LOGIN_MANAGER_INTERFACE),
        sdbus::return_slot
    );

    auto login_session = sdbus::createObject(
        *logind,
        sdbus::ObjectPath{std::string(LOGIN_SESSION_PATH)}
    );
    auto session_id = sdbus::registerProperty("Id");
    session_id.withGetter([] { return std::string{"test-session"}; });
    auto login_session_slot = login_session->addVTable(
        std::move(session_id)
    ).forInterface(
        std::string(LOGIN_SESSION_INTERFACE),
        sdbus::return_slot
    );
    logind->enterEventLoopAsync();

    auto service = sdbus::createSessionBusConnectionWithAddress(address);
    service->requestName(sdbus::ServiceName{std::string(SERVICE)});
    auto object = sdbus::createObject(
        *service,
        sdbus::ObjectPath{std::string(OBJECT)}
    );

    auto inspect = sdbus::registerMethod("Inspect");
    inspect.outputSignature = sdbus::Signature{"uuss"};
    inspect.outputParamNames = {
        "effectiveUid", "pid", "uniqueName", "sessionId"
    };
    inspect.callbackHandler = [&](sdbus::MethodCall call) {
        const auto peer = vauth::dbus::authenticate_bus_peer(call);
        const std::string session =
            vauth::dbus::login_session_for_bus_peer(*service, peer.pid);
        auto reply = call.createReply();
        reply << static_cast<uint32_t>(peer.effectiveUid)
              << static_cast<uint32_t>(peer.pid)
              << peer.uniqueName
              << session;
        reply.send();
    };
    auto slot = object->addVTable(std::move(inspect)).forInterface(
        std::string(INTERFACE),
        sdbus::return_slot
    );
    service->enterEventLoopAsync();

    auto client = sdbus::createSessionBusConnectionWithAddress(address);
    auto proxy = sdbus::createProxy(
        *client,
        sdbus::ServiceName{std::string(SERVICE)},
        sdbus::ObjectPath{std::string(OBJECT)}
    );
    uint32_t effective_uid = 0;
    uint32_t pid = 0;
    std::string unique_name;
    std::string session;
    proxy->callMethod("Inspect")
        .onInterface(std::string(INTERFACE))
        .storeResultsTo(effective_uid, pid, unique_name, session);

    service->leaveEventLoop();
    logind->leaveEventLoop();
    static_cast<void>(slot);
    static_cast<void>(login_manager_slot);
    static_cast<void>(login_session_slot);
    CHECK(effective_uid == static_cast<uint32_t>(geteuid()));
    CHECK(pid == static_cast<uint32_t>(getpid()));
    CHECK(queried_pid.load() == pid);
    CHECK(!unique_name.empty());
    CHECK(unique_name.front() == ':');
    CHECK(session == "test-session");
    return true;
}

}

int main(int argc, char** argv) {
    try {
        if(argc != 2)
            throw std::invalid_argument("Expected private D-Bus address");
        test_support::Runner runner;
        runner.run("authenticated D-Bus peer credentials", [&] {
            return test_authenticated_peer_credentials(argv[1]);
        });
        return runner.finish();
    } catch(const std::exception& error) {
        std::cerr << "Test invocation failed: " << error.what() << '\n';
        return 1;
    }
}
