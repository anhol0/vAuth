#include "peer_credentials.hpp"

#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>

namespace vauth::dbus {
namespace {

constexpr std::string_view LOGIN_SERVICE = "org.freedesktop.login1";
constexpr std::string_view LOGIN_MANAGER_PATH =
    "/org/freedesktop/login1";
constexpr std::string_view LOGIN_MANAGER_INTERFACE =
    "org.freedesktop.login1.Manager";
constexpr std::string_view LOGIN_SESSION_INTERFACE =
    "org.freedesktop.login1.Session";

}

AuthenticatedBusPeer authenticate_bus_peer(const sdbus::MethodCall& call) {
    const char* sender = call.getSender();
    if(sender == nullptr || sender[0] != ':')
        throw std::runtime_error("Agent has no authenticated unique bus name");

    // The bus authenticates the effective UID directly. Requesting the real
    // UID may require a /proc lookup, which is intentionally unavailable under
    // ProtectProc=invisible when the agent belongs to another user.
    const uid_t effective_uid = call.getCredsEuid();
    const pid_t pid = call.getCredsPid();
    if(pid <= 0)
        throw std::runtime_error("Agent has no authenticated process ID");

    return {
        .effectiveUid = effective_uid,
        .pid = pid,
        .uniqueName = sender
    };
}

std::string login_session_for_bus_peer(
    sdbus::IConnection& connection,
    pid_t pid
) {
    if(
        pid <= 0 ||
        static_cast<uintmax_t>(pid) > std::numeric_limits<uint32_t>::max()
    ) {
        throw std::invalid_argument("Agent process ID is out of range");
    }

    auto manager = sdbus::createProxy(
        connection,
        sdbus::ServiceName{std::string(LOGIN_SERVICE)},
        sdbus::ObjectPath{std::string(LOGIN_MANAGER_PATH)}
    );
    sdbus::ObjectPath session_path;
    manager->callMethod("GetSessionByPID")
        .onInterface(std::string(LOGIN_MANAGER_INTERFACE))
        .withArguments(static_cast<uint32_t>(pid))
        .storeResultsTo(session_path);

    auto session = sdbus::createProxy(
        connection,
        sdbus::ServiceName{std::string(LOGIN_SERVICE)},
        session_path
    );
    std::string session_id = session->getProperty("Id")
        .onInterface(std::string(LOGIN_SESSION_INTERFACE))
        .get<std::string>();
    if(session_id.empty())
        throw std::runtime_error("Agent login session is empty");
    return session_id;
}

}
