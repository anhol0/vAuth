#pragma once

#include <sdbus-c++/sdbus-c++.h>

#include <string>
#include <sys/types.h>

namespace vauth::dbus {

struct AuthenticatedBusPeer {
    uid_t effectiveUid;
    pid_t pid;
    std::string uniqueName;
};

[[nodiscard]] AuthenticatedBusPeer authenticate_bus_peer(
    const sdbus::MethodCall& call
);

[[nodiscard]] std::string login_session_for_bus_peer(
    sdbus::IConnection& connection,
    pid_t pid
);

}
