#include "commands.hpp"
#include "test_runner.hpp"

#include <sdbus-c++/sdbus-c++.h>

#include <atomic>
#include <iostream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace {

void check(bool condition, const char* expression, int line) {
    if(!condition) {
        throw std::runtime_error(
            "CHECK failed at line " + std::to_string(line) +
            ": " + expression
        );
    }
}

#define CHECK(expression) check((expression), #expression, __LINE__)

bool contains(std::string_view text, std::string_view expected) {
    return text.find(expected) != std::string_view::npos;
}

struct RenderedStatus {
    int exitCode;
    std::string output;
};

RenderedStatus capture_status(sdbus::IConnection& connection) {
    std::ostringstream output;
    auto* previous = std::cout.rdbuf(output.rdbuf());
    try {
        const int result = get_status(connection);
        std::cout.rdbuf(previous);
        return {.exitCode = result, .output = output.str()};
    } catch(...) {
        std::cout.rdbuf(previous);
        throw;
    }
}

void test_status_over_private_dbus(const std::string& address) {
    std::atomic_bool unit_loaded = true;
    std::atomic_bool agent_available = true;
    std::atomic_bool agent_access_denied = false;
    std::atomic_bool daemon_disappeared = false;

    auto systemd_connection =
        sdbus::createSessionBusConnectionWithAddress(address);
    systemd_connection->requestName(
        sdbus::ServiceName{"org.freedesktop.systemd1"}
    );
    auto manager = sdbus::createObject(
        *systemd_connection,
        sdbus::ObjectPath{"/org/freedesktop/systemd1"}
    );
    auto get_unit = sdbus::registerMethod("GetUnit");
    get_unit.implementedAs(
        [&](const std::string& unit_name) -> sdbus::ObjectPath {
            if(unit_name != "vauth.service") {
                throw sdbus::Error(
                    sdbus::Error::Name{
                        "org.freedesktop.systemd1.NoSuchUnit"
                    },
                    "Unknown test unit"
                );
            }
            if(!unit_loaded.load()) {
                throw sdbus::Error(
                    sdbus::Error::Name{
                        "org.freedesktop.systemd1.NoSuchUnit"
                    },
                    "Test unit is not loaded"
                );
            }
            return sdbus::ObjectPath{
                "/org/freedesktop/systemd1/unit/vauth_2eservice"
            };
        }
    );
    auto manager_slot = manager->addVTable(std::move(get_unit)).forInterface(
        "org.freedesktop.systemd1.Manager",
        sdbus::return_slot
    );

    auto unit = sdbus::createObject(
        *systemd_connection,
        sdbus::ObjectPath{
            "/org/freedesktop/systemd1/unit/vauth_2eservice"
        }
    );
    auto active_state = sdbus::registerProperty("ActiveState");
    active_state.withGetter([] { return std::string{"active"}; });
    auto sub_state = sdbus::registerProperty("SubState");
    sub_state.withGetter([] { return std::string{"running"}; });
    auto unit_slot = unit->addVTable(
        std::move(active_state),
        std::move(sub_state)
    ).forInterface("org.freedesktop.systemd1.Unit", sdbus::return_slot);
    systemd_connection->enterEventLoopAsync();

    auto daemon_connection =
        sdbus::createSessionBusConnectionWithAddress(address);
    daemon_connection->requestName(
        sdbus::ServiceName{"org.lamellix.vAuth"}
    );
    auto daemon = sdbus::createObject(
        *daemon_connection,
        sdbus::ObjectPath{"/org/lamellix/vAuth"}
    );
    auto has_agent = sdbus::registerMethod("HasAvailableAgent");
    has_agent.implementedAs([&] {
        if(agent_access_denied.load()) {
            throw sdbus::Error(
                sdbus::Error::Name{
                    "org.freedesktop.DBus.Error.AccessDenied"
                },
                "Simulated access denial"
            );
        }
        if(daemon_disappeared.load()) {
            throw sdbus::Error(
                sdbus::Error::Name{
                    "org.freedesktop.DBus.Error.ServiceUnknown"
                },
                "Simulated daemon disappearance"
            );
        }
        return agent_available.load();
    });
    auto daemon_slot = daemon->addVTable(std::move(has_agent)).forInterface(
        "org.lamellix.vAuth.Status1",
        sdbus::return_slot
    );
    daemon_connection->enterEventLoopAsync();

    auto client = sdbus::createSessionBusConnectionWithAddress(address);

    auto rendered = capture_status(*client);
    CHECK(rendered.exitCode == 0);
    CHECK(contains(rendered.output, "● running"));
    CHECK(contains(rendered.output, "● active (running)"));
    CHECK(contains(rendered.output, "● agent connected"));

    agent_available = false;
    rendered = capture_status(*client);
    CHECK(rendered.exitCode == 0);
    CHECK(contains(rendered.output, "● agent not connected"));

    unit_loaded = false;
    rendered = capture_status(*client);
    CHECK(rendered.exitCode == 0);
    CHECK(contains(rendered.output, "● unit not loaded"));

    unit_loaded = true;
    daemon_disappeared = true;
    rendered = capture_status(*client);
    CHECK(rendered.exitCode == 1);
    CHECK(contains(rendered.output, "● unavailable (daemon not running)"));

    daemon_disappeared = false;
    agent_access_denied = true;
    bool access_denied = false;
    try {
        static_cast<void>(capture_status(*client));
    } catch(const sdbus::Error& error) {
        access_denied = error.getName() ==
            "org.freedesktop.DBus.Error.AccessDenied";
    }
    CHECK(access_denied);

    agent_access_denied = false;
    daemon_slot.reset();
    auto malformed_has_agent = sdbus::registerMethod("HasAvailableAgent");
    malformed_has_agent.implementedAs([] {
        return std::string{"not-a-boolean"};
    });
    auto malformed_daemon_slot = daemon->addVTable(
        std::move(malformed_has_agent)
    ).forInterface("org.lamellix.vAuth.Status1", sdbus::return_slot);
    bool malformed_reply_rejected = false;
    try {
        static_cast<void>(capture_status(*client));
    } catch(const sdbus::Error&) {
        malformed_reply_rejected = true;
    }
    CHECK(malformed_reply_rejected);

    daemon_connection->releaseName(
        sdbus::ServiceName{"org.lamellix.vAuth"}
    );
    rendered = capture_status(*client);
    CHECK(rendered.exitCode == 1);
    CHECK(contains(rendered.output, "● not running"));

    daemon_connection->leaveEventLoop();
    systemd_connection->leaveEventLoop();
    static_cast<void>(manager_slot);
    static_cast<void>(unit_slot);
    static_cast<void>(malformed_daemon_slot);
}

} // namespace

int main(int argc, char** argv) {
    try {
        if(argc != 2)
            throw std::invalid_argument("Expected private D-Bus address");
        test_support::Runner runner;
        runner.run("test_status_over_private_dbus", [&] {
            test_status_over_private_dbus(argv[1]);
        });
        return runner.finish();
    } catch(const std::exception& error) {
        std::cerr << "Test invocation failed: " << error.what() << '\n';
        return 1;
    }
}
