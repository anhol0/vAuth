#include <cerrno>
#include <cstdlib>
#include <fcntl.h>
#include <filesystem>
#include <iostream>
#include <optional>
#include <signal.h>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include <openssl/crypto.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <unistd.h>

#include "credentials/credential.hpp"
#include "cryptography/store_security.hpp"
#include "cryptography/tpm.hpp"
#include "dbus/agent_service.hpp"
#include "device.hpp"
#include "event.hpp"
#include "log.hpp"
#include "storage/authorization.hpp"
#include "uv/src/auth.hpp"
#include "uv/src/auth_handler.hpp"

namespace {

constexpr const char *STORE_PATH = "/var/lib/vauth/credentials.v1";

class ShutdownSignal {
  public:
    ShutdownSignal() {
        sigset_t signals;
        if (sigemptyset(&signals) != 0 || sigaddset(&signals, SIGINT) != 0 ||
            sigaddset(&signals, SIGTERM) != 0) {
            throw std::system_error(errno, std::generic_category(),
                                    "prepare shutdown signals");
        }
        if (sigprocmask(SIG_BLOCK, &signals, &previousMask_) != 0) {
            throw std::system_error(errno, std::generic_category(),
                                    "block shutdown signals");
        }
        maskInstalled_ = true;

        fd_ = signalfd(-1, &signals, SFD_CLOEXEC | SFD_NONBLOCK);
        if (fd_ < 0) {
            const int saved_errno = errno;
            static_cast<void>(
                sigprocmask(SIG_SETMASK, &previousMask_, nullptr));
            maskInstalled_ = false;
            throw std::system_error(saved_errno, std::generic_category(),
                                    "create shutdown signal descriptor");
        }
    }

    ~ShutdownSignal() {
        if (fd_ >= 0)
            static_cast<void>(close(fd_));
        if (maskInstalled_) {
            static_cast<void>(
                sigprocmask(SIG_SETMASK, &previousMask_, nullptr));
        }
    }

    ShutdownSignal(const ShutdownSignal &) = delete;
    ShutdownSignal &operator=(const ShutdownSignal &) = delete;

    [[nodiscard]] int native_handle() const noexcept { return fd_; }

  private:
    sigset_t previousMask_{};
    int fd_ = -1;
    bool maskInstalled_ = false;
};

struct Options {
    std::string command = "run";
    std::optional<std::filesystem::path> authorizationPath;
#ifdef VAUTH_DEVELOPMENT_BUILD
    bool confirmedClear = false;
#endif
};

[[noreturn]] void usage_error(const std::string &message) {
    std::string usage = "\nUsage: vauth [run|provision] [--auth-file PATH]";
#ifdef VAUTH_DEVELOPMENT_BUILD
    usage += "\n       vauth clear-store --yes [--auth-file PATH]"
             " (Debug builds only)";
#endif
    throw std::invalid_argument(message + usage);
}

Options parse_options(int argc, char **argv) {
    Options options;
    int index = 1;
    if (index < argc && argv[index][0] != '-') {
        options.command = argv[index++];
    }
    if (options.command != "run" && options.command != "provision"
#ifdef VAUTH_DEVELOPMENT_BUILD
        && options.command != "clear-store"
#endif
    ) {
        usage_error("Unknown command: " + options.command);
    }

    while (index < argc) {
        const std::string argument = argv[index++];
        if (argument == "--auth-file") {
            if (index >= argc) {
                usage_error("Incomplete option: --auth-file");
            }
            if (options.authorizationPath) {
                usage_error("--auth-file may be specified only once");
            }
            options.authorizationPath = argv[index++];
            continue;
        }
#ifdef VAUTH_DEVELOPMENT_BUILD
        if (argument == "--yes") {
            if (options.confirmedClear) {
                usage_error("--yes may be specified only once");
            }
            options.confirmedClear = true;
            continue;
        }
#endif
        usage_error("Unknown option: " + argument);
    }

#ifdef VAUTH_DEVELOPMENT_BUILD
    if (options.command == "clear-store" && !options.confirmedClear) {
        usage_error("clear-store requires --yes confirmation");
    }
    if (options.command != "clear-store" && options.confirmedClear) {
        usage_error("--yes is valid only with clear-store");
    }
#endif
    return options;
}

} // namespace

int main(int argc, char **argv) {
    if (argc >= 2 && std::string_view(argv[1]) == VAUTH_AUTH_HANDLER_COMMAND) {
        return run_vauth_auth_handler(argc - 2, argv + 2);
    }

    try {
        const Options options = parse_options(argc, argv);
        std::optional<ShutdownSignal> shutdown_signal;
        if (options.command == "run")
            shutdown_signal.emplace();

        StoreAuthorization authorization(
            store_authorization_path(options.authorizationPath));
        FapiStoreSecurity security(authorization.view());

        if (options.command == "provision") {
            security.provision();
            std::cout << "Database key and rollback counter provisioned\n";
            return 0;
        }

        CredentialStoreLock store_lock(STORE_PATH);
        auto database_key = security.unseal_key();
#ifdef VAUTH_DEVELOPMENT_BUILD
        if (options.command == "clear-store") {
            CredentialStore store(STORE_PATH, std::move(database_key),
                                  &security);
            store.load();
            store.clear();
            std::cout
                << "Credential store cleared; TPM security objects preserved\n";
            return 0;
        }
#endif
        CredentialKeyProvider key_provider(security.tcti(), database_key);
        CredentialStore store(STORE_PATH, std::move(database_key), &security);
        store.load();

        vauth::dbus::AgentService agent_service;
        FIDODevice device;
        device.init();
        std::cout << "UHID device created\n";
#ifdef DEBUG
        PamUserInteraction user_interaction("vauth", VAUTH_DEBUG_PAM_CONFIG_DIR,
                                            agent_service, agent_service);
#else
        PamUserInteraction user_interaction("vauth", "/etc/vauth/config",
                                            agent_service, agent_service);
#endif
        run(device, store, key_provider, user_interaction,
            shutdown_signal->native_handle());
        return 0;
    } catch (const std::exception &error) {
        vauth::log::error("vauth", error.what());
        return 1;
    }
}
