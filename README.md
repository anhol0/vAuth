# vAuth

vAuth is a Lamellix Labs virtual FIDO2 authenticator for Linux. It exposes a
virtual security key through `/dev/uhid`, implements selected CTAP2 operations,
uses PAM for user verification, and keeps credential records in an
AES-256-GCM-encrypted database. Database security material and credential keys
are protected by the system TPM.

The credential database is stored at `/var/lib/vauth/credentials.v1`. vAuth
supports resident and non-resident credentials, user presence and verification,
self-attestation, and TPM-backed assertion signing.

The complete target process, privilege, key, persistence, and administration
design is documented in [`ARCHITECTURE.md`](ARCHITECTURE.md).

## Build and test

The build requires CMake, a C++20 compiler, pkg-config, TinyCBOR, OpenSSL,
TPM2-TSS ESAPI/FAPI/RC/MU, PAM, sdbus-c++, libsystemd, Slint, and rlottie
development files.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

The resulting executables are `build/vauthd` and `build/vauth-ui`. The
software-TPM integration test is enabled when `swtpm` and the TPM2/FAPI
command-line tools are installed.

The unprivileged UI can also be built independently:

```sh
cmake -S client -B client/build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF
cmake --build client/build --parallel
```

Before running the daemon as the `vauth` service user, install the system-bus
policy and reload the bus configuration:

```sh
sudo install -m 0644 config/org.lamellix.vAuth.conf \
  /etc/dbus-1/system.d/org.lamellix.vAuth.conf
sudo busctl call org.freedesktop.DBus /org/freedesktop/DBus \
  org.freedesktop.DBus ReloadConfig
```

Run `./build/vauth-ui` as the desktop user before starting a WebAuthn ceremony.
It registers once with the daemon, remains resident, and opens its Slint window
only when presence or verification is required. Without an active registered
agent, vAuth rejects operations that require user interaction; it never falls
back to daemon stdin or a local dialog. Passwords are submitted through a
bounded one-shot Unix pipe rather than as D-Bus string values.

Debug builds also produce `build/vauth-agent-debug`, which provides the same
D-Bus responses through a console interface for diagnostics. Run only one UI
agent at a time.

## Custom user-interaction agents

The bundled Slint UI is not the only supported user-interaction agent. Local
applications may implement the public system-bus interface
`org.lamellix.vAuth.UserInteraction1` at `/org/lamellix/vAuth` on the
`org.lamellix.vAuth` service. The interface is versioned; agents must use the
method and signal signatures for the advertised interface name rather than
assuming that a future version is compatible.

The complete wire protocol, state machine, error behavior, and security
requirements are documented in [`docs/agent-api.md`](docs/agent-api.md). A
machine-readable introspection definition is available at
[`docs/org.lamellix.vAuth.UserInteraction1.xml`](docs/org.lamellix.vAuth.UserInteraction1.xml),
and minimal C++, Python, and Go implementations are in
[`examples/agents/`](examples/agents/).

Call `RegisterAgent()` once on a D-Bus connection before handling interactions.
It returns a nonzero `generation`. The daemon sends that connection targeted
`StateChanged(generation, requestId, promptId, state, operation,
relyingPartyId, message)` signals.
Reply with `RespondToPresence(generation, requestId, approved)`,
`SubmitSecret(generation, requestId, promptId, secretPipe)`, or
`CancelInteraction(generation, requestId)` as appropriate. `UnregisterAgent()`
has no arguments. Each request ID is nonzero and one-shot; an agent must ignore
events for another generation or for a request that has already reached a
terminal state.

Verification secrets must be written to a newly created one-shot Unix pipe and
submitted as its read descriptor. They must be at most 1024 bytes, must not
contain NUL, and must be erased from UI and application buffers immediately
after submission. An agent must not send secrets in D-Bus strings, run PAM
itself, claim that verification succeeded, or retain authentication input.
Custom graphical agents should run unprivileged and disable core dumps just as
the bundled UI does.

### Agent trust model

The API is intentionally open to custom agents. The daemon authenticates the
caller's D-Bus unique name, operating-system UID and PID, and requires an active,
local, non-remote logind session. It does not authenticate the executable as the
bundled vAuth UI. Exactly one agent is registered globally: the first eligible
caller remains the agent until it unregisters, disconnects, or its session stops
being active. A new registration receives a new generation and invalidates the
old interaction context.

This means every process in an eligible login session is inside the interaction-
agent trust boundary. A hostile process could register before the intended UI,
approve or deny presence requests, suppress the real UI, or present a deceptive
secret prompt. Users should run only trusted custom agents, and deployments
that do not accept this same-session threat model must restrict registration
with a narrower D-Bus policy or an additional authorization mechanism. The
current single-agent design is intended for single-seat use; multi-seat systems
need additional device-to-session routing before they can safely serve more than
one simultaneously active local session.

## Provision database security objects

TPM2-TSS FAPI must be provisioned once for the system. Skip the first command if
`tss2_provision` has already completed successfully:

```sh
sudo tss2_provision
```

vAuth provisioning creates an authorized sealed database key at
`/HS/SRK/vauth-database-key` and an authorized rollback counter at
`/nv/Owner/vauth-db-generation`. Normal startup never creates or replaces these
objects.

For a system service, create an encrypted systemd credential and provision vAuth
with it:

```sh
sudo install -d -m 0700 /etc/credstore.encrypted
sudo systemd-creds encrypt --name=vauth-db-auth - \
  /etc/credstore.encrypted/vauth-db-auth
sudo systemd-run --wait --pipe --property=Type=oneshot \
  --property=LoadCredentialEncrypted=vauth-db-auth:/etc/credstore.encrypted/vauth-db-auth \
  /usr/bin/vauthctl provision
```

Enter a non-empty authorization of at most 32 bytes when prompted. Keep recovery
material separately: clearing the TPM or losing this authorization makes the
database unrecoverable. The service template is available at
[`config/vauth.service.in`](config/vauth.service.in) and is configured and
installed by CMake.

For local provisioning and recovery, `vauthctl` can read a protected
mode-`0400` authorization file directly:

```sh
sudo ./build/vauthctl/vauthctl provision --auth-file .dev/vauth-db-auth
```

The daemon does not accept an authorization-file override. Run it through its
systemd unit, which supplies `vauth-db-auth` with `LoadCredentialEncrypted`.

Provisioning generates the database key and rollback counter. The transient TPM
parent is recreated when vAuth starts, and individual credential keys are
created when passkeys are registered.
