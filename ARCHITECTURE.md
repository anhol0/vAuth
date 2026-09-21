# vAuth architecture

This document describes the target architecture for the public release of
vAuth. It records process boundaries, privilege separation, trust decisions,
key ownership, persistent state, and the main protocol flows. It is not a
replacement for the normative CTAP specification or for the public interaction
agent API.

The normative authenticator protocol is the
[CTAP 2.0 Proposed Standard dated January 30, 2019](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html).
The D-Bus interaction protocol is documented in
[`docs/agent-api.md`](docs/agent-api.md).

## Design goals

vAuth is designed around the following boundaries:

- The main daemon processes untrusted CTAPHID and CBOR input without root
  privileges.
- The desktop UI displays requests and transports user responses, but never
  decides whether PAM authentication succeeded.
- PAM runs in a short-lived root process reached through a narrow, bounded
  protocol.
- Credential private keys remain TPM-wrapped. Assertion signing is performed
  by the TPM.
- The credential database is authenticated and encrypted, updated atomically,
  and protected against rollback with a TPM NV counter.
- Production secrets are delivered to narrowly scoped processes rather than
  stored as plaintext command-line arguments, environment variables, or
  ordinary configuration files.
- Every externally visible interaction has explicit ownership, bounded input,
  cancellation, timeout, and terminal states.

## Deployment and privilege boundaries

```mermaid
flowchart LR
    Client[Browser or native FIDO client]
    Kernel[Linux HID and UHID subsystem]

    subgraph DaemonBoundary[System service: UID vauth]
        Daemon[vauthd]
        Store[Credential store lock and cache]
        CTAP[CTAPHID and CTAP2 handlers]
    end

    subgraph UserSession[Active local login session]
        Agent[vauth-ui or trusted custom agent]
    end

    subgraph RootBoundary[Root verification boundary]
        Broker[Socket-activated PAM verifier broker]
        Worker[Short-lived PAM worker]
        PAM[PAM modules]
    end

    TPM[TPM via TPM2-TSS]
    Disk["/var/lib/vauth/credentials.v1"]
    Systemd[systemd service and credential manager]

    Client <--> Kernel
    Kernel <--> Daemon
    Daemon --- CTAP
    Daemon --- Store
    Daemon <--> |targeted system-bus API| Agent
    Daemon <--> |SOCK_SEQPACKET| Broker
    Broker <--> |private socket| Worker
    Worker <--> PAM
    Daemon <--> TPM
    Store <--> Disk
    Systemd --> |runtime authorization credential| Daemon
    Systemd --> |socket activation| Broker
```

The installed daemon executable is intended to be named `vauthd` and placed in
a non-interactive system executable directory such as
`/usr/libexec/vauth/vauthd`. The same executable has three internal modes:

| Mode | Identity | Purpose |
|---|---|---|
| `run` | `vauth` service user | UHID device, CTAP processing, D-Bus service, TPM operations, and credential store |
| `pam-verifier` | root, socket-activated | Authenticates the daemon peer, validates the requested login session, and supervises one PAM worker |
| `vauth_auth_handler` | root, child of the broker | Runs the PAM conversation and reports its result |

`vauth-ui` runs as the desktop user. `vauthctl` is a separate administration
program. Neither should be installed setuid.

The executable rename remains release work. The diagrams describe the intended
final state.

## Main daemon data path

```mermaid
flowchart TD
    UHID["/dev/uhid reports"]
    Event[Single owning event loop]
    Frames[CTAPHIDFrameProcessor]
    Worker[At most one CTAP worker]
    Dispatch[CTAPCommandHandler]
    Command[MakeCredential, GetAssertion, GetNextAssertion, or GetInfo]
    Interaction[UserInteraction boundary]
    Keys[CredentialKeyProvider]
    Store[CredentialStore]
    Response[CTAP response framing]

    UHID --> Event
    Event --> Frames
    Frames --> |complete validated request| Worker
    Worker --> Dispatch
    Dispatch --> Command
    Command --> Interaction
    Command --> Keys
    Command --> Store
    Command --> Response
    Response --> Event
    Event --> UHID
```

The event-loop thread owns the UHID descriptor, allocated channel set, frame
assembler, active-task record, keepalive schedule, and command handler. It
starts at most one long-running CTAP worker. Other channels receive the
appropriate busy response while that worker is active.

The worker observes a stop token throughout user interaction and TPM/storage
work. Completion is handed back under synchronization and joined before the
event loop reads the result or clears assertion-continuation state. A cancelled
operation cannot publish a cached assertion or commit a partially completed
credential operation.

`GetNextAssertion` continuation state belongs to the originating channel. It is
cleared on replacement, exhaustion, timeout where required, cancellation, and
error.

## User presence and verification

Presence and verification are separate authorities:

- The UI agent may approve or deny a user-presence prompt.
- Only PAM may report successful user verification.
- The daemon decides whether the completed ceremony permits the CTAP operation
  and sets the corresponding authenticator-data flags.

### Interaction and PAM sequence

```mermaid
sequenceDiagram
    participant C as CTAP worker in vauthd
    participant D as D-Bus interaction service
    participant U as UI agent
    participant B as Root verifier broker
    participant P as Root PAM worker
    participant M as PAM modules

    C->>D: begin interaction with request ID
    D-->>U: verification_started
    C->>B: StartVerification(targetUid, sessionId)
    B->>B: Verify SO_PEERCRED and validate session with logind
    B->>P: Start fixed PAM service for resolved username
    P->>M: pam_authenticate and pam_acct_mgmt

    loop Zero or more PAM messages
        M-->>P: information, error, or secret prompt
        P-->>B: bounded verifier message
        B-->>C: bounded verifier message
        C->>D: publish generic state or secret_required
        D-->>U: targeted StateChanged signal
        U->>D: one-shot secret pipe when required
        D-->>C: bounded sensitive response
        C-->>B: SecretResponse
        B-->>P: SecretResponse
        P-->>M: PAM conversation response
    end

    M-->>P: PAM result
    P-->>B: success, denied, or error
    B-->>C: VerificationComplete
    C->>D: terminal generic UI state
    D-->>U: verification_succeeded, verification_failed, cancelled, or timed_out
```

The daemon-to-broker connection uses one Unix `SOCK_SEQPACKET` connection per
verification. The broker obtains the peer identity with `SO_PEERCRED`, requires
the dedicated daemon UID, and validates through logind that the supplied
session exists, is active and local, and belongs to the supplied target UID.
It repeats the session validation before accepting PAM success. The broker
resolves the account name itself and uses fixed PAM service and configuration
values.

The broker remains responsive while PAM blocks. It forwards status and secret
messages, observes daemon cancellation or disconnect, terminates and reaps the
worker, and enforces the overall deadline.

PAM results are interpreted as follows:

| Result | Meaning inside vAuth | CTAP boundary |
|---|---|---|
| `success` | PAM authenticated the account and the trusted context is still current | Continue the operation and set UV when applicable |
| `denied` | PAM made an authoritative negative authentication or account-policy decision | `CTAP2_ERR_OPERATION_DENIED` |
| `error` | PAM, its configuration, the broker, or the verifier protocol failed to produce an authentication decision | `CTAP1_ERR_OTHER` |

The UI deliberately receives a generic failure state for both denial and
infrastructure failure. Detailed diagnostics remain in trusted service logs and
must never include authentication secrets.

## Interaction-agent trust boundary

The D-Bus service derives an agent's unique bus name, PID, UID, account name,
and login session from authenticated operating-system data. Registration is
limited to an active, local, non-remote logind session. One agent is registered
globally, and its bus name plus generation bind every request and response.

The API intentionally permits custom agents. Consequently, every process able
to register from an eligible login session is inside the documented interaction
trust boundary. The daemon does not treat the bundled UI executable as a
special identity.

Secrets cross D-Bus only through a bounded, one-shot pipe descriptor. The UI
must clear its field and buffers after submission. The daemon and verifier use
move-only sensitive buffers and clear them after consumption.

## Security material and key hierarchy

The production systemd credential named `vauth-db-auth` contains the FAPI
authorization value. It is not the database encryption key and it is not a
credential private key.

```mermaid
flowchart TD
    Admin[Provisioning authorization<br/>1 to 32 non-NUL bytes]
    EncryptedCredential["/etc/credstore.encrypted/vauth-db-auth"]
    RuntimeCredential["/run/credentials/.../vauth-db-auth"]

    Seal[FAPI sealed object<br/>/HS/SRK/vauth-database-key]
    Counter[FAPI NV counter<br/>/nv/Owner/vauth-db-generation]
    DatabaseKey[TPM-generated 256-bit database master key]
    Origin[Counter origin]

    StoreKey[AES-256-GCM store key]
    ParentAuth[HKDF-derived transient parent authorization]
    CredentialMaster[HKDF-derived credential authorization master]
    CredentialAuth[Per-credential authorization<br/>derived with credential ID]
    WrappedKeys[TPM-wrapped ES256 credential key blobs]

    Admin --> |systemd-creds encrypt| EncryptedCredential
    EncryptedCredential --> |systemd decrypts for the unit| RuntimeCredential
    RuntimeCredential --> |FAPI authorization callback| Seal
    RuntimeCredential --> |FAPI authorization callback| Counter
    Seal --> DatabaseKey
    Seal --> Origin
    DatabaseKey --> StoreKey
    DatabaseKey --> ParentAuth
    DatabaseKey --> CredentialMaster
    CredentialMaster --> CredentialAuth
    ParentAuth --> WrappedKeys
    CredentialAuth --> WrappedKeys
```

Provisioning performs these operations:

1. Create the authorized TPM NV rollback counter.
2. Increment it once and record that value as the counter origin.
3. Ask the TPM for a random 256-bit database key.
4. Seal the database key and counter origin together in the authorized FAPI
   seal.
5. Verify that the key can be unsealed and that the logical database generation
   begins at zero.

Both the sealed object and NV counter are created with the same supplied FAPI
authorization. `FapiStoreSecurity` provides that authorization only for the two
known object paths.

At startup, the daemon uses the authorization to unseal the database key. That
key encrypts the store and derives the authorizations protecting the transient
TPM parent and per-credential keys. The authorization is therefore required to
reach the database key, but it does not directly encrypt the database.

The systemd credential mechanism is the selected production delivery method
because it keeps the authorization encrypted at rest and exposes its plaintext
only in the service's private runtime credential directory. A mode-`0400`
authorization file remains available for development and explicit recovery.
Another equally protected secret-delivery mechanism could satisfy the same
cryptographic role; systemd credentials are an operational choice, not a TPM
format requirement.

Loss of either the TPM state or the authorization makes the database and its
credential keys unrecoverable. Recovery material must be handled separately
from the machine.

## Credential persistence and rollback protection

The credential store is `/var/lib/vauth/credentials.v1`. Its directory is
owned by `vauth` with mode `0700`; the file has mode `0600`. A non-blocking
exclusive lock on the directory prevents the daemon and management utility
from opening the store concurrently.

The encrypted envelope contains:

```text
magic || format version || generation || fresh 96-bit nonce || ciphertext || GCM tag
```

The header is authenticated as AES-256-GCM additional data. The decrypted JSON
contains credential metadata and TPM-wrapped private/public blobs; it does not
contain raw credential private keys.

### Durable update

```mermaid
flowchart TD
    Copy[Copy current in-memory map]
    Validate[Apply change and validate all records and bounds]
    Serialize[Serialize candidate generation]
    Encrypt[Encrypt with fresh AES-GCM nonce]
    Temp[Create same-directory mode-0600 temporary file]
    SyncFile[Write and fsync temporary file]
    Rename[Atomic rename over store]
    SyncDir[fsync store directory]
    Counter[Increment TPM NV generation exactly once]
    Publish[Replace in-memory state]

    Copy --> Validate --> Serialize --> Encrypt --> Temp --> SyncFile --> Rename --> SyncDir --> Counter --> Publish
```

The file is deliberately committed before the NV counter. On startup, a store
generation exactly one ahead of the counter is recognized as an interrupted
commit and the counter is advanced. A store behind the counter is rejected as
a rollback. Other generation mismatches are rejected as inconsistent.

The in-memory map is replaced only after the durable file and counter update
succeed. After an ambiguous counter failure, further writes require a reload so
that crash-recovery rules determine the authoritative state.

## TPM credential keys

Each FIDO credential has an ES256 key created by the TPM under a transient
primary parent. The database stores the TPM private and public blobs. To sign an
assertion, vAuth:

1. Recreates the transient parent using authorization derived from the database
   key.
2. Derives the credential authorization from the database key and credential
   ID.
3. Validates and loads the stored TPM blobs.
4. Asks the TPM to sign the assertion digest.
5. Converts the TPM ECDSA signature to the CTAP/WebAuthn response encoding.

RP ID and owner UID filtering occurs before a credential is selected.
Non-discoverable credentials are considered only when identified by an allow
list; resident discovery returns discoverable credentials only.

## Administration with vauthctl

`vauthctl status` queries systemd and the daemon's read-only D-Bus status API.
It does not need the database authorization.

Provisioning and credential-store commands need the same FAPI authorization as
the daemon. The final production path is a systemd-managed, one-shot invocation
running as the `vauth` service identity with:

- `LoadCredentialEncrypted=vauth-db-auth:...`;
- the TPM access required by FAPI;
- access to `/var/lib/vauth`;
- the same FAPI configuration as the daemon; and
- the daemon stopped, because direct management takes the exclusive store lock.

```mermaid
sequenceDiagram
    participant A as Administrator
    participant V as vauthctl
    participant S as systemd
    participant M as Managed vauthctl operation, UID vauth
    participant T as TPM and FAPI
    participant D as Credential store

    A->>V: provision, list, delete, or clear
    V->>S: request authorized one-shot operation
    S->>M: start with private decrypted credential
    M->>M: validate credential file ownership, mode, and size
    M->>T: authorize FAPI objects and unseal key
    M->>D: acquire exclusive lock and perform operation
    M-->>S: bounded result and exit status
    S-->>V: completion
    V-->>A: human-readable result
```

The exact installed management-unit interface is still release work. For
development and recovery, `--auth-file` explicitly supplies a protected
mode-`0400` file. The encrypted credential file itself must never be passed to
`--auth-file`; it is ciphertext that only systemd should decrypt.

A future daemon management API could allow mutation while the daemon is
running, but it would require privileged authorization and explicit store
synchronization. It is intentionally outside the initial release architecture.

## Filesystem and runtime ownership

| Resource | Owner or consumer | Purpose |
|---|---|---|
| `/usr/libexec/vauth/vauthd` | root-owned executable | Daemon and internal verifier modes |
| `/usr/bin/vauthctl` | root-owned executable, not setuid | Administration frontend |
| `/usr/bin/vauth-ui` | desktop user process | Bundled interaction agent |
| `/var/lib/vauth/` | `vauth:vauth`, mode `0700` | Credential store and its lock scope |
| `/var/lib/vauth/credentials.v1` | `vauth:vauth`, mode `0600` | Authenticated encrypted credential database |
| `/etc/credstore.encrypted/vauth-db-auth` | root-managed | Encrypted FAPI authorization credential |
| `/run/credentials/<unit>/vauth-db-auth` | private to the active unit | Decrypted runtime authorization supplied by systemd |
| `/run/vauth-pam-verifier.sock` | root-owned, group-restricted socket | Daemon-to-root-verifier transport |
| `/dev/uhid` | accessible to `vauth` service only as required | Virtual HID device creation and reports |
| `/dev/tpmrm0` | accessible to `vauth` service and managed admin operation | TPM resource-manager transport |

FAPI object storage is managed by TPM2-TSS according to its configured FAPI
profile and directories; vAuth does not define a second private FAPI keystore
under `/var/lib/vauth`.

## Failure and cancellation model

- Malformed transport or CTAP input is rejected at the narrowest parsing
  boundary before side effects.
- User denial is distinct from verifier infrastructure failure.
- UI cancellation and CTAPHID cancellation remain observable while PAM blocks.
- Losing the registered D-Bus name, changing login session, or changing agent
  generation invalidates pending interaction state.
- Losing either side of the verifier socket terminates the broker operation and
  its PAM worker.
- Sensitive buffers and TPM/FAPI allocations use RAII and are cleared or freed
  on every exit path.
- No code path falls back to daemon stdin, a terminal prompt, `getlogin()`, or a
  local dialog when the UI agent is absent.

## Release-completion work

The target architecture requires the following remaining implementation work:

1. Complete cancellation, disconnect, timeout, worker-reaping, and real PAM
   conversation integration tests.
2. Finalize and harden the installed socket/service units.
3. Add the systemd-backed execution path for privileged `vauthctl` operations.
4. Complete the installed daemon rename to `vauthd` and align packaging,
   service files, documentation, and tests.
