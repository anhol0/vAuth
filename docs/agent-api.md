# User-interaction agent API

This document defines version 1 of the public D-Bus API used by unprivileged
user-interface agents. The bundled Slint UI uses the same interface as custom
agents.

## Endpoint and wire types

| Property | Value |
|---|---|
| Bus | System bus |
| Destination | `org.lamellix.vAuth` |
| Object path | `/org/lamellix/vAuth` |
| Interface | `org.lamellix.vAuth.UserInteraction1` |

The interface suffix is its version. An incompatible revision will use a new
interface name. The matching introspection XML is
[`org.lamellix.vAuth.UserInteraction1.xml`](org.lamellix.vAuth.UserInteraction1.xml).

The signatures below use standard D-Bus types: `t` is an unsigned 64-bit
integer, `b` is a boolean, `s` is a UTF-8 string, and `h` is a Unix file
descriptor.

Communication is asymmetric:

- The daemon sends the `StateChanged` signal to the registered agent.
- The agent sends method calls to the daemon. Version 1 defines no signals sent
  by the agent.
- Every method has an empty successful reply except `RegisterAgent`, which
  returns a generation.

## Registration and ownership

### `RegisterAgent() -> generation: t`

Register once on the connection that will receive signals and send replies. A
successful call returns a nonzero generation. The daemon derives the caller's
unique bus name, PID, UID, account name, and login session from authenticated
operating-system and D-Bus data; the agent supplies none of them.

Registration succeeds only for an active, local, non-remote logind session.
There is one agent globally. The first eligible caller remains registered until
it unregisters, disconnects, or its session stops being active. Another caller
receives `org.lamellix.vAuth.Error.RegistrationFailed`. Repeating registration
on the same connection is idempotent while its binding remains current.

The generation is bound to the registered unique bus name and login session.
Keep it for all replies. Reconnection or a new registration creates a new
binding; events and replies from an older generation are stale.

### `UnregisterAgent() -> ()`

Unregister the calling connection. This method has no input arguments. Only the
currently registered unique bus sender may call it. Unregistration invalidates
any pending interaction. Calling it from another connection returns
`org.lamellix.vAuth.Error.NotRegistered`.

A disconnect has the same invalidating effect, so explicit unregister is useful
for orderly shutdown but is not required after a process or bus failure.

Agents are expected to register before a ceremony and remain resident. When an
operation needs interaction and no agent is registered, the daemon currently
allows a two-second startup grace and then fails the operation closed; version 1
does not define a D-Bus activation request for launching an agent.

## Daemon-to-agent signal

### `StateChanged(t generation, t requestId, s state, s operation, s relyingPartyId)`

This signal is targeted to the registered unique bus name rather than
broadcast. Its fields are:

| Field | Meaning |
|---|---|
| `generation` | Registration generation that must equal the value returned by `RegisterAgent` |
| `requestId` | Nonzero daemon-issued identifier for one interaction |
| `state` | State-machine value listed below |
| `operation` | CTAP ceremony or reason for the interaction |
| `relyingPartyId` | RP ID to show to the user; do not treat it as a trusted display name |

Agents must reject unknown state values, ignore another generation, and track at
most one nonterminal request ID. A first signal for an interaction is either
`presence_required` or `verification_started`. Terminal signals close the
request ID; late UI callbacks must not send a reply for it.

### Operation values

| Value | Meaning |
|---|---|
| `make_credential` | Create a new credential for the displayed RP ID |
| `get_assertion` | Use an existing credential for the displayed RP ID |
| `check_excluded_credential` | Confirm presence before reporting that the RP already has an excluded credential |

Agents should handle an unknown future operation conservatively: show a generic
authentication message containing the RP ID and do not infer extra authority
from the operation string.

### State values

| State | Terminal | Agent behavior |
|---|---:|---|
| `presence_required` | No | Ask for an explicit user decision, then call `RespondToPresence` or `CancelInteraction` |
| `presence_approved` | Yes | Show optional success feedback; send no reply |
| `presence_denied` | Yes | Show optional denial feedback; send no reply |
| `verification_started` | No | Show verification progress; PAM is running in the daemon helper |
| `fingerprint_required` | No | Ask the user to use the configured fingerprint authenticator; send no success claim |
| `fingerprint_failed` | No | Show failure/retry feedback; the daemon still controls PAM |
| `password_required` | No | Collect one password and call `SubmitPassword`, or call `CancelInteraction` |
| `verification_succeeded` | Yes | Show optional success feedback; send no reply |
| `verification_failed` | Yes | Show optional failure feedback; send no reply |
| `cancelled` | Yes | Close the UI and erase pending input |
| `timed_out` | Yes | Close the UI and erase pending input |

The daemon may repeat or move between verification-progress states as PAM
progresses. Agents must not assume that fingerprint states always occur or that
`password_required` follows `fingerprint_failed`.

Presence and verification interactions currently have a 30-second daemon-side
deadline. The agent must still wait for a terminal signal instead of maintaining
an independent authoritative timeout.

The valid high-level flows are:

```text
presence_required
  -> presence_approved | presence_denied | cancelled | timed_out

verification_started
  -> fingerprint_required | fingerprint_failed | password_required
  -> verification_succeeded | verification_failed | cancelled | timed_out
```

Any verification-progress state may be followed by another verification-
progress state before a terminal result.

## Agent-to-daemon methods

All reply methods authenticate the calling unique bus name and require the
current generation and request ID. A stale, foreign, duplicate, late, or
state-inappropriate call returns
`org.lamellix.vAuth.Error.InvalidInteraction`.

### `RespondToPresence(t generation, t requestId, b approved) -> ()`

Valid only while the matching request is in `presence_required`.
`approved=true` permits the ceremony to continue; `approved=false` denies it.
The response is one-shot. Do not call `CancelInteraction` or send another
presence response after this method succeeds.

Approval is only a user-presence decision. The agent does not authenticate the
user and cannot claim user verification.

### `SubmitPassword(t generation, t requestId, h passwordPipe) -> ()`

Valid only while the matching request is in `password_required`. It is one-shot
for the interaction. `passwordPipe` must be the read descriptor of a newly
created Unix pipe containing only the password bytes:

1. Create a pipe with close-on-exec descriptors.
2. Write at most 1024 bytes to its write end. Embedded NUL bytes are forbidden;
   do not append a newline or terminating NUL.
3. Close the write end before calling `SubmitPassword`.
4. Pass the read descriptor as D-Bus type `h`.
5. Close local descriptors after the synchronous method call completes and
   erase every mutable password buffer immediately.

The daemon rejects regular files, sockets, open writer ends, oversized values,
embedded NUL, duplicate submissions, and submissions in any other state. It
reads the descriptor once and never accepts password bytes in a D-Bus string.
The daemon, not the agent, runs PAM and publishes the resulting state.

### `CancelInteraction(t generation, t requestId) -> ()`

Request cancellation of the current nonterminal interaction. Use this when the
user closes the UI or explicitly cancels. The daemon later publishes
`cancelled`; method success itself is not the terminal state notification.

Cancellation is one-shot and is rejected after a presence response, another
cancellation, or a terminal state. Erase pending password input immediately
without waiting for the terminal signal.

## Errors and lifecycle rules

| Error name | Meaning |
|---|---|
| `org.lamellix.vAuth.Error.RegistrationFailed` | Registration identity/session validation failed or another agent is registered |
| `org.lamellix.vAuth.Error.NotRegistered` | `UnregisterAgent` did not come from the current agent |
| `org.lamellix.vAuth.Error.InvalidInteraction` | A reply was stale, foreign, duplicate, late, malformed at the interaction layer, or invalid for the current state |

The bus may return a standard D-Bus error before the daemon handler runs when a
method name or wire signature is wrong. Agents should treat every method error,
loss of the daemon name, bus disconnect, generation mismatch, or unknown state
as fail-closed: invalidate the local request and erase sensitive input.

Signals can arrive soon after registration. Install the signal match before
calling `RegisterAgent`, then activate event processing and filter queued events
against the returned generation. Never reuse a request ID across generations.

## Security requirements for custom agents

- Require an explicit action for `presence_required`; never auto-approve it.
- Display the RP ID and operation so the user can identify the request. The RP
  ID is protocol context, not a verified human-readable application name.
- Run unprivileged in the user's login session. Graphical agents should disable
  core dumps and prevent screenshots or accessibility export where their UI
  toolkit permits it.
- Keep password data in mutable, bounded buffers, clear UI fields before
  submission, and overwrite buffers immediately afterwards.
- Never log passwords, descriptors, full request payloads, or other secrets.
- Never run PAM or report authentication success. Only the daemon publishes
  verification terminal states.
- Bind every UI callback to both generation and request ID. Disable controls
  after the first response so duplicate callbacks cannot reply.
- Treat disconnect, session change, cancellation, timeout, and terminal states
  as reasons to close the UI and clear all local interaction state.

## Trust model

The API intentionally permits custom agents. The daemon verifies membership in
an active local login session, but does not authenticate the executable as the
bundled vAuth UI. Therefore every process able to register from that session is
inside the interaction-agent trust boundary. A hostile process can race to
register, approve or deny presence, suppress the intended UI, or present a
deceptive password prompt.

Deployments that do not accept that boundary must narrow the system-bus policy
or add an authorization mechanism. Version 1 is also globally single-agent and
is intended for single-seat use; it does not safely route one system-wide UHID
request among multiple simultaneously active seats.

## Examples

Minimal C++, Python, and Go console agents are provided in
[`examples/agents/`](../examples/agents/). They demonstrate registration,
directed signal handling, generation/request filtering, presence replies,
cancellation, and the Unix-descriptor password submission primitive. They
deliberately cancel password prompts because ordinary console strings are not an
appropriate production password UI.
