# Custom agent examples

These minimal console programs demonstrate version 1 of the vAuth
user-interaction API:

- [`cpp/`](cpp/) uses sdbus-c++.
- [`python/`](python/) uses dbus-next.
- [`go/`](go/) uses godbus/dbus.

Run only one agent at a time, from an active local logind session. Each example
asks before approving `presence_required`, tracks the registration generation
and request ID, and cancels password prompts by default. It includes a password
submission helper to show correct Unix-file-descriptor transfer, but a real UI
must supply that helper with a bounded mutable buffer from a protected password
widget and erase the buffer after the call.

These programs are educational starting points, not hardened user interfaces.
Read the complete [`agent API and security requirements`](../../docs/agent-api.md)
before adapting one.
