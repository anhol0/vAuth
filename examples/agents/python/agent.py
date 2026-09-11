#!/usr/bin/env python3
"""Minimal vAuth presence agent using dbus-next.

This console example cancels password prompts. A graphical agent may call
submit_password() with a mutable buffer populated by a protected password
widget, then clear that widget and buffer immediately.
"""

import asyncio
import os
from typing import Optional

from dbus_next import BusType, Message, MessageType
from dbus_next.aio import MessageBus


SERVICE = "org.lamellix.vAuth"
PATH = "/org/lamellix/vAuth"
INTERFACE = "org.lamellix.vAuth.UserInteraction1"
START_STATES = {"presence_required", "verification_started"}
TERMINAL_STATES = {
    "presence_approved",
    "presence_denied",
    "verification_succeeded",
    "verification_failed",
    "cancelled",
    "timed_out",
}
KNOWN_STATES = START_STATES | TERMINAL_STATES | {
    "fingerprint_required",
    "fingerprint_failed",
    "password_required",
}


class Agent:
    def __init__(self) -> None:
        self.bus: Optional[MessageBus] = None
        self.interface = None
        self.generation = 0
        self.active_request: Optional[int] = None

    async def connect(self) -> None:
        self.bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
        introspection = await self.bus.introspect(SERVICE, PATH)
        proxy = self.bus.get_proxy_object(SERVICE, PATH, introspection)
        self.interface = proxy.get_interface(INTERFACE)

        # Subscribe before registration so an early directed event is queued.
        self.interface.on_state_changed(self.on_state_changed)
        self.generation = await self.interface.call_register_agent()
        if self.generation == 0:
            raise RuntimeError("daemon returned generation zero")
        print(f"registered generation {self.generation}")

    def on_state_changed(
        self,
        generation: int,
        request_id: int,
        state: str,
        operation: str,
        relying_party_id: str,
    ) -> None:
        asyncio.create_task(
            self.handle_state(
                generation, request_id, state, operation, relying_party_id
            )
        )

    async def handle_state(
        self,
        generation: int,
        request_id: int,
        state: str,
        operation: str,
        relying_party_id: str,
    ) -> None:
        if (
            generation != self.generation
            or request_id == 0
            or state not in KNOWN_STATES
        ):
            return
        if state in START_STATES:
            if self.active_request not in (None, request_id):
                return
            self.active_request = request_id
        elif self.active_request != request_id:
            return

        print(f"{state}: {operation} for RP {relying_party_id}")

        if state == "presence_required":
            answer = await asyncio.to_thread(
                input, "Approve? [y]es/[n]o/[c]ancel: "
            )
            try:
                if answer.strip().lower().startswith("c"):
                    await self.interface.call_cancel_interaction(
                        self.generation, request_id
                    )
                else:
                    await self.interface.call_respond_to_presence(
                        self.generation,
                        request_id,
                        answer.strip().lower().startswith("y"),
                    )
            except Exception as error:
                print(f"presence reply failed: {error}")
        elif state == "password_required":
            # Console strings cannot be reliably erased. A real UI should call
            # submit_password() with bytes from a protected password widget.
            try:
                await self.interface.call_cancel_interaction(
                    self.generation, request_id
                )
            except Exception as error:
                print(f"password cancellation failed: {error}")

        if state in TERMINAL_STATES:
            self.active_request = None

    async def submit_password(
        self, request_id: int, password: bytearray
    ) -> None:
        """Submit and erase a mutable password buffer."""
        read_fd = -1
        write_fd = -1
        try:
            if self.bus is None or self.active_request != request_id:
                raise RuntimeError("interaction is not active")
            if len(password) > 1024 or 0 in password:
                raise ValueError(
                    "password must be at most 1024 bytes without NUL"
                )

            read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
            written = 0
            while written < len(password):
                written += os.write(write_fd, memoryview(password)[written:])
            os.close(write_fd)
            write_fd = -1

            # A D-Bus 'h' value indexes the ancillary unix_fds array.
            reply = await self.bus.call(
                Message(
                    destination=SERVICE,
                    path=PATH,
                    interface=INTERFACE,
                    member="SubmitPassword",
                    signature="tth",
                    body=[self.generation, request_id, 0],
                    unix_fds=[read_fd],
                )
            )
            if reply.message_type == MessageType.ERROR:
                detail = str(reply.body[0]) if reply.body else "D-Bus error"
                raise RuntimeError(f"{reply.error_name}: {detail}")
        finally:
            if write_fd >= 0:
                os.close(write_fd)
            if read_fd >= 0:
                os.close(read_fd)
            password[:] = b"\0" * len(password)
            password.clear()

    async def close(self) -> None:
        if self.interface is not None and self.generation != 0:
            try:
                await self.interface.call_unregister_agent()
            except Exception:
                pass
        if self.bus is not None:
            self.bus.disconnect()


async def main() -> None:
    agent = Agent()
    await agent.connect()
    try:
        await asyncio.Future()
    finally:
        await agent.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
