#!/usr/bin/env bash
set -euo pipefail

test_binary=$1
dbus_daemon=$2
mapfile -t bus < <(
    "$dbus_daemon" --session --fork --print-address=1 --print-pid=1
)
if [[ ${#bus[@]} -ne 2 ]]; then
    echo "dbus-daemon did not return an address and PID" >&2
    exit 1
fi
bus_address=${bus[0]}
bus_pid=${bus[1]}

cleanup() {
    kill "$bus_pid" >/dev/null 2>&1 || true
    wait "$bus_pid" >/dev/null 2>&1 || true
}
trap cleanup EXIT

"$test_binary" "$bus_address"
