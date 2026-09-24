#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 5 ]]; then
    echo "systemd_units_test.sh received an unexpected argument count" >&2
    exit 2
fi

analyzer=$1
main_unit=$2
broker_unit=$3
socket_unit=$4
fapi_system_directory=$5

test_directory=$(mktemp -d /tmp/vauth-systemd-units-test.XXXXXX)
cleanup() {
    rm -rf -- "$test_directory"
}
trap cleanup EXIT

sed 's|^ExecStart=.*$|ExecStart=/bin/true|' \
    "$main_unit" >"$test_directory/vauth.service"
sed 's|^ExecStart=.*$|ExecStart=/bin/true|' \
    "$broker_unit" >"$test_directory/vauth-pam-verifier@.service"
cp "$socket_unit" "$test_directory/vauth-pam-verifier.socket"

"$analyzer" verify \
    "$test_directory/vauth.service" \
    "$test_directory/vauth-pam-verifier.socket" \
    "$test_directory/vauth-pam-verifier@.service"

require_directive() {
    local unit=$1
    local directive=$2
    if ! grep -Fxq "$directive" "$unit"; then
        echo "$unit is missing required directive: $directive" >&2
        exit 1
    fi
}

common_directives=(
    'NoNewPrivileges=yes'
    'CapabilityBoundingSet='
    'AmbientCapabilities='
    'PrivateTmp=yes'
    'PrivateNetwork=yes'
    'PrivateIPC=yes'
    'ProtectHome=yes'
    'ProtectSystem=strict'
    'ProtectClock=yes'
    'ProtectControlGroups=yes'
    'ProtectHostname=yes'
    'ProtectKernelLogs=yes'
    'ProtectKernelModules=yes'
    'ProtectKernelTunables=yes'
    'ProtectProc=invisible'
    'ProcSubset=pid'
    'RestrictAddressFamilies=AF_UNIX'
    'RestrictNamespaces=yes'
    'RestrictRealtime=yes'
    'RestrictSUIDSGID=yes'
    'LockPersonality=yes'
    'MemoryDenyWriteExecute=yes'
    'SystemCallArchitectures=native'
    'SystemCallFilter=~@clock @cpu-emulation @debug @module @mount @obsolete @raw-io @reboot @swap'
    'SystemCallErrorNumber=EPERM'
    'KeyringMode=private'
    'LimitCORE=0'
)

for directive in "${common_directives[@]}"; do
    require_directive "$main_unit" "$directive"
    require_directive "$broker_unit" "$directive"
done

require_directive "$main_unit" "ReadWritePaths=$fapi_system_directory"
require_directive "$main_unit" 'InaccessiblePaths=/etc/credstore.encrypted'
require_directive "$main_unit" 'DevicePolicy=closed'
require_directive "$main_unit" 'DeviceAllow=/dev/uhid rw'
require_directive "$main_unit" 'DeviceAllow=/dev/tpmrm0 rw'
require_directive "$main_unit" 'RemoveIPC=yes'
require_directive "$broker_unit" 'DevicePolicy=closed'
require_directive "$broker_unit" 'InaccessiblePaths=/var/lib/vauth'
require_directive "$broker_unit" 'InaccessiblePaths=/etc/credstore.encrypted'
require_directive "$broker_unit" "InaccessiblePaths=$fapi_system_directory"
require_directive "$broker_unit" 'TasksMax=32'
require_directive "$broker_unit" 'RuntimeMaxSec=45s'

if grep -Fxq 'DeviceAllow=/dev/tpm0 rw' "$main_unit"; then
    echo "$main_unit grants access to the raw TPM device" >&2
    exit 1
fi

if grep -q '^DeviceAllow=' "$broker_unit"; then
    echo "$broker_unit grants direct hardware-device access" >&2
    exit 1
fi
