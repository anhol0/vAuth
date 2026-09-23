#!/usr/bin/env bash
set -euo pipefail

analyzer=$1
main_unit=$2
broker_unit=$3
socket_unit=$4

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
