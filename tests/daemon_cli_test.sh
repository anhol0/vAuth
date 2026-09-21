#!/usr/bin/env bash
set -euo pipefail

binary=$1
test_directory=$(mktemp -d /tmp/vauth-daemon-cli-test.XXXXXX)

cleanup() {
    rm -rf -- "$test_directory"
}
trap cleanup EXIT

check_auth_file_rejected() {
    set +e
    "$binary" "$@" >"$test_directory/stdout" 2>"$test_directory/stderr"
    local status=$?
    set -e

    if [[ $status -eq 0 ]]; then
        echo "Daemon accepted an authorization-file override: $*" >&2
        exit 1
    fi
    grep -q "Unknown option: --auth-file" "$test_directory/stderr"
    grep -q "Usage: vauth \[run\]" "$test_directory/stderr"
}

check_auth_file_rejected --auth-file "$test_directory/authorization"
check_auth_file_rejected run --auth-file "$test_directory/authorization"
