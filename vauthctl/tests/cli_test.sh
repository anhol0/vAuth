#!/usr/bin/env bash
set -euo pipefail

binary=$1
test_directory=$(mktemp -d /tmp/vauthctl-cli-test.XXXXXX)

cleanup() {
    rm -rf -- "$test_directory"
}
trap cleanup EXIT

run_command() {
    local expected_status=$1
    shift
    set +e
    "$binary" "$@" >"$test_directory/stdout" 2>"$test_directory/stderr"
    local actual_status=$?
    set -e
    if [[ $actual_status -ne $expected_status ]]; then
        echo "Expected exit status $expected_status, received $actual_status: $*" >&2
        cat "$test_directory/stdout" >&2
        cat "$test_directory/stderr" >&2
        exit 1
    fi
}

run_command 0 --help
grep -q "Manage the vAuth authenticator" "$test_directory/stdout"
[[ ! -s "$test_directory/stderr" ]]

run_command 2
grep -q "A subcommand is required" "$test_directory/stderr"

run_command 2 unknown
grep -q "A subcommand is required" "$test_directory/stderr"

run_command 2 credentials clear
grep -q -- "--confirm-destroy-all is required" "$test_directory/stderr"

run_command 2 credentials delete --owner 1000 --id invalid
grep -q "Credential ID" "$test_directory/stderr"

missing_authorization=$test_directory/missing-authorization
run_command 1 credentials list --auth-file "$missing_authorization"
grep -q "open database authorization credential" "$test_directory/stderr"
if grep -q "credential store cleared" "$test_directory/stdout"; then
    echo "A failed command reported success" >&2
    exit 1
fi
