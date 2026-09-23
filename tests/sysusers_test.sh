#!/usr/bin/env bash
set -euo pipefail

sysusers=$1
configuration=$2

test_root=$(mktemp -d /tmp/vauth-sysusers-test.XXXXXX)
cleanup() {
    rm -rf -- "$test_root"
}
trap cleanup EXIT

"$sysusers" --dry-run --root="$test_root" "$configuration"
