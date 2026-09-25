#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 14 ]]; then
    echo "install_layout_test.sh received an unexpected argument count" >&2
    exit 2
fi

cmake_command=$1
build_directory=$2
build_configuration=$3
install_prefix=$4
bindir=$5
libexecdir=$6
systemd_unit_dir=$7
sysusers_dir=$8
udev_rules_dir=$9
dbus_policy_dir=${10}
pam_config_dir=${11}
install_ui=${12}
full_libexecdir=${13}
docdir=${14}

staging_directory=$(mktemp -d /tmp/vauth-install-layout-test.XXXXXX)
cleanup() {
    rm -rf -- "$staging_directory"
}
trap cleanup EXIT

staged_path() {
    local destination=$1
    if [[ $destination = /* ]]; then
        printf '%s%s' "$staging_directory" "$destination"
    else
        printf '%s%s/%s' "$staging_directory" "$install_prefix" "$destination"
    fi
}

DESTDIR=$staging_directory "$cmake_command" \
    --install "$build_directory" --config "$build_configuration"

daemon=$(staged_path "$libexecdir/vauth/vauthd")
control=$(staged_path "$bindir/vauthctl")
ui=$(staged_path "$bindir/vauth-ui")
main_unit=$(staged_path "$systemd_unit_dir/vauth.service")
socket_unit=$(staged_path "$systemd_unit_dir/vauth-pam-verifier.socket")
broker_unit=$(staged_path "$systemd_unit_dir/vauth-pam-verifier@.service")
sysusers=$(staged_path "$sysusers_dir/vauth.conf")
udev_rule=$(staged_path "$udev_rules_dir/70-vauth.rules")
dbus_policy=$(staged_path "$dbus_policy_dir/org.lamellix.vAuth.conf")
pam_policy=$(staged_path "$pam_config_dir/vauth")
project_license=$(staged_path "$docdir/LICENSE")
third_party_notices=$(staged_path "$docdir/THIRD_PARTY_NOTICES.md")

for executable in "$daemon" "$control"; do
    [[ -x $executable ]]
    [[ $(stat -c '%a' "$executable") == 755 ]]
done

if [[ $install_ui == ON ]]; then
    [[ -x $ui ]]
    [[ $(stat -c '%a' "$ui") == 755 ]]
else
    [[ ! -e $ui ]]
fi

for policy in \
    "$main_unit" \
    "$socket_unit" \
    "$broker_unit" \
    "$sysusers" \
    "$udev_rule" \
    "$dbus_policy" \
    "$pam_policy" \
    "$project_license" \
    "$third_party_notices"; do
    [[ -f $policy ]]
    [[ $(stat -c '%a' "$policy") == 644 ]]
done

grep -Fxq "ExecStart=$full_libexecdir/vauth/vauthd run" "$main_unit"
grep -Fxq "ExecStart=$full_libexecdir/vauth/vauthd pam-verifier" "$broker_unit"
grep -Fxq "Requires=vauth-pam-verifier.socket" "$main_unit"
grep -Fxq \
    "LoadCredentialEncrypted=vauth-db-auth:/etc/credstore.encrypted/vauth-db-auth" \
    "$main_unit"
grep -Fxq "ListenSequentialPacket=/run/vauth-pam-verifier.sock" "$socket_unit"
grep -Fxq "SocketGroup=vauth" "$socket_unit"
grep -Eq '^u[[:space:]]+vauth[[:space:]]' "$sysusers"
grep -Eq '^m[[:space:]]+vauth[[:space:]]+tss$' "$sysusers"
grep -q 'KERNEL=="uhid"' "$udev_rule"
grep -Fq '<policy user="vauth">' "$dbus_policy"
grep -Fq '<allow own="org.lamellix.vAuth"/>' "$dbus_policy"
grep -Fq 'pam_fprintd.so' "$pam_policy"
grep -Fq 'pam_unix.so try_first_pass' "$pam_policy"

if find "$staging_directory" -type f \
    \( -name 'vauth-agent-debug' -o -name 'libvauth_test_pam_module.so' \) \
    | grep -q .; then
    echo "Development-only artifacts were installed" >&2
    exit 1
fi

if find "$staging_directory" -type f -name 'vauth-db-auth' | grep -q .; then
    echo "The host-specific encrypted credential was installed" >&2
    exit 1
fi
