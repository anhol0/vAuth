#!/bin/sh
set -eu

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_directory/../../.." && pwd)

if [ -z "${VAUTH_SLINT_DIR:-}" ]; then
    echo "Set VAUTH_SLINT_DIR to the static Slint CMake package directory." >&2
    echo "Example: VAUTH_SLINT_DIR=/opt/slint-static/lib/cmake/Slint $0" >&2
    exit 2
fi
case "$VAUTH_SLINT_DIR" in
    /*) ;;
    *)
        echo "VAUTH_SLINT_DIR must be an absolute path" >&2
        exit 2
        ;;
esac
if [ ! -f "$VAUTH_SLINT_DIR/SlintConfig.cmake" ]; then
    echo "SlintConfig.cmake was not found under VAUTH_SLINT_DIR" >&2
    exit 2
fi

for command_name in dpkg-buildpackage dpkg-parsechangelog git lintian tar; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "Required command is missing: $command_name" >&2
        exit 2
    fi
done

if [ -n "$(git -C "$repository_root" status --porcelain --untracked-files=normal)" ]; then
    echo "Commit or remove working-tree changes before building a package." >&2
    exit 2
fi

package_version=$(dpkg-parsechangelog \
    -l"$script_directory/changelog" \
    -SVersion)
upstream_version=${package_version%-*}

workspace=$(mktemp -d "${TMPDIR:-/tmp}/vauth-debian.XXXXXX")
cleanup() {
    rm -rf -- "$workspace"
}
trap cleanup EXIT HUP INT TERM

source_directory="$workspace/vauth-$upstream_version"
mkdir -p "$source_directory"
git -C "$repository_root" archive --format=tar HEAD |
    tar -xf - -C "$source_directory"
cp -a \
    "$source_directory/packaging/debian/vauth-0.1.0" \
    "$source_directory/debian"

export VAUTH_SLINT_DIR
(
    cd "$source_directory"
    dpkg-buildpackage --build=binary --no-sign
)

set -- "$workspace"/*.changes
if [ ! -e "$1" ]; then
    echo "dpkg-buildpackage produced no changes file" >&2
    exit 1
fi
lintian "$@"

output_directory=${VAUTH_DEB_OUTPUT_DIR:-$script_directory/out}
mkdir -p "$output_directory"
artifact_count=0
for artifact in \
    "$workspace"/*.buildinfo \
    "$workspace"/*.changes \
    "$workspace"/*.deb
do
    if [ -e "$artifact" ]; then
        cp -a "$artifact" "$output_directory/"
        artifact_count=$((artifact_count + 1))
    fi
done
if [ "$artifact_count" -eq 0 ]; then
    echo "No package artifacts were produced" >&2
    exit 1
fi

echo "Debian package artifacts are in $output_directory"
