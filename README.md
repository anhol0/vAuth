# vAuth

<p align="center">
  <img src="https://raw.githubusercontent.com/lamellixlabs/vAuth/refs/heads/main/vauth.svg" alt="vAuth logo" width="600">
</p>

[![Built with Slint](https://img.shields.io/badge/Built%20with-Slint-2379F4?logo=slint&logoColor=white)](https://slint.dev/)
[![License](https://img.shields.io/github/license/lamellixlabs/vAuth)](https://github.com/lamellixlabs/vAuth/blob/main/LICENSE)
![C++20](https://img.shields.io/badge/C%2B%2B-20-00599C?logo=cplusplus&logoColor=white)
![Linux](https://img.shields.io/badge/platform-Linux-FCC624?logo=linux&logoColor=black)
![FIDO2](https://img.shields.io/badge/FIDO2-CTAP2.0-blue)
![TPM](https://img.shields.io/badge/TPM-2.0-blue)
![Status](https://img.shields.io/badge/status-public_beta-blue)

> [!WARNING]
> **Public beta limitations**
>
> - The first prebuilt package targets Debian 13 on amd64.
> - vAuth requires systemd, logind, UHID, and a TPM 2.0 with a usable Owner
>   hierarchy; there is no software-only fallback.
> - Only password and fingerprint PAM verification are tested. Other modules
>   may require administrator-provided service sandbox changes.
> - The interaction agent is globally single-agent and intended for a
>   single-seat system.
> - Installation does not provision the TPM, enable services, or configure UI
>   autostart.
> - In Firefox, cancel through the browser prompt rather than `vauth-ui`.
> - Clearing the TPM makes existing vAuth credentials unrecoverable.

## What is it and why would you need it?

vAuth is an application that aims to bring the convenience of Windows Hello  
to Linux based systems equipped with TPM hardware. It runs in the background  
and allows users to use any of their preferred authentication methods to sign  
into websites, services or other apps that support FIDO2.0 protocol. Browsers  
see a security key, while passkeys stay on the computer and sensitive operations  
are confirmed through a small desktop interface.

It is useful when you want machine-bound passkeys without carrying a separate
USB authenticator. vAuth uses the TPM for credential keys, PAM for user
verification, and an encrypted local credential store. A fingerprint reader is
optional; password verification remains available through PAM. Although the
officially tested authentication methods include only password and fingerprint,
other PAM modules may require additional setup and are not part of the beta's
tested configuration.

## Requirements

- Linux with systemd, logind, D-Bus, PAM, and UHID support (`/dev/uhid`)
- A TPM 2.0 exposed through the kernel resource manager (`/dev/tpmrm0`)
- TPM2-TSS FAPI configured and provisioned
- A local graphical login session running `vauth-ui`, or a compatible custom
  [interaction agent](docs/agent-api.md)
- Root access for installation and initial provisioning

vAuth deliberately has no non-TPM fallback. A fingerprint reader and `fprintd`
are optional.

## Installation

### Distribution packages

Packages for Debian/Ubuntu, Fedora, and Arch Linux are planned but not published
yet. This section will contain the supported repository commands when they are
available. Until then, build vAuth from source.

### Build from source

The build needs CMake 3.21+, pkg-config, a C++20 compiler, CLI11,
nlohmann/json, TinyCBOR, OpenSSL, TPM2-TSS, PAM, sdbus-c++, libsystemd,
rlottie, and the Slint C++ SDK.

Install the distro-provided dependencies:

**Debian 13 / Ubuntu 26.04 or newer**

```sh
sudo apt install build-essential cmake ninja-build pkg-config git \
  libcli11-dev nlohmann-json3-dev libtinycbor-dev libssl-dev \
  libtss2-dev tpm2-tools libpam0g-dev libsdbus-c++-dev \
  libsystemd-dev librlottie-dev
```

**Fedora**

```sh
sudo dnf install gcc-c++ cmake ninja-build pkgconf-pkg-config git \
  cli11-devel json-devel openssl-devel tpm2-tss-devel tpm2-tools \
  pam-devel sdbus-cpp-devel systemd-devel rlottie-devel
```

Fedora does not currently package TinyCBOR; install it from
[upstream](https://github.com/intel/tinycbor) before configuring vAuth.

**Arch Linux**

```sh
sudo pacman -S --needed base-devel cmake ninja pkgconf git cli11 \
  nlohmann-json openssl tpm2-tss tpm2-tools pam sdbus-cpp systemd
```

TinyCBOR and rlottie must currently be installed from upstream or a reviewed
PKGBUILD on Arch.

Install the Slint C++ SDK using its
[official binary-package or source instructions](https://docs.slint.dev/latest/docs/cpp/cmake/).
When using the prebuilt SDK, add its extracted directory to
`CMAKE_PREFIX_PATH` and its `lib` directory to `LD_LIBRARY_PATH`.
Shared Slint linkage is the default. To link only Slint statically, build its
C++ SDK with `BUILD_SHARED_LIBS=OFF`, select that SDK with `Slint_DIR` or
`CMAKE_PREFIX_PATH`, and configure vAuth with
`-DVAUTH_LINK_SLINT_STATIC=ON`. This does not make the other dependencies
static.

Configure, build, test, and install:

```sh
cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX=/usr
cmake --build build --parallel
ctest --test-dir build --output-on-failure
sudo cmake --install build

sudo systemd-sysusers /usr/lib/sysusers.d/vauth.conf
sudo modprobe --use-blacklist uhid
sudo udevadm control --reload-rules
sudo udevadm trigger --action=add /sys/class/misc/uhid
sudo udevadm settle
sudo systemctl daemon-reload
sudo busctl call org.freedesktop.DBus /org/freedesktop/DBus \
  org.freedesktop.DBus ReloadConfig
```

If TPM2-TSS uses a different FAPI system directory, configure the matching path
with `-DVAUTH_FAPI_SYSTEM_DIR=/absolute/path`.

## First setup

vAuth requires an already usable TPM2-TSS FAPI environment. Do not run
`tss2_provision` over an existing FAPI environment: it changes machine-wide
TPM state and may require the current TPM Owner authorization.

> [!IMPORTANT]
> Windows 10 version 1607 and newer normally provisions the TPM with a random
> high-entropy Owner authorization and then discards that value. On a TPM still
> in that state, FAPI may be able to use an existing unprotected storage root
> key, but vAuth cannot create its mandatory `/nv/Owner/vauth-db-generation`
> rollback counter. `vauthctl provision` checks this before creating either
> vAuth object and fails closed. vAuth does not offer a mode without rollback
> protection and never clears the TPM automatically.
> The corresponding diagnostic is `TPM Owner hierarchy has a non-empty
> authorization`; it identifies this unsupported TPM state rather than a
> damaged TPM.
>
> Clearing the TPM destroys TPM-protected material and can make BitLocker,
> Windows Hello, and other applications' keys unusable. Only clear it as a
> deliberate machine-administration operation after following the recovery and
> backup procedures for every TPM consumer. See Microsoft's
> [TPM Owner authorization documentation](https://learn.microsoft.com/en-us/windows/security/hardware-security/tpm/change-the-tpm-owner-password).

If FAPI has not been provisioned and the TPM Owner hierarchy is usable,
provision it before continuing:

```sh
sudo tss2_provision
```

After confirming that FAPI is usable and permits creation of Owner-authorized
NV indices, create vAuth's encrypted authorization credential and TPM objects:

```sh
sudo systemctl stop vauth.service
sudo vauthctl provision
sudo systemctl enable --now vauth-pam-verifier.socket vauth.service
```

On first use, `vauthctl provision` generates a 192-bit authorization and shows
it once. Save it securely and confirm the prompt; vAuth then encrypts it with
`systemd-creds` before creating the TPM objects. Losing it—or clearing the
TPM—makes existing vAuth credentials unrecoverable.

### Recovering the encrypted authorization

If `/etc/credstore.encrypted/vauth-db-auth` is lost or corrupted but the
authorization shown during provisioning was saved, recreate the systemd
credential envelope without reprovisioning the TPM objects or credential
database:

```bash
(
    set -euo pipefail
    sudo systemctl stop vauth.service
    sudo install -d -o root -g root -m 0700 /etc/credstore.encrypted

    read -r -s -p "Paste saved vAuth authorization: " VAUTH_DB_AUTH
    printf '\n'
    while [[ ! $VAUTH_DB_AUTH =~ ^[A-Za-z0-9_-]{32}$ ]]; do
        echo "The authorization must be 32 base64url characters." >&2
        read -r -s -p "Paste saved vAuth authorization: " VAUTH_DB_AUTH
        printf '\n'
    done

    printf '%s' "$VAUTH_DB_AUTH" |
        sudo systemd-creds encrypt \
            --force \
            --with-key=host+tpm2 \
            --name=vauth-db-auth \
            - /etc/credstore.encrypted/.vauth-db-auth.recovered
    unset VAUTH_DB_AUTH

    sudo systemd-creds decrypt \
        --name=vauth-db-auth \
        /etc/credstore.encrypted/.vauth-db-auth.recovered \
        - >/dev/null
    sudo chown root:root /etc/credstore.encrypted/.vauth-db-auth.recovered
    sudo chmod 0600 /etc/credstore.encrypted/.vauth-db-auth.recovered
    sudo mv -fT \
        /etc/credstore.encrypted/.vauth-db-auth.recovered \
        /etc/credstore.encrypted/vauth-db-auth
    sudo systemctl start vauth.service
)
```

The saved authorization must be exact, and the original TPM/FAPI objects must
still exist on the same TPM. This procedure only replaces systemd's encrypted
envelope; it cannot recover credentials after the TPM was cleared or the FAPI
objects or encrypted credential database were lost.

Start `vauth-ui` in the desktop session and check the installation:

```sh
vauth-ui
vauthctl status
```

> [!WARNING]
> When using Firefox, cancel an active passkey operation through Firefox's own
> in-browser authentication prompt instead of the Cancel control in
> `vauth-ui`. Firefox may retry an authenticator request cancelled through the
> vAuth interface.

vAuth does not install an autostart entry for `vauth-ui`. Configure it to start
with the graphical session only if that matches your desktop environment or
window-manager setup.

## Learn more

See [ARCHITECTURE.md](ARCHITECTURE.md) for the process model, privilege
boundaries, TPM key hierarchy, encrypted storage, PAM verifier, D-Bus trust
model, and protocol flow.

Custom UI authors can use the documented [agent API](docs/agent-api.md) and
[examples](examples/agents/). Distribution maintainers should follow the
[packaging policy](docs/packaging.md). vAuth is licensed under the terms in
[LICENSE](LICENSE). Library acknowledgements and license information are in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Please report vulnerabilities
privately according to the [security policy](SECURITY.md).
