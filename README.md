# vAuth

<p align="center">
  <img src="https://raw.githubusercontent.com/lamellixlabs/vAuth/refs/heads/main/vauth.svg" alt="vAuth logo" width="600">
</p>

[![Built with Slint](https://img.shields.io/badge/Built%20with-Slint-2379F4?logo=slint&logoColor=white)](https://slint.dev/)
[![License](https://img.shields.io/github/license/anhol0/vAuth)](https://github.com/anhol0/vAuth/blob/main/LICENSE)
![C++20](https://img.shields.io/badge/C%2B%2B-20-00599C?logo=cplusplus&logoColor=white)
![Linux](https://img.shields.io/badge/platform-Linux-FCC624?logo=linux&logoColor=black)
![FIDO2](https://img.shields.io/badge/FIDO2-CTAP2.0-blue)
![TPM](https://img.shields.io/badge/TPM-2.0-blue)
![Status](https://img.shields.io/badge/status-public_beta-blue)


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
optional; password verification remains available through PAM. Even though  
the officially tested authentication methods include only password and fingerprint,  
you can use virtually any authentication method of your convenience, including  
Smart Cards, NFC, facial recognition through Howdy, and many more.

> [!IMPORTANT]
> vAuth is pre-release software. Distribution packages and automated first-run
> setup are still in progress.

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
sudo udevadm control --reload-rules
sudo systemctl daemon-reload
sudo busctl call org.freedesktop.DBus /org/freedesktop/DBus \
  org.freedesktop.DBus ReloadConfig
```

If TPM2-TSS uses a different FAPI system directory, configure the matching path
with `-DVAUTH_FAPI_SYSTEM_DIR=/absolute/path`.

## First setup

Provision TPM2-TSS FAPI once, then create vAuth's encrypted authorization
credential and TPM objects:

```sh
sudo tss2_provision
sudo install -d -m 0700 /etc/credstore.encrypted
systemd-ask-password "Choose a vAuth recovery secret:" | \
  sudo systemd-creds encrypt --name=vauth-db-auth - \
  /etc/credstore.encrypted/vauth-db-auth

sudo systemctl stop vauth.service
sudo vauthctl provision
sudo systemctl enable --now vauth-pam-verifier.socket vauth.service
```

Keep the authorization secret somewhere safe. Losing it—or clearing the
TPM—makes existing vAuth credentials unrecoverable.

Start `vauth-ui` in the desktop session and check the installation:

```sh
vauth-ui
vauthctl status
```

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
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
