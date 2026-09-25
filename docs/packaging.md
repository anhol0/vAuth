# Packaging policy

This document defines the distribution-package lifecycle for vAuth. Package
formats may use their native helper tools, but must preserve these behaviors.

## Installation

A package installs the binaries, systemd units, sysusers declaration,
modules-load declaration, udev rule, D-Bus policy, PAM policy, project license,
and third-party notices at the paths documented in
[ARCHITECTURE.md](../ARCHITECTURE.md).

Installation may perform only non-secret system integration:

- create or update the `vauth` system account from `vauth.conf`;
- arrange for the `uhid` kernel module to load at boot and attempt to load it
  immediately on a live installation;
- reload systemd units, udev rules, and the system-bus policy; and
- apply the udev rule to `/dev/uhid` when the package manager can do so safely.

Installation must not:

- enable or start `vauth.service` or `vauth-pam-verifier.socket`;
- provision, delete, or replace TPM2-TSS FAPI objects;
- create, decrypt, replace, or prompt for `vauth-db-auth`;
- create or modify the credential database; or
- start or configure session autostart for `vauth-ui`.

The verifier service template is socket-activated and must never be enabled or
started directly. No vendor preset supplied by vAuth enables either system
unit. Distribution packaging helpers must be configured not to auto-enable or
auto-start them.

The PAM policy is administrator-managed configuration. Package upgrades must
preserve local changes according to the distribution's normal configuration-
file mechanism.

## First setup

Provisioning is an explicit administrator operation after installation. The
administrator provisions TPM2-TSS FAPI if necessary, creates the encrypted
systemd credential, stops any old daemon instance, and runs:

```sh
sudo vauthctl provision
sudo systemctl enable --now vauth-pam-verifier.socket vauth.service
```

The package must not combine these operations with installation. They require
a usable TPM, site-specific FAPI configuration, and an administrator-selected
recovery secret, and provisioning failure must leave package installation
successful and diagnosable.

Provisioning also requires permission to create an Owner-authorized TPM NV
index. Windows 10 version 1607 and newer normally provisions a TPM with a
random Owner authorization and discards it. If that authorization remains
active and is unavailable, `vauthctl provision` must fail: packages must not
retry by clearing or reprovisioning the TPM, and must not offer or select a
rollback-unprotected configuration. Package documentation should direct the
administrator to evaluate all existing TPM consumers and their recovery
procedures rather than presenting TPM clearing as a routine vAuth setup step.

`vauth-ui` is launched by the desktop user. vAuth deliberately installs no XDG
autostart entry or systemd user unit: users of different desktop environments
and window managers decide how and when their interaction agent starts.

## Upgrade

An upgrade must preserve:

- `/etc/credstore.encrypted/vauth-db-auth`;
- `/var/lib/vauth/` and its credential database;
- all vAuth FAPI objects; and
- locally modified PAM configuration.

It must never reprovision security objects or regenerate authorization. The
package may reload system integration and try-restart `vauth.service` only when
the service was already active. An upgrade must not enable a previously
disabled unit.

Any future persistent-format migration must be implemented as a separately
tested, failure-atomic operation. Packaging scripts must not modify a credential
store whose format they do not understand.

## Removal and purge

Removal stops and disables the vAuth system units and removes only package-
owned files. It leaves the service account, encrypted authorization credential,
credential database, and FAPI objects intact so that reinstalling the package
does not silently destroy credentials.

Purge may remove package-owned configuration, subject to distribution policy,
but must not delete `/etc/credstore.encrypted/vauth-db-auth`, `/var/lib/vauth/`,
or FAPI objects. Those resources contain or protect user credentials and are
removed only through an explicit, separately documented administrator action.

## Package splitting

The initial release may use one binary package. A distribution may split the
daemon and administration files from `vauth-ui` so custom-agent installations
do not require the graphical stack. Such a split must not make the bundled UI
a daemon security dependency: the documented D-Bus agent interface remains the
boundary, and the daemon continues to fail closed when no eligible agent is
registered.

Package builds may link Slint statically so that it is a build-time dependency
rather than an installed runtime dependency. Such builds use a Slint C++ SDK
built with `BUILD_SHARED_LIBS=OFF` and configure vAuth with
`-DVAUTH_LINK_SLINT_STATIC=ON`. Source builds retain shared linkage by default.
Static linkage does not remove Slint's license, attribution, source-availability,
or distribution-policy obligations.
