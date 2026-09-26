# Security Policy

vAuth handles authentication credentials and interacts with PAM and the TPM.
Please report suspected security vulnerabilities privately rather than opening
a public issue or discussion.

## Supported Versions

Use this section to tell people about which versions of your project are
currently being supported with security updates.

| Version | Supported          |
| ------- | ------------------ |
| vAuth v0.1.0   | :white_check_mark: |
| vauth-ui v0.1.0 | :white_check_mark: |
| vauthctl v0.1.0 | :white_check_mark: |

## Reporting a vulnerability

Email **admin@lamellix.com** with the subject `[vAuth security]` and include:

- the affected version or commit;
- the operating system and relevant configuration;
- a description of the impact and required attacker capabilities;
- minimal steps or a proof of concept that reproduces the issue; and
- any suggested mitigation, if known.

Do not include passwords, TPM authorization values, private keys, credential
databases, or other real authentication material. Use test data and redact logs
where necessary.

The report will be acknowledged and triaged as availability permits. We will
coordinate a fix and public disclosure with the reporter. Please allow time for
a patched release before publishing technical details.

## Scope and responsible testing

Reports concerning the daemon, CTAP/CTAPHID implementation, PAM verifier,
interaction-agent boundary, TPM/FAPI usage, credential storage, `vauthctl`, or
the supplied systemd and packaging configuration are welcome.

Only test systems and accounts that you own or are explicitly authorized to
test. Avoid disrupting services, accessing another person's data, weakening a
machine's TPM configuration, or clearing a TPM. Stop testing and report the
issue if sensitive data becomes accessible.

Vulnerabilities in an upstream dependency should normally also be reported to
that project. Please notify us privately when the vulnerability is exploitable
through vAuth or requires a vAuth-side mitigation.

There is currently no paid bug-bounty program.
