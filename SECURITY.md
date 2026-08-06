# Security Policy

## Supported Versions

proofctl is currently pre-release (`v0.3.14`). Security fixes are applied to the
`main` branch only; there are no backport guarantees until a stable release series
is declared.

| Version | Supported |
| ------- | --------- |
| main    | ✓         |

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Instead, report them via one of these channels:

1. **GitHub private security advisory** — preferred:
   [https://github.com/telleroutlook/proofctl/security/advisories/new](https://github.com/telleroutlook/proofctl/security/advisories/new)

2. **Email** — send a description to the maintainer via the email address listed
   on the GitHub profile at [https://github.com/telleroutlook](https://github.com/telleroutlook).

Please include:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a minimal proof-of-concept
- Any suggested mitigations

You can expect an acknowledgement within **72 hours** and a fix or mitigation
plan within **14 days** for critical issues.

## Scope

proofctl is a **local CLI tool**. Its attack surface is limited to:

- Parsing untrusted `graph.json` / policy JSON files
- Executing checker binaries specified in `graph.json`
- Reading and writing files under `.proofctl/`

Out of scope: network services, multi-user environments (proofctl has no server
component), or vulnerabilities in the mathematical proofs themselves.
