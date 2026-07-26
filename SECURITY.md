# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.0   | ✅ Yes     |

## Reporting a Vulnerability

Report suspected vulnerabilities through a private GitHub security advisory on
this repository. Do not open a public issue for an unfixed vulnerability, and
do not include credentials, customer data, or engagement details in a report.

## Scope of This Package

This package performs security work only against hosts named by an active
Engagement Scope, and only when the host PawnLogic Network Policy and Operation
Policy also allow the operation. It cannot authorize itself:

- Installing this distribution does not enable it.
- Enabling the Extension does not create a scope.
- A scope names hosts explicitly; wildcards are not supported.
- Active operations require a scope that permits active work.
- Non-interactive sessions fail closed rather than assuming confirmation.

Report any path that reaches a network operation without satisfying all of the
above as a vulnerability.
