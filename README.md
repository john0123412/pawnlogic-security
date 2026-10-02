# pawnlogic-security

Scope-gated security tooling for the [PawnLogic](https://github.com/john0123412/PawnLogic)
agent host, distributed independently of the core package.

Installing this package does not authorize or enable it. The PawnLogic
Extension stays disabled until an operator explicitly enables it, and its
network tools remain unavailable until a valid Engagement Scope is active.

## Status

The current public release is `0.1.0`, published independently of the
PawnLogic core package. It implements:

- a versioned Engagement Scope file with exact hosts, CIDRs, exclusions,
  explicit ports, passive/active actions, expiry, and request, concurrency, and
  duration budgets
- scope-gated passive DNS, TLS, HTTP-header, and technology reconnaissance
- scope-gated bounded active port discovery
- append-only redacted evidence records
- two built-in, versioned workflows shared by `pawn-security` and `/security`
- reproducible workflow plans and versioned local run records
- an optional, default-disabled JSON child-process adapter with Operation Policy
  checks, bounded I/O, timeout cleanup, environment isolation, and output
  redaction

It does not implement HTTP replay, external scanner adapters, workflow YAML
loading, CIDR expansion, exploit or destructive workflows, MCP execution, or
an AI-generated planner. No built-in workflow invokes the optional child
adapter.

## Requirements

- Python 3.10 or newer
- `pawnlogic>=0.4,<0.5`

## Install

Install the published package:

```bash
python -m pip install pawnlogic-security
```

For checkout development:

```bash
python -m pip install -e .
```

Nothing is loaded merely because the distribution is installed.

## Enable in PawnLogic

```text
/extension list
/extension enable security
/extension status security
```

The Extension contributes `/security` after enablement:

```text
/security status
/security scope show
/security scope set <scope-file>
/security scope clear
/security plan <objective>
/security run <workflow>
/security evidence list
/security evidence export <run-id>
```

`/security` is an async host command and writes through the active PawnLogic
output sink. Scope changes rebuild the complete contribution set atomically:
the command remains present while security tools appear or disappear.

Disable the Extension with:

```text
/extension disable security
```

## Engagement Scope

Every operation requires an explicit, unexpired Engagement Scope. A minimal
passive scope file looks like:

```json
{
  "version": 1,
  "identifier": "authorized-review",
  "authorized_by": "security-team",
  "reference": "CHANGE-1234",
  "expires_at": 4102444800,
  "targets": ["app.example.com"],
  "exclude": [],
  "ports": ["443"],
  "allow_active": false,
  "actions": ["passive"],
  "destructive": false,
  "max_requests": 20,
  "max_concurrency": 1,
  "max_duration": 300,
  "evidence_dir": "evidence"
}
```

Active discovery additionally requires `allow_active: true`, the `active`
action, and explicit ports, for example `"ports": ["443", "8000-8010"]`.
Destructive authorization is rejected because destructive workflows are not
implemented.

The passive example explicitly authorizes port `443` because TLS inspection and
HTTPS header collection make network connections even though they do not send
active probes.

Scope is necessary but never sufficient. The host Network Policy runs after
scope validation and may still refuse the target. Resolved addresses and
redirect changes must remain in scope. Model-provided tool arguments cannot
grant authorization.

## Workflows

The built-in workflow manifests have schema version `1` and their own workflow
version:

- `passive-recon` runs `security_passive_recon`
- `active-discovery` runs `security_active_discovery`

Both direct and hosted commands call the same `WorkflowRunner` interface:

```bash
pawn-security scope validate <scope-file>
pawn-security run passive-recon --scope <scope-file>
```

```text
/security run passive-recon
```

The runner sorts explicit host targets and runs one workflow target at a time.
The execution adapters consume the engagement-wide request budget before
individual network requests. The runner does not expand a CIDR into hosts.
`active-discovery` additionally requires an active scope; port-scan concurrency
remains bounded by the scope.

`/security plan <objective>` is deliberately conservative. It returns a
deterministic suggestion to begin with `passive-recon`, reports that execution
has not started, and performs no network work.

## Evidence

When the active scope sets `evidence_dir`, tool observations and run records
are written there. A relative `evidence_dir` is resolved from the directory
containing the scope file. Without `evidence_dir`, they fall back to:

```text
<runtime home>/security/evidence.jsonl
```

The direct command uses `PAWNLOGIC_HOME` when set, otherwise
`~/.pawnlogic`, for that fallback only.

Within the selected evidence directory, observations use `evidence.jsonl` and
completed workflow records use canonical, schema-versioned JSON with
restrictive permissions under:

```text
<evidence directory>/runs/<run-id>.json
```

`/security evidence list` shows run summaries. `/security evidence export
<run-id>` writes the selected canonical run record to the active output sink.
Export accepts only a fixed-format run ID; it does not accept an output path
and does not create an evidence archive.

## Trust boundaries

- No scope, an expired scope, an excluded or unmatched target, an unauthorized
  port, or an exhausted budget fails closed.
- Active work requires explicit active authorization and ports.
- Loopback, private, link-local, metadata, and credential-bearing targets are
  still governed by PawnLogic Network Policy.
- The package does not silently download scanners, wordlists, browsers,
  containers, or system packages.
- The optional child-process adapter is disabled by default. When explicitly
  configured by an integrator, it executes a literal argument vector without a
  shell only after the host Operation Policy allows it; current workflows do
  not call it.

## Development

```bash
python -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
.venv/bin/python -m pytest -q
.venv/bin/python -m ruff check .
```

## License

MIT. See [LICENSE](LICENSE).
