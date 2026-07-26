# pawnlogic-security

Scope-gated security tooling for the [PawnLogic](https://github.com/john0123412/PawnLogic)
agent host, distributed independently of the core package.

The core `pawnlogic` distribution deliberately ships no security tools. This
package adds them as an Extension that stays disabled until you enable it.

## Status

This is a contracts and scaffolding slice, not a usable security tool set. The
authorization and evidence contracts are implemented and tested, but:

- there is no way to set an Engagement Scope yet, so every tool call is refused
  with `scope:no_scope`
- passive reconnaissance and active discovery perform no real work; they return
  the authorization verdict only
- the `/security` commands and scope file format do not exist yet
- the distribution is unpublished

Do not read the sections below as a description of working functionality.

## Requirements

- Python 3.10 or newer
- `pawnlogic>=0.3,<0.4`

## Install

```bash
pip install pawnlogic-security
```

Installing this distribution is **not** authorization to run it. Nothing is
loaded or executed until the Extension is explicitly enabled.

## Enable

Inside PawnLogic:

```
/extension list
/extension enable security
/extension status security
```

Disable it the same way:

```
/extension disable security
```

## Engagement Scope

Every operation requires an active Engagement Scope. A scope is an explicit,
expiring authorization record that names its targets:

- **No scope** denies.
- **An expired scope** denies.
- **A target the scope does not name** denies. Wildcards are not supported, and
  a subdomain is not covered by its parent.
- **A malformed target** denies rather than raising.
- **Active operations** additionally require a scope that permits active work.

A scope only reports its own state. It never claims a target is allowed: the
host Network Policy runs afterwards and can still refuse. Being in scope is
necessary, never sufficient.

The host Operation Policy is not on this path, because nothing here runs a
subprocess. It becomes a required gate when scanner-binary execution is added.

## Trust boundaries

- Tool arguments come from a model and are untrusted. Naming a target does not
  authorize it, and no argument can assert scope validity or authorization.
- Non-interactive sessions fail closed. A tool invoked by a model cannot answer
  a confirmation prompt, so anything short of an outright allow is refused.
- Cloud metadata endpoints, loopback and private ranges, and credential-bearing
  URLs are decided by the host Network Policy, not by this package.

## Evidence

Observations are appended to `<runtime home>/security/evidence.jsonl` as
schema-versioned JSON lines. Records are never edited or deleted, timestamps
are supplied by the caller, and credential-shaped values are redacted before
anything is written.

## Command line

```bash
pawn-security            # what this provides and how to enable it
pawn-security --manifest # the manifest the host validates
```

The command reports status only. It cannot enable the Extension or perform
security work.

## Development

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pytest -q
.venv/bin/python -m ruff check .
```

## License

MIT. See [LICENSE](LICENSE).
