# Changelog

All notable changes to pawnlogic-security are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

Target version `0.1.0`. Nothing has been published to PyPI or TestPyPI, so this
section stays undated until a release is authorized.

### Added

- Added a versioned Engagement Scope file with exact hosts, CIDRs, exclusions,
  explicit ports, passive/active actions, destructive-action rejection,
  expiry, and request, concurrency, and duration budgets.
- Added real stdlib-backed passive DNS, TLS, HTTP-header, and technology
  reconnaissance plus bounded active port discovery. Both remain behind
  Engagement Scope and host Network Policy.
- Added append-only evidence records with schema versions, caller-supplied
  timestamps, restrictive permissions, and credential redaction before write.
- Added the explicitly enabled PawnLogic Extension and `/security scope
  set|clear|show`, `/security status`, `/security plan`, `/security run`, and
  `/security evidence list|export` commands.
- Added `pawn-security scope validate <scope-file>` and `pawn-security run
  <workflow> --scope <scope-file>`.
- Added schema-versioned, workflow-versioned built-in manifests for
  `passive-recon` and `active-discovery`. Direct and hosted execution share the
  same scope-gated runner.
- Added canonical local workflow run records, safe run-ID-only listing/export,
  and deterministic no-execution planning that proposes passive reconnaissance
  first. Scope-relative `evidence_dir` values are resolved from the scope file
  directory; runtime-home storage is the fallback when no directory is set.
- Added an optional, default-disabled JSON child-process adapter with host
  Operation Policy checks, literal argv execution, bounded input/output,
  timeout process-group cleanup, a scrubbed environment, and output redaction.
  No built-in workflow invokes it.

### Fixed

- Fixed the Extension command contribution to use the canonical `/security`
  verb and the host's async `CommandContext`, with all output routed through
  the active sink.
- Fixed re-contribution to return the complete current contribution set, so
  `/security` remains registered when scope changes add or withdraw tools.
- Fixed Tool visibility so passive-only scopes expose only passive
  reconnaissance; active discovery additionally requires the active action,
  active authorization, and explicit ports.
- Removed direct writes to `ScopeManager` private callback state; Extension
  lifecycle integration now uses public construction and shutdown interfaces.

### Security

- Workflow execution refuses absent or expired scope, exhausted request
  budgets, active workflows without active authorization, and manifests that
  would require automatic CIDR expansion.
- Workflow run files use restrictive permissions, redact rendered outputs, do
  not overwrite a different existing run, and can be exported only by a
  fixed-format run ID.
- Destructive workflows, external scanner integrations, HTTP replay, workflow
  YAML loading, MCP execution, and CIDR expansion remain unimplemented.
