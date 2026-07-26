# Changelog

All notable changes to pawnlogic-security are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

Target version `0.1.0`. Nothing has been published to PyPI or TestPyPI, so this
section stays undated until a release is authorized.

Contracts and scaffolding only. This is **not** a usable security tool set: no
Engagement Scope can be set yet, so every tool call is refused with
`scope:no_scope`, and the reconnaissance tools return an authorization verdict
without performing any network work.

### Added
- Added an Engagement Scope value type with explicit targets, an expiry, and an
  authorization record. Absent, expired, unmatched, and malformed targets all
  deny, and a scope can never widen itself. Scope files, persistence, CIDR and
  port ranges, exclusions, and request/concurrency/duration budgets are not
  implemented yet.
- Added append-only evidence records with a schema version, caller-supplied
  timestamps, and credential redaction applied before anything is written.
- Added passive reconnaissance and bounded active discovery tool handlers. Each
  requires a valid scope, defers to the host Network Policy, and refuses when
  non-interactive confirmation is unavailable. Neither performs DNS, TLS,
  HTTP-header, technology, port, or service work yet.
- Added a PawnLogic Extension exported through the `pawnlogic.extensions` entry
  point group. Discovery reads metadata without importing this package, and the
  Extension stays disabled until it is explicitly enabled. The Extension
  contributes no commands yet, so a host session has no way to supply a scope.

### Security
- Tool arguments are untrusted. Naming a target never authorizes it, and no
  argument can assert scope validity or authorization on its own.
- Active operations additionally require a scope that permits active work.
- The host Operation Policy governs subprocess execution and is not on any path
  in this package, because nothing here runs a subprocess.
