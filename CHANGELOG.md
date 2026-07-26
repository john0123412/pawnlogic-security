# Changelog

All notable changes to pawnlogic-security are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [0.1.0] - 2026-07-26

### Added
- Added an Engagement Scope value type with explicit targets, an expiry, and an
  authorization record. Absent, expired, unmatched, and malformed targets all
  deny, and a scope can never widen itself.
- Added append-only evidence records with a schema version, caller-supplied
  timestamps, and credential redaction applied before anything is written.
- Added passive reconnaissance and bounded active discovery tools. Each one
  requires a valid scope, defers to the host Network Policy and Operation
  Policy, and refuses when non-interactive confirmation is unavailable.
- Added a PawnLogic Extension exported through the `pawnlogic.extensions` entry
  point group. Discovery reads metadata without importing this package, and the
  Extension stays disabled until it is explicitly enabled.

### Security
- Tool arguments are untrusted. Naming a target never authorizes it, and no
  argument can assert scope validity or authorization on its own.
- Active operations additionally require a scope that permits active work.
