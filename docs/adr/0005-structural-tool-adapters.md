# ADR 0005: Isolate structural tools behind one bounded runner

- Status: accepted
- Date: 2026-08-24

## Context

ExifTool, ffprobe, and MediaInfo are mature parsers but operate on untrusted
media and may be absent, slow, noisy, or fail. Calling them from routes or with a
shell would duplicate safety controls and make command injection or unbounded
capture easier.

## Decision

All optional tools use a small adapter and one `SafeSubprocessRunner`. Commands
are argument arrays with `shell=False`; only the internally resolved evidence
path is passed, never an uploaded filename or URL. The runner enforces timeout
and output limits, records exit/runtime/version, terminates failures, sanitizes
paths, and maps availability/failure into explicit forensic test states. API
startup does not probe or require any optional executable, and the repository
never installs system packages.

## Consequences

Adapters are testable with controlled JSON and fake executables. A missing or
failed parser reduces coverage and produces a partial report instead of false
success. Process sandboxing beyond local user permissions is not provided in
Phase 3; production deployment will require stronger OS/container isolation.
