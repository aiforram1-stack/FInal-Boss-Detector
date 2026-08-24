# ADR 0003: Versioned detector evidence, not detector verdicts

- Status: Accepted
- Date: 2026-08-24

## Context

Detector outputs are model- and preprocessing-specific. A raw score has no
universal scale, benchmark performance may not transfer to case data, and related
models are not independent confirmations.

## Decision

GPU workers exchange versioned JSON contracts. Results record input hash,
detector source/version, repository commit, container digest, model revision,
checkpoint SHA-256, preprocessing, raw outputs, raw score, runtime, artifacts,
warnings, and timestamps.

The field is named `raw_score`, never probability or confidence. A
`calibrated_score` is optional and is invalid without named, versioned calibrator
metadata and calibration-data lineage. A result never supplies the platform’s
final forensic conclusion.

Contract readers accept and preserve unknown fields for forward compatibility but
must not interpret them without a schema upgrade. Failures and unperformed tests
use explicit states rather than disappearing from the report.

## Consequences

Results are reproducible and limitations remain visible. Downstream reporting
must understand detector-specific scales and calibration applicability. Breaking
changes require a new schema major version.
