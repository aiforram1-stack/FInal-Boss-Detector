# ADR 0001: Private monorepo as the control plane

- Status: Accepted
- Date: 2026-08-24

## Context

Contracts, API code, detector adapters, reporting, infrastructure, tests, and
governance documentation must evolve together without putting sensitive or very
large objects in source control.

## Decision

Use one private GitHub monorepo for code, schemas, synthetic fixtures, manifests,
documentation, CI workflows, and model metadata. Store evidence, private cases,
datasets, model weights, extracted media, caches, and unredacted reports in
private versioned object storage. Reference every external object with an
immutable manifest and cryptographic hash.

Stable contracts merge before parallel component work. Later detector, API,
reporting, and infrastructure changes use bounded feature branches or worktrees.

## Consequences

Cross-component contract review and reproducible CI are straightforward. The
repository is not a backup for evidence or models, so external storage lifecycle,
access control, and disaster recovery must be designed in Phase 2 and later.
