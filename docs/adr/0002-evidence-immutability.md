# ADR 0002: Evidence originals are create-only

- Status: Accepted
- Date: 2026-08-24

## Context

Forensic conclusions are only reproducible when the analyzed bytes are provably
the submitted bytes. Ordinary filesystem writes and mutable object keys can
silently replace evidence.

## Decision

An original will be streamed into a staging object while SHA-256 and SHA-512 are
computed, then finalized with a create-only operation under a content-addressed
key. No API will expose an update or overwrite operation for an original.
Derivatives are separate objects and record parent hash, transformation tool and
version, exact parameters, output hashes, and whether the operation is lossy.

Media paths, filenames, metadata, and URLs are untrusted display or transport
data; they never determine an unrestricted filesystem target.

## Consequences

Duplicate bytes can be deduplicated safely, and every detector input is
verifiable. Corrections create new records rather than mutating history. Storage
cleanup must distinguish unreachable staging objects from immutable case data.
Phase 1 defines lineage contracts only; storage code begins in Phase 2.
