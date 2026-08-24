# Project Mission

Build a reproducible multimedia forensic platform for image, video and audio
analysis.

The platform must preserve evidence integrity, run pinned detector versions and
produce structured evidence records.

# Current Authorization

- Read `PLAN.md` before starting work.
- Phase 0, Phase 1, and Phase 2 local evidence intake are authorized.
- Phase 2 is CPU-only local case creation, bounded upload, hashing, byte-signature
  type detection, append-only storage, SQLite persistence, and metadata retrieval.
- Do not implement detector inference, report generation, cloud deployment,
  frontend code, model downloads, OSINT, training, or Phase 3 work until the user
  explicitly authorizes the corresponding later phase.

# Non-Negotiable Rules

- Never modify an evidence original.
- Never commit private evidence, credentials, datasets or large model
  checkpoints to Git.
- Every derivative must contain the parent SHA-256 and the exact transformation
  used.
- Every detector result must record:
  - detector name
  - source-code commit
  - model/checkpoint revision
  - checkpoint SHA-256
  - input SHA-256
  - preprocessing
  - raw score
  - calibrated score, when available
  - runtime
  - warnings
- Do not describe an uncalibrated detector score as a probability.
- Do not create a final real/fake verdict from one detector.
- Do not silently catch detector failures.
- Do not use mutable Docker tags such as `latest` for deployment.
- Never expose production secrets in logs.
- Do not train on user data without explicit training permission.

# Architecture Rules

- Shared contracts belong under `packages/contracts`.
- Evidence preservation belongs under `packages/evidence`.
- Detector-specific logic belongs under `workers`.
- The API must not import detector implementation code.
- GPU workers accept and return versioned JSON contracts.
- Large files are referenced through hashes and object-store locations.
- External repositories and checkpoints must be pinned.

# Development Commands

- `make setup`
- `make lint`
- `make typecheck`
- `make test`
- `make test-api`
- `make db-upgrade`
- `make api`
- `make safety`

# Definition of Done

A task is complete only when:

- implementation exists;
- unit tests exist;
- error handling exists;
- schemas are updated;
- documentation is updated;
- lint, type checking and tests pass;
- no secret or large binary has been committed.

# Code Review Rules

Flag:

- any ability to overwrite evidence originals;
- missing input/output hashes;
- mutable model or container references;
- detector results without model metadata;
- missing timeouts or file-size controls;
- training on production evidence;
- raw model scores presented as confidence;
- hidden network access;
- unsafe parsing of untrusted files.
