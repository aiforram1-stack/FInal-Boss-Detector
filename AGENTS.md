# Project Mission

Build a reproducible multimedia forensic platform for image, video and audio
analysis.

The platform must preserve evidence integrity, run pinned detector versions and
produce structured evidence records.

# Current Authorization

- Read `PLAN.md` before starting work.
- Phase 6, first real Community Forensics GPU validation on RunPod Serverless,
  is the only active implementation phase. GitHub PRs #2, #4, #6, #8, and #10
  are merged into `main`. Release-verifier repair PR #16 and cache-layout
  repair PR #18, bootstrap-fitness repair PR #19, four-job-cap repair PR #20,
  and hidden-GPU deny repair PR #21 are also merged. Protected `main`
  publication passed every release gate for source commit
  `18f499d79aed272064a0653f1d615cc5816ab6e0` and immutable image
  digest
  `sha256:c2fdf5625301683beb18c71e04685a205fb2e7e34911e6efac177f452e7a0117`.
  The GitHub repository is public; the source-linked GHCR package remains private.
- The renewed bootstrap job against that repaired digest was cancelled on
  2026-08-25 when one worker became unhealthy and RunPod introduced an
  unexpected second worker. No bootstrap receipt, CUDA fitness result, model
  load, or inference result was produced. The queue endpoint is retained at
  minimum zero/maximum zero with no workers or jobs. Retained endpoint logs
  confirmed that the cache resolver and Python entrypoint succeeded, then the
  pre-queue GPU fitness probe failed and exited the worker. The reviewable
  repair defers bootstrap fitness into the controlled bootstrap request while
  keeping verified validation fail-closed at startup. Do not start another paid
  worker until a refreshed proposal receives the exact approval phrase.
- A third paid bootstrap submission was cancelled on 2026-08-25 before handler
  execution because RunPod assigned the scheduler-known 24 GB Blackwell MIG
  type even though the approval-time `AMPERE_24` catalog response listed only
  RTX A5000 and RTX 3090. The endpoint was immediately restored to minimum
  zero/maximum zero with no workers or jobs. No checkpoint hash, CUDA fitness,
  model load, or inference result was produced.
- Three paid submissions have been consumed. On 2026-08-25 the user explicitly
  approved a five-submission ceiling, leaving exactly two submissions for the
  still-required bootstrap and final validation and no retry allowance. Do not
  start another paid worker until this breaking budget repair is merged and
  republished and a refreshed exact proposal receives
  `APPROVE PHASE 6 SERVERLESS COST`. The USD 2.00 total spend cap and all
  worker, identity, and retry safety stops remain unchanged.
- Phase 6 repository work may keep status/runbook documentation current, repair
  fail-closed proposal controls, and prepare a reviewable pull request.
  Do not weaken or bypass any failed SBOM, provenance, package-link, GitHub
  attestation, vulnerability, identity, or pull-by-digest gate.
- RunPod account, catalog, registry, billing, and resource reads are allowed.
  Do not create or modify an endpoint, worker, job, Pod, volume, registry
  credential, or other billable resource until the user sends exactly
  `APPROVE PHASE 6 SERVERLESS COST` for the reported configuration.
- Local development remains CPU-only on macOS. Required tests use the mock
  backend, generated fixtures, fake HTTP transports, no checkpoint and no CUDA.
- Phase 6 must use one queue endpoint, minimum workers zero, maximum workers at
  most one during approved validation and zero at completion, one GPU per
  worker, no network volume, no Pod, no private evidence, and no more than
  $2.00 total approved spend. Do not connect the main API or begin Phase 7.
- Changing repository visibility or GHCR package access/linkage requires an
  explicit user confirmation immediately before the settings change.

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
- Structural tool adapters and deterministic reporting belong under
  `packages/structural`.
- Detector-specific logic belongs under `workers`.
- Phase 4 Community Forensics code belongs under `workers/image-community` and
  must follow its scoped `AGENTS.md`.
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
- `make test-structural`
- `make structural-check-tools`
- `make structural-smoke`
- `make report-smoke`
- `make db-upgrade`
- `make api`
- `make safety`
- `make image-community-container-check`
- `make phase6-check`

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
