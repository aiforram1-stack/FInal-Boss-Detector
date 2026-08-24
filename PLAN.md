# Multimedia Forensic Platform Plan

## Authorization boundary

**Only Phase 0 through Phase 4 are authorized in the current task.** Phase 4 is
the sole active implementation milestone. All later phases are planning
context; do not implement Phase 5 or beyond without explicit user authorization.

Current status (2026-08-24):

- [x] Phase 0 repository foundation completed.
- [x] Phase 1 shared contracts completed and verified.
- [x] Phase 2 local evidence intake is complete on
  `feat/phase-2-evidence-intake` and awaiting review.
- [x] Phase 3 structural media analysis and deterministic reporting is complete
  on `feat/phase-3-structural-reporting` and awaiting review.
- [x] Phase 4 Community Forensics worker adapter is complete locally on
  `feat/phase-4-community-forensics-worker`, tracked by GitHub issue #5, and
  awaiting pull-request review.
- [ ] Phase 5 and later are not authorized.

## Mission and first vertical slice

Build a reproducible multimedia forensic platform that preserves evidence
integrity, runs pinned detector versions, stores versioned evidence records, and
separates deterministic facts from human analytical conclusions.

The first operational slice will eventually be:

```text
media upload -> immutable preservation -> local structural analysis
             -> deterministic JSON/HTML report
             -> later pinned detector workers -> private manual review
```

## Milestones and acceptance criteria

### Phase 0 — Plan and repository foundation (authorized)

Dependencies: none.

Deliverables:

- private-monorepo-ready structure and repository policy;
- Python 3.11 project tooling, formatting, linting, typing, and tests;
- architecture overview and foundational ADRs;
- ignored locations for evidence, reports, model data, datasets, and secrets;
- documented environment-variable names with no live credentials.

Acceptance:

- required directories and foundation files exist;
- architecture documentation includes the local control plane, private evidence
  storage, GitHub/GitHub Actions, GPU workers, deterministic reporting, and the
  later learning plane;
- repository safety checks reject common secret filenames, model weights, and
  oversized tracked files;
- `git status` contains no private data or generated runtime state.

### Phase 1 — Shared contracts (authorized)

Dependencies: Phase 0.

Deliverables:

- versioned Pydantic v2 models for `Case`, `EvidenceAsset`,
  `EvidenceDerivative`, `DetectorJob`, `DetectorIdentity`, `DetectorRun`,
  `DetectorResult`, `ForensicTestResult`, and `ReportManifest`;
- generated, committed JSON Schemas;
- synthetic JSON examples and backward-compatible loading tests;
- contract tests for IDs, UTC timestamps, hashes, calibration metadata,
  derivative lineage, unknown-field preservation, and serialization.

Acceptance:

- all identifiers validate as UUIDs;
- all externally stored timestamps are timezone-aware UTC;
- SHA-256 and SHA-512 values reject malformed or uppercase encodings;
- detector identity is reproducible down to source commit, container digest,
  model revision, and checkpoint hash;
- calibrated scores cannot exist without a named and versioned calibrator;
- derivatives contain complete parent/output lineage and exact transformation
  metadata;
- forensic tests support every specified non-success and policy state;
- unknown future fields round-trip without being interpreted by current code;
- schemas regenerate without a diff;
- formatting, linting, strict typing, tests, and safety review pass;
- no detector, evidence storage, API, cloud, frontend, training, model download,
  or real-media implementation is present.

### Phase 2 — Immutable evidence storage and local API (completed)

Dependencies: Phase 1 contracts merged.

Current branch: `feat/phase-2-evidence-intake`. The repository is a normal clean
checkout, so this bounded branch is used instead of creating a worktree.

Deliverables: streaming SHA-256/SHA-512, create-only storage backend, SQLite
development persistence, migrations, case/upload/read endpoints, file limits,
signature-based MIME validation, and untrusted-path defenses.

Acceptance: a case can be created and retrieved; small generated image, audio,
and video fixtures can be uploaded in bounded chunks; authoritative SHA-256 and
SHA-512 plus detected MIME type and exact size are persisted; same-case uploads
are idempotent; cross-case uploads share one blob; originals cannot be
overwritten; storage URIs reveal no physical path; SQLite foreign keys and
uniqueness are enforced; staging cleanup, database rollback, health, OpenAPI,
size, malformed upload, unsupported type, write failure, concurrency, and path
tests pass on macOS without network, models, CUDA, FFmpeg, or external programs.

#### Phase 2 internal architecture

```text
FastAPI routes
    -> case/evidence application services
        -> SQLAlchemy repositories -> SQLite (foreign keys enabled)
        -> StorageBackend protocol
            -> LocalContentAddressedStorage
                staging/.part -> one-pass hashes/type -> atomic hard-link put-if-absent
```

The upload transaction boundary is intentionally compensating rather than fully
atomic across SQLite and the filesystem:

1. stream into a unique same-filesystem staging file while hashing;
2. validate size and byte signature;
3. atomically promote with a no-overwrite hard link;
4. insert/reuse the blob and case association in one database transaction;
5. return only after the database commit and a final object-existence check.

If the database fails after a newly promoted blob is created, the request fails
and the unreferenced immutable blob is retained rather than deleted during a
concurrent race. A reconciliation command reports unreferenced blobs for an
operator to review. It never deletes them automatically.

#### Phase 2 implementation sequence

1. Add validated environment configuration and structured request-ID logging.
2. Add SQLAlchemy models, foreign-key-enabled sessions, repositories, and one
   Alembic migration for cases, evidence blobs, and case evidence assets.
3. Define `StorageBackend` and implement bounded staged writes, signature-based
   type detection, hash-derived paths, atomic hard-link promotion, read-only
   permissions, deduplication, and reconciliation inventory.
4. Add case and evidence-intake services that map persistence records to the
   shared Phase 1 `Case` and `EvidenceAsset` contracts.
5. Add `/health`, case creation/retrieval, upload, and evidence metadata routes
   with versioned safe errors and no raw download endpoint.
6. Add generated tiny fixtures and comprehensive unit/API/failure/concurrency
   tests using temporary database and storage roots.
7. Add CI, ADR 0004, local runbook, README/Makefile/configuration updates, and a
   bounded-memory local smoke test.
8. Review every Phase 2 change for overwrite, traversal, partial state, path
   disclosure, unbounded reads, unsafe logging, and accidental tracked data.

Completion evidence (2026-08-24): 51 contract/storage/API tests pass on macOS;
Ruff formatting and lint, strict mypy, JSON Schema regeneration, OpenAPI
generation, repository safety scanning, migration upgrade, and an 8 MiB
generated upload smoke test pass. The smoke test used 64 KiB storage chunks and
left one content object with no staging residue.

### Phase 3 — Structural media analysis and deterministic reporting (authorized)

Dependencies: Phases 1–2. This branch is stacked on the unmerged Phase 2 branch;
its pull request must target `feat/phase-2-evidence-intake` until Phase 2 merges.

Current branch: `feat/phase-3-structural-reporting`.

Deliverables: integrity re-verification before analysis; a declarative registry
covering file signature, ExifTool, ffprobe, MediaInfo, media summaries, and
metadata consistency; a bounded shell-free subprocess runner; optional-tool
availability records; normalized structural result contracts and persistence;
create-only result artifacts; deterministic canonical JSON and escaped,
self-contained HTML reports; synchronous local API endpoints; migrations,
documentation, CI, and CPU-only tests.

Acceptance: analysis refuses missing or hash-mismatched originals and records the
failure; every registered test emits a shared forensic status; missing tools do
not prevent startup; subprocesses have argument-array invocation, timeouts, and
bounded/sanitized output; reports contain no physical paths, raw media, secrets,
probabilities, confidence, AI-generation claims, or forensic verdicts; canonical
serialization and report hashes are reproducible for the same stored object;
HTML is escaped, accessible, printable, and has no scripts or external assets;
duplicate active runs are prevented; formatting, linting, strict typing, mocked
CPU tests, OpenAPI validation, migration, smoke tests, and repository safety pass
on macOS without models, GPU, cloud, network, or real media.

No part of Phase 3 may perform detector inference, install tools automatically,
download weights, call OSINT providers, deploy infrastructure, add frontend or
authentication code, or start training.

Completion evidence (2026-08-24): GitHub issue
[#3](https://github.com/aiforram1-stack/FInal-Boss-Detector/issues/3) tracks the
scope. The local gate passes with 92 tests; three optional installed-tool probes
skip explicitly because ExifTool, ffprobe, and MediaInfo are unavailable. Ruff
formatting/lint, strict mypy, deterministic schema regeneration, Phase 3
OpenAPI, Alembic head migration coverage, repository safety, structural smoke,
report smoke, and the available system `file` integration probe pass. The smoke
path runs entirely in temporary storage with generated bytes and verifies the
stored JSON/HTML SHA-256 values.

### Phase 4 — First image-detector worker adapter (authorized; active)

Dependencies: Phase 3 contracts and reporting boundaries are stable.

Candidate worktree: `feat/phase-4-community-forensics-worker`.

Current branch: `feat/phase-4-community-forensics-worker`, stacked on the
unmerged Phase 3 branch. Its pull request must target
`feat/phase-3-structural-reporting` until the earlier pull requests merge.

Deliverables: pinned Community Forensics source/model/preprocessor metadata;
retained licensing; a validated model manifest; injectable SSRF-constrained
HTTPS retrieval; input hash and length verification; bounded image decoding;
exact official evaluation preprocessing; deterministic mock inference; a
checkpoint-verifying real CUDA backend that is not run locally; structured
fitness, telemetry and errors; a thin RunPod-compatible handler; an opt-in
checkpoint acquisition script; CPU-only tests; GPU-test scaffolding; and a
pinned Linux AMD64 CUDA Dockerfile. Weight download and real GPU execution
remain explicit later operator actions; no GPU is rented, endpoint deployed,
container published, or API connection added in this milestone.

Acceptance: mocked CPU tests produce a valid `DetectorResult` with a raw score
and complete immutable detector identity; the adapter never calls that score a
probability or verdict; source, container base, model revision, and checkpoint
expectations are immutable and license-reviewed. Secure retrieval rejects
unapproved hosts, local/private/link-local/metadata addresses, redirects unless
explicitly enabled and revalidated, oversized input, MIME disagreement, and
hash/length mismatch. Decode and preprocessing are bounded, deterministic and
fingerprinted. Mock mode cannot pass production fitness; real mode cannot pass
without CUDA, a verified checkpoint hash, a complete container identity and a
successful output-shape probe. Ordinary macOS and CI commands perform no real
network request, checkpoint download, CUDA execution, RunPod call, or container
publication.

#### Phase 4 verified upstream pins

- source: `https://github.com/JeongsooP/Community-Forensics` at
  `ee5b71d43db0f3779e1edd64ee927b13f2dd6ad4` (MIT);
- model: `OwensLab/commfor-model-384` at
  `6076002bf0d9dd37537f965ee2f06f826c333b61`;
- checkpoint: `model.safetensors`, 87,262,324 bytes, Hugging Face Git LFS
  SHA-256 `b89f36275f3bf5e2b040eee36597a8f19db051bff9a473a9cf7b2466284fb387`;
- preprocessor: `OwensLab/commfor-data-preprocessor` at
  `3540a3f0d688f8bf492a8aed48613b891f88047e`;
- evaluation transform: convert to RGB, resize the shorter edge to 440 with
  Pillow bilinear antialiasing while preserving aspect ratio, centered 384 by
  384 crop, float32 RGB channel-first scaling to `[0, 1]`, and ImageNet mean
  `[0.485, 0.456, 0.406]` / standard deviation `[0.229, 0.224, 0.225]`;
- output: one binary-classification logit per image, with upstream labels
  `real=0` and `fake=1`. The upstream example applies sigmoid for evaluation,
  but provides no calibration evidence; Phase 4 therefore records the raw
  pre-sigmoid logit and keeps calibrated fields null.

#### Phase 4 implementation sequence

1. Record the authorization boundary and upstream integration decision.
2. Validate the pinned manifest and preserve upstream notices.
3. Implement dependency-injected input, decoding, preprocessing, backend and
   fitness interfaces with structured failures.
4. Implement the deterministic local mock and the fail-closed real CUDA
   backend without installing or executing CUDA dependencies on macOS.
5. Compose the framework-independent job service, result builder and thin
   RunPod handler.
6. Add opt-in checkpoint verification, pinned Docker assets, configuration,
   Make targets and CPU-only CI.
7. Add generated-fixture unit, contract, security, handler, fitness and skipped
   GPU tests plus the architecture/model-card/runbook documentation.
8. Run the full local gate, review the diff against the twenty Phase 4 security
   questions, commit once, push and open a stacked pull request linked to #5.

Completion evidence (2026-08-24): 165 CPU/local tests pass. Three optional
structural-tool probes and the explicitly gated GPU integration scaffold skip
with stated reasons. Ruff formatting/lint, strict mypy across 93 files,
deterministic schema regeneration, OpenAPI, both Phase 3 smoke paths, migrations,
repository safety, manifest validation, checkpoint dry-run, Docker policy and
the generated-fixture mock handler pass. Secure retrieval additionally pins the
TLS connection to a connect-time revalidated global IP to close DNS-rebinding
TOCTOU. No checkpoint, real inference, CUDA runtime, live input request, RunPod
resource, GPU, container build/publication, API integration or Phase 5 work was
performed.

### Phase 5 — Container publication and cloud-GPU execution (not authorized)

Dependencies: the Phase 4 worker passes locally and its contracts are frozen.

Candidate worktrees: `feat/phase-5-worker-image` and
`feat/phase-5-runpod-integration` may proceed independently.

Deliverables: pinned dependencies, retained upstream notices, non-root runtime
where practical, commit-SHA GHCR tags, image digest capture, GitHub Actions image
build, temporary Pod validation, and then a queue-based serverless endpoint.

Acceptance: one explicitly authorized GPU smoke job verifies evidence hash and
schema; the worker image is addressed by digest; no credential appears in the
image, logs, workflow, repository, or report.

### Phase 6 — Async detector orchestration (not authorized)

Dependencies: Phases 3 and 5.

Candidate worktrees: detector job persistence and cloud client may proceed in
parallel against frozen contracts.

Deliverables: asynchronous submission/polling, lifecycle persistence, strict
returned identity/hash validation, immediate result copying, retries, and a
private manual-review bundle that composes structural and detector records.

Acceptance: an uploaded evidence item can be submitted, polled, validated,
persisted, and included in a deterministic report without allowing narrative
tools to alter evidence or machine-produced results.

### Phase 7 — Independent image evidence families (not authorized)

Dependencies: the complete Phase 6 vertical slice is stable.

Candidate worktrees: one per detector or evidence family.

Deliverables: a second neural detector, C2PA/provenance, compression analysis,
copy-move checks, and manipulation localization. Structural Phase 3 outputs are
reused rather than reimplemented.

Acceptance: disagreement and unavailable tests remain visible without averaging
incommensurate raw scores or producing a single-detector verdict.

### Phase 8 — Audio forensics (not authorized)

Dependencies: Phases 3 and 6; image operational controls proven.

Candidate worktrees: audio preprocessing and detector adapters can proceed in
parallel once their shared output shape is agreed.

Deliverables: immutable PCM derivatives with lineage, segment-aware detectors,
codec/channel context, and timeline reporting.

Acceptance: originals remain unchanged; derivatives identify exact tools and
parameters; overlapping results form a timeline instead of one opaque score.

### Phase 9 — Video forensics (not authorized)

Dependencies: Phases 7–8.

Candidate worktrees: scene/keyframe, temporal detector, face, audio, and
audiovisual adapters.

Deliverables: scene and structure segmentation, keyframe lineage, temporal
analysis, and cross-modal result correlation.

Acceptance: image, audio, face, and temporal results resolve to timestamps; no
long video is reduced to a single center-crop or opaque invocation.

### Phase 10 — Provenance and policy-gated OSINT (not authorized)

Dependencies: Phase 6 reporting and an approved case privacy policy.

Candidate worktrees: C2PA/provider verification and each approved OSINT adapter.

Deliverables: network policy enforcement, audit records, bounded provider
clients, source citations, and privacy skip states.

Acceptance: every network call is policy-gated, auditable, and distinct from
content inference; restricted cases record `SKIPPED_BY_PRIVACY_POLICY`.

### Phase 11 — Calibration and evidence fusion (not authorized)

Dependencies: multiple evidence families and representative evaluation data.

Deliverables: versioned calibration datasets, domain-shift evaluation,
contradiction-preserving fusion, limitations, and decision thresholds.

Acceptance: raw scores are never averaged as probabilities; calibration lineage
is complete; claims do not exceed validation evidence; alternative explanations
and correlated detector families remain explicit.

### Phase 12 — Dataset and continual-learning plane (not authorized)

Dependencies: stable production telemetry with explicit training permission,
dataset governance, Phase 11 evaluation gates, and rollback mechanisms.

Candidate worktrees: manifests/lineage, augmentation, candidate training,
evaluation, and promotion policy.

Deliverables: consent/license manifests, isolated candidate training,
evaluation, model cards, shadow/canary promotion, and rollback.

Acceptance: production evidence is excluded by default; licenses and consent are
machine-checkable; scheduled training creates candidates only; human approval
and rollback precede promotion.

### Phase 13 — Optional automated reasoning (not authorized)

Dependencies: deterministic reports and mature review policy.

Deliverables: citation-bound analytical assistance over immutable report data.

Acceptance: reasoning cannot alter evidence or test records; citations resolve
to IDs; contradictions, alternatives, missing tests, and limitations are
mandatory; humans retain approval responsibility.

## Dependency map

```text
Phase 0 -> Phase 1 -> Phase 2 -> Phase 3 -> Phase 4 -> Phase 5 -> Phase 6
                                             |                     |
                                             |                     +-> Phase 7 -> Phase 9
                                             |                     +-> Phase 8 ----+
                                             |                     +-> Phase 10
                                             +-------------------------------------+
Phase 7 + Phase 10 -> Phase 11 -> Phase 12
Phase 6 -------------------------------> Phase 13 (optional)
```

Contracts merge before independent worktrees begin. Parallel branches must not
modify the same contract version without a coordination issue and migration
plan.

## Cross-cutting constraints

### Security and privacy

- Treat media paths, filenames, archives, metadata, signed URLs, detector
  responses, and external URLs as untrusted input.
- Evidence originals are create-only. No code path may truncate, replace, or
  transform an original in place.
- Evidence, reports, datasets, model caches, and credentials stay outside Git.
- Use bounded streaming, timeouts, content sniffing, schema validation, SSRF
  controls, least-privilege credentials, audit logs, encryption, retention, and
  object versioning when those phases are authorized.
- Production evidence is excluded from training unless case-specific permission
  and dataset governance explicitly authorize it.

### Licensing and provenance

- Pin external source commits, model revisions, checkpoint hashes, base images,
  and dependency locks.
- Retain upstream notices and record code, model, and dataset licenses
  separately; a code license does not grant dataset or model rights.
- Store large objects externally behind immutable manifests containing URI,
  version, byte length, SHA-256, license, source, and lineage.

### Model risk

- A raw score is not a probability, confidence value, authorship claim, or final
  real/fake verdict.
- Calibrated values require a named calibrator, calibration dataset lineage,
  version, and applicability constraints.
- Benchmark metrics are not assumed production performance.
- Detector agreement does not imply independence; reports group related evidence
  families and preserve contradictions and alternative explanations.
- Failures and unperformed tests are evidence about coverage and are never
  silently discarded.

## Phase 1 file tree

```text
.
├── AGENTS.md
├── PLAN.md
├── README.md
├── .gitignore
├── .env.example
├── pyproject.toml
├── Makefile
├── apps/api/README.md
├── docs/
│   ├── architecture/system-overview.md
│   ├── adr/0001-monorepo.md
│   ├── adr/0002-evidence-immutability.md
│   ├── adr/0003-detector-contracts.md
│   └── examples/
│       ├── example-case.json
│       └── example-detector-result.json
├── packages/
│   ├── contracts/src/forensic_contracts/{__init__.py,models.py}
│   ├── contracts/tests/test_models.py
│   └── evidence/README.md
├── schemas/*.schema.json
├── scripts/{generate_schemas.py,check_repository_safety.py}
├── tests/README.md
└── workers/README.md
```

## Phase 1 execution order

1. Establish this plan and the repository/architecture documentation.
2. Implement contracts and synthetic examples only.
3. Generate schemas and confirm regeneration is deterministic.
4. Run formatting, linting, strict typing, tests, and safety checks.
5. Review the complete diff for privacy, security, lineage, compatibility, and
   terminology.
6. Create one local commit: `feat(contracts): establish forensic platform foundation`.
7. Push a feature branch and create a pull request only if an authenticated
   remote is already available.
