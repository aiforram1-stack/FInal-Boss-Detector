# Multimedia Forensic Platform Plan

## Authorization boundary

**Only Phase 0 and Phase 1 are authorized in the current task.** All later
phases are planning context. Do not implement Phase 2 or beyond without explicit
user authorization.

Current status (2026-08-24):

- [x] Phase 0 repository foundation completed.
- [x] Phase 1 shared contracts completed and verified.
- [ ] Phase 2 is not authorized and has not been implemented.

## Mission and first vertical slice

Build a reproducible multimedia forensic platform that preserves evidence
integrity, runs pinned detector versions, stores versioned evidence records, and
separates deterministic facts from human analytical conclusions.

The first operational slice will eventually be:

```text
image upload -> immutable preservation -> cloud-GPU detector
             -> structured result -> deterministic report
             -> private manual Codex review
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

### Phase 2 — Immutable evidence storage and local API (not authorized)

Dependencies: Phase 1 contracts merged.

Candidate worktrees: `feat/002-evidence-storage`, followed by
`feat/003-upload-api` after the storage interface stabilizes.

Deliverables: streaming SHA-256/SHA-512, create-only storage backend, SQLite
development persistence, migrations, case/upload/read endpoints, file limits,
signature-based MIME validation, and untrusted-path defenses.

Acceptance: one rights-cleared test JPEG is stored once; repeat uploads do not
duplicate bytes; originals cannot be overwritten; size, corrupted-stream, MIME,
and traversal tests pass.

### Phase 3 — First image detector worker (not authorized)

Dependencies: Phases 1–2.

Candidate worktree: `feat/004-community-forensics-worker`.

Deliverables: pinned Community Forensics 384 adapter, exact official
preprocessing, verified checkpoint hash, bounded HTTPS download, input-hash
verification, one-time startup loading, fitness check, mocked unit tests, and an
opt-in GPU integration test.

Acceptance: a RunPod-compatible handler returns a valid `DetectorResult` with a
raw detector score and complete immutable identity; it never claims a verdict or
probability.

### Phase 4 — Container and cloud-GPU execution (not authorized)

Dependencies: Phase 3 worker passes locally on a temporary GPU Pod.

Candidate worktrees: `feat/005-worker-container` and
`feat/006-runpod-integration` may proceed independently after the worker entry
point and contracts are frozen.

Deliverables: pinned Docker base/dependencies, retained upstream license,
non-root runtime where practical, commit-SHA GHCR tags, image digest capture,
GitHub Actions build, Pod runbook, then queue-based RunPod Serverless endpoint.

Acceptance: one real GPU smoke job verifies the evidence hash and schema; the
API-independent worker image is addressed by digest; no secret is in image,
logs, workflow, or repository.

### Phase 5 — Async orchestration and deterministic reporting (not authorized)

Dependencies: Phases 2 and 4.

Candidate worktrees: `feat/008-gpu-client` and `feat/009-reporting` can proceed
in parallel against the stable contracts, then integrate.

Deliverables: asynchronous job submission/polling, lifecycle persistence,
strict returned-identity/hash validation, immediate result copying, deterministic
`report.json`/`report.html`, and ignored private review bundles.

Acceptance: create case, upload, analyze, persist result, retrieve JSON/HTML
report, and create a manual-review bundle end to end; deterministic fields cannot
be edited by narrative tooling.

### Phase 6 — Independent image evidence families (not authorized)

Dependencies: the complete Phase 5 vertical slice is stable.

Candidate worktrees: one per detector or evidence family.

Deliverables: second neural detector, EXIF/file structure, C2PA/provenance,
compression analysis, copy-move and manipulation localization. Results remain
separated by evidence family and failed tests remain visible.

Acceptance: disagreement and unavailable tests are reported without averaging
incommensurate raw scores or producing a single-detector verdict.

### Phase 7 — Audio forensics (not authorized)

Dependencies: Phases 1 and 5; image operational controls proven.

Candidate worktrees: audio preprocessing and detector worker can proceed in
parallel once their shared output shape is agreed.

Acceptance: originals remain unchanged; documented PCM derivatives retain
lineage; overlapping segment results and codec/language/channel context produce
a timeline rather than a single center-crop score.

### Phase 8 — Video forensics (not authorized)

Dependencies: Phases 6–7.

Candidate worktrees: structural, scene/keyframe, temporal detector, face,
audio, and audiovisual branches.

Acceptance: video is segmented by structure and scene; image/audio/face results
are correlated by timestamp; no long video is reduced to one opaque invocation.

### Phase 9 — Provenance and OSINT (not authorized)

Dependencies: Phase 5 reporting and case privacy policy.

Candidate worktrees: provider verification, C2PA, and approved OSINT adapters.

Acceptance: every network call is policy-gated, auditable, bounded, and clearly
distinguished from media-content inference; restricted cases can skip calls with
`SKIPPED_BY_PRIVACY_POLICY` recorded.

### Phase 10 — Calibration and evidence fusion (not authorized)

Dependencies: multiple detector families plus representative evaluation data.

Acceptance: calibration datasets and versions are recorded; outputs are tested
for domain shift; fusion preserves contradictions; no raw scores are averaged;
claims never exceed validation evidence.

### Phase 11 — Dataset and continual-learning plane (not authorized)

Dependencies: stable production telemetry with explicit training permission,
dataset governance, Phase 10 evaluation gates, and rollback mechanisms.

Candidate worktrees: manifests/lineage, augmentation, candidate training,
evaluation, and promotion policy.

Acceptance: production evidence is excluded by default; licenses and consent are
machine-checkable; weekly training only creates candidates; shadow/canary gates,
human approval, signed model cards, and rollback precede promotion.

### Phase 12 — Optional automated reasoning (not authorized)

Dependencies: deterministic reports and mature review policy.

Acceptance: reasoning cannot alter evidence records; citations resolve to
evidence IDs; contradictions, alternatives, missing tests, and limitations are
mandatory; humans retain approval responsibility.

## Dependency map

```text
Phase 0 -> Phase 1 -> Phase 2 -> Phase 3 -> Phase 4
                       |                    |
                       +--------------------+-> Phase 5 -> Phase 6 -> Phase 8
                                                  |          |
                                                  +-> Phase 7+
                                                  +-> Phase 9
Phase 6 + Phase 9 -> Phase 10 -> Phase 11
Phase 5 -------------------------------> Phase 12 (optional)
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
