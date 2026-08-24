# Multimedia Forensic Platform

Repository foundation, shared contracts, immutable local evidence intake,
CPU-only structural reporting, and the Phase 5 publication pipeline for the
Community Forensics image-worker adapter. Originals are
content-addressed, re-hashed before local analysis, and reported through
canonical JSON plus escaped self-contained HTML. The new detector boundary is
tested locally with a deterministic mock; the real CUDA backend and immutable
Linux AMD64 container are prepared but CUDA has not been executed.

No real detector inference, model download, GPU rental, RunPod deployment, frontend,
authentication, training, PDF, OSINT, or real media are included. Reports
contain structural observations and coverage only—never a real/fake,
authorship, or AI-generation verdict. Detector raw scores are likewise
uncalibrated supporting evidence. Local preservation is application-enforced
append-only behavior, not production or regulatory WORM.

## Develop

Python 3.11 or newer is required.

```bash
make setup
make schemas
make db-upgrade
make structural-check-tools
make api
```

In another terminal, create a restricted case:

```bash
curl -X POST http://127.0.0.1:8000/v1/cases \
  -H 'Content-Type: application/json' \
  -d '{"claim":"Local verification","privacy_mode":"RESTRICTED"}'
```

The full local quality gate is:

```bash
make lint
make typecheck
make test
make openapi
make safety
make structural-smoke
make report-smoke
```

The Phase 5 Mac-safe worker and container-policy gate is:

```bash
make image-community-manifest-check
make image-community-checkpoint-dry-run
make image-community-lint
make image-community-typecheck
make image-community-test
make image-community-docker-lint
make image-community-mock
make image-community-container-check
```

These commands perform no checkpoint download, CUDA execution, live object
fetch, RunPod call, container publication, or GPU provisioning. The separate
GitHub pull-request workflow builds both Linux AMD64 image targets without
publishing; protected main/manual publication is documented in
`docs/adr/0010-container-publication-and-attestation.md`.

`make schemas` must not change committed files after a clean generation.

ExifTool, ffprobe, and MediaInfo are optional. The API starts when they are
missing and records `PROVIDER_UNAVAILABLE` for their tests. To install the local
macOS toolchain explicitly:

```bash
brew install exiftool ffmpeg mediainfo libmagic
```

Nothing in this repository runs package installation automatically.

After creating a case and uploading evidence, start and retrieve analysis:

```bash
curl -X POST \
  http://127.0.0.1:8000/v1/cases/CASE_ID/evidence/EVIDENCE_ID/structural-analysis

curl \
  http://127.0.0.1:8000/v1/cases/CASE_ID/reports/structural.json

curl \
  http://127.0.0.1:8000/v1/cases/CASE_ID/reports/structural.html \
  -o structural-report.html
```

## Repository map

- [`PLAN.md`](PLAN.md): long-term milestones and current authorization boundary.
- [`AGENTS.md`](AGENTS.md): mandatory safety and architecture rules.
- [`docs/architecture/system-overview.md`](docs/architecture/system-overview.md):
  system planes and trust boundaries.
- `packages/contracts/`: immutable shared Pydantic contracts.
- `packages/evidence/`: reusable storage protocol and local backend.
- `packages/structural/`: safe tool runner, adapters, normalization, consistency,
  create-only result artifacts, and deterministic report rendering.
- `workers/image-community/`: pinned manifest, secure input/decoder pipeline,
  deterministic mock, unexecuted real CUDA backend, RunPod-compatible handler,
  Docker definition, and GPU-test scaffolding.
- `apps/api/`: FastAPI routes, services, SQLite persistence, and migrations.
- `schemas/`: generated JSON Schemas committed for non-Python consumers.
- `docs/model-cards/community-forensics.md`: scope, immutable identity, raw-score
  semantics, limitations, and license notes for the first detector.

Raw detector scores are detector-specific evidence. They are not probabilities,
confidence claims, or final forensic verdicts.
