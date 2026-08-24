# Multimedia Forensic Platform

Repository foundation, shared contracts, immutable local evidence intake, and
CPU-only structural reporting for an evidence-first multimedia forensic
platform. The implementation is intentionally limited to Phases 0–3. It
preserves originals in content-addressed storage, verifies their hashes before
each analysis, records every structural test state, and generates canonical JSON
plus escaped self-contained HTML.

No detector inference, cloud deployment, frontend, authentication, training,
model weights, PDF, OSINT, or real media are included. Reports contain
structural observations and coverage only—never a real/fake, authorship, or
AI-generation verdict. Local preservation is application-enforced append-only
behavior, not production or regulatory WORM.

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
- `apps/api/`: FastAPI routes, services, SQLite persistence, and migrations.
- `schemas/`: generated JSON Schemas committed for non-Python consumers.
- `workers/`: reserved for later explicitly authorized detector phases.

Raw detector scores are detector-specific evidence. They are not probabilities,
confidence claims, or final forensic verdicts.
