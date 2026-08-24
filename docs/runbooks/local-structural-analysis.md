# Local structural-analysis runbook

## Prepare the CPU-only service

From the repository root:

```bash
make setup
cp .env.example .env
make db-upgrade
make structural-check-tools
make api
```

The API binds to loopback by default and has no authentication. Do not expose it
to another host. Runtime evidence, results, reports, and SQLite files live under
ignored `var/` paths. Optional macOS tools may be installed explicitly with:

```bash
brew install exiftool ffmpeg mediainfo libmagic
```

This repository never runs that command. If a tool is absent, its test records
`PROVIDER_UNAVAILABLE` and the remaining analysis continues.

## Create, upload, and analyze

Create a case and upload only a small file you generated or are authorized to
use, following `docs/runbooks/local-evidence-intake.md`. Then run:

```bash
curl -X POST \
  http://127.0.0.1:8000/v1/cases/CASE_ID/evidence/EVIDENCE_ID/structural-analysis
```

The request is synchronous with bounded tool timeouts. HTTP 409 with
`EVIDENCE_INTEGRITY_FAILURE` means the preserved object was missing or no longer
matched its stored hash/size; the refusal is persisted. Do not repair or replace
the object. Preserve the local state and investigate the storage boundary.

Retrieve run history and the latest case report:

```bash
curl \
  http://127.0.0.1:8000/v1/cases/CASE_ID/evidence/EVIDENCE_ID/structural-analysis

curl \
  http://127.0.0.1:8000/v1/cases/CASE_ID/reports/structural.json

curl \
  http://127.0.0.1:8000/v1/cases/CASE_ID/reports/structural.html \
  -o structural-report.html
```

The HTML contains no original media, JavaScript, external font, or network
asset. Tool JSON and report artifacts are private even though their logical URIs
appear in manifests; never add `var/` to Git.

## Verify without optional tools

```bash
make test-structural
make structural-smoke
make report-smoke
make openapi
make safety
```

The required tests use fake or missing executables and no network. Optional
installed-tool probing is separate:

```bash
make test-tool-integration
```

Tool versions are reported as observations of the local environment. Installing
or upgrading a parser can change normalized metadata, so record the tool
inventory with any report used for review.
