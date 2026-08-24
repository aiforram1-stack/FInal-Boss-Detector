# Multimedia Forensic Platform

Repository foundation, shared contracts, and a local evidence-intake vertical
slice for an evidence-first multimedia forensic platform. The current
implementation is intentionally limited to Phases 0–2: planning, repository
policy, versioned Pydantic models, and a CPU-only FastAPI/SQLite service that
preserves originals in local content-addressed storage.

No detector inference, cloud deployment, frontend, report generation, training
code, model weights, or real media are included. Local preservation is
application-enforced append-only behavior, not production or regulatory WORM.

## Develop

Python 3.11 or newer is required.

```bash
make setup
make schemas
make db-upgrade
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
```

`make schemas` must not change committed files after a clean generation.

## Repository map

- [`PLAN.md`](PLAN.md): long-term milestones and current authorization boundary.
- [`AGENTS.md`](AGENTS.md): mandatory safety and architecture rules.
- [`docs/architecture/system-overview.md`](docs/architecture/system-overview.md):
  system planes and trust boundaries.
- `packages/contracts/`: immutable shared Pydantic contracts.
- `packages/evidence/`: reusable storage protocol and local backend.
- `apps/api/`: FastAPI routes, services, SQLite persistence, and migrations.
- `schemas/`: generated JSON Schemas committed for non-Python consumers.
- `workers/`: reserved for later explicitly authorized detector phases.

Raw detector scores are detector-specific evidence. They are not probabilities,
confidence claims, or final forensic verdicts.
