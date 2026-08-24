# Multimedia Forensic Platform

Repository foundation and shared contracts for an evidence-first multimedia
forensic platform. The current implementation is intentionally limited to Phase
0 and Phase 1: planning, repository policy, versioned Pydantic models, JSON
Schemas, synthetic examples, and contract verification.

No evidence storage, API, detector inference, cloud deployment, frontend,
training code, model weights, or real media are included.

## Develop

Python 3.11 or newer is required.

```bash
make setup
make schemas
make lint
make typecheck
make test
make safety
```

`make schemas` must not change committed files after a clean generation.

## Repository map

- [`PLAN.md`](PLAN.md): long-term milestones and current authorization boundary.
- [`AGENTS.md`](AGENTS.md): mandatory safety and architecture rules.
- [`docs/architecture/system-overview.md`](docs/architecture/system-overview.md):
  system planes and trust boundaries.
- `packages/contracts/`: the only executable Phase 1 package.
- `schemas/`: generated JSON Schemas committed for non-Python consumers.
- `apps/api/`, `packages/evidence/`, and `workers/`: later-phase placeholders.

Raw detector scores are detector-specific evidence. They are not probabilities,
confidence claims, or final forensic verdicts.
