# ADR 0007: Select Community Forensics as the first image detector

- Status: accepted for Phase 4 adapter development
- Date: 2026-08-24

## Context

The first detector must exercise the shared job/result contracts without
turning one model output into a case verdict. Community Forensics publishes an
official implementation, an immutable source history, evaluation code, model
weights, and an MIT license. Its 384-pixel model has a compact one-logit output
that is suitable for testing detector identity and preprocessing lineage.

## Decision

Implement one adapter for the 384-pixel Community Forensics model. The Phase 4
default is a deterministic mock backend. A separate real backend is present for
later Linux AMD64 CUDA validation and refuses to start without CUDA, a complete
container identity, and the exact verified checkpoint.

The adapter stores the pre-sigmoid classifier logit as `raw_score`. The
upstream class mapping is `0=real` and `1=fake`; a non-negative logit therefore
maps to the upstream `fake` class. That mapping is only a description of the
model output. It is not a probability, confidence, authenticity finding, or
forensic verdict. Calibration fields remain null.

## Consequences

Phase 4 can validate the worker boundary entirely on a Mac without PyTorch,
CUDA, a checkpoint, external storage, or RunPod. Real parity remains unproven
until an authorized GPU run compares this wrapper with the pinned official
implementation. No report or FastAPI integration is added in this phase.
