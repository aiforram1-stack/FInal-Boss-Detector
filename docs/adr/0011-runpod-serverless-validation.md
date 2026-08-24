# ADR 0011: Queue-only RunPod Serverless validation

- Status: Proposed for Phase 6 preparation review
- Date: 2026-08-24
- Scope: first controlled Community Forensics GPU validation

## Context

The Phase 5 container pipeline packages the pinned Community Forensics adapter
without model weights. Real checkpoint loading, CUDA fitness, upstream parity,
and inference remain unverified. Phase 6 authorizes preparation for one private
queue-based RunPod Serverless endpoint, but no billable operation is allowed
until an exact configuration and cost proposal receives the exact approval
phrase.

The repository history is stacked. Pull requests for Phases 2 through 5 remain
open, so this preparation branch is based on Phase 5 and must target that branch.
It cannot supply an authoritative `main` image digest until the stack is
reviewed, merged, and protected publication succeeds.

Current official RunPod documentation describes asynchronous queue operations
(`/run`, `/status`, `/cancel`, `/retry`, `/purge-queue`, `/health`), scale-to-zero
worker limits, five-second idle timeout, queue-delay scaling, ordinary
FlashBoot, and host-cached Hugging Face models. RunPod's supported model cache
root is `/runpod-volume/huggingface-cache/hub`.

The current REST v2 endpoint-create surface selects GPU pools, not exact GPU
type IDs. On the audit date, `AMPERE_24` costs USD 0.69/hour and contains L4,
RTX A5000, RTX 3090, and a 24 GB Blackwell MIG type. The last type is not
approved by this phase. The current `set-endpoint-gpus` operation supports pool
selection plus explicit type exclusions and a minimum CUDA version. REST v2
endpoint creation does not expose the cached-model field; the console documents
one Model field per endpoint but does not document that this field guarantees
the worker's required immutable revision.

## Decision

### Approval, budget, and infrastructure boundary

The endpoint proposal is immutable for approval purposes: private GHCR digest,
source commit, registry-credential reference, cached-model reference and
separate required revision, complete observed GPU-pool membership, approved and
excluded type IDs, CUDA floor, current rate, disk size, min/max workers,
timeout, scaling, and cost estimate are canonically hashed. Only the exact phrase
`APPROVE PHASE 6 SERVERLESS COST` authorizes that proposal.

The endpoint is queue based and selects `AMPERE_24`. Its observed pool members
must be completely partitioned into the approved L4/A5000/RTX 3090 set and an
explicit exclusion set before a job is submitted. The current Blackwell MIG
member is excluded. The minimum host CUDA version is 12.4 without an upper
restriction. Minimum workers is zero, maximum workers is one during approved
execution, one GPU is used per worker, the idle timeout is five seconds, and no
network volume or data-centre restriction is used by default. Maximum workers
becomes zero after validation. Total spend is capped at USD 2.00 and paid jobs
at three. No Pod fallback is permitted without separate approval.

### One cached model, resolved fail closed

The worker accepts a configurable RunPod Hugging Face cache root and resolves
only the exact `OwensLab/commfor-model-384` snapshot revision and
`model.safetensors`. Snapshot and reference paths cannot escape the model cache;
the checkpoint must resolve to that model's blob store. Unexpected additional
weight files, inconsistent refs, malformed bounded safetensors metadata, byte
length mismatches, and SHA-256 mismatches fail closed. Runtime downloads remain
disabled.

The RunPod Model field records only `OwensLab/commfor-model-384`. Because the
current REST v2/MCP creation surface does not configure that field and the
console documentation does not promise immutable-revision semantics, a
supported authenticated control path must attach and then prove the field
before a job. The worker still requires the exact pinned snapshot directory and
consistent ref; a default-branch move fails closed instead of becoming a model
update.

Bootstrap mode observes the actual cached byte length and hash and labels the
receipt `OBSERVED_BOOTSTRAP_HASH`. It does not claim final verification. Normal
GPU validation refuses the legacy or absent status and requires the observed
identity in the checked-in manifest and republished container.

### One paid validation bundle

The `gpu_validation` operation combines CUDA/one-GPU/VRAM readiness, model
identity, evaluation mode, official upstream preprocessing/model parity,
controlled generated-fixture inference, one warm-up, at least five repetitions,
repeatability, negative tests, timing, and VRAM telemetry. This avoids repeated
cold starts. The detector artifact retains an uncalibrated raw pre-sigmoid
logit, null calibration metadata, and no forensic verdict.

Versioned artifacts use UTC timestamps, complete source/container/model
identity, sanitized payloads, and canonical SHA-256 integrity. Full logs,
secrets, signed URLs, endpoint credentials, cache paths, checkpoint bytes, and
private evidence are prohibited.

### Pure local control logic

Repository code builds and validates endpoint proposals, budget records,
approval bindings, `/run` payloads, current RunPod job states, bounded polling,
deadline cancellation, output sanitization, health parsing, and the final
zero-worker lock. It performs no network access. Account reads and eventual
mutations use the connected RunPod MCP/API control plane so API keys do not
enter repository code or shell history.

## Consequences

- The preparation branch is fully testable on macOS without CUDA, Docker, a
  checkpoint, model download, or RunPod resource.
- The first cloud action must wait for prerequisite merges, a newly published
  immutable image, attestation verification, read-only account audit, private
  registry readiness, current pricing, and exact user approval.
- Bootstrap requires a manifest update and second protected image publication
  before final validation, adding review latency but binding validation to the
  observed checkpoint.
- One generated fixture proves adapter parity only for the pinned runtime and
  device; it does not establish calibration, general accuracy, production
  throughput, or cross-GPU determinism.
- The main FastAPI application remains disconnected and Phase 7 remains out of
  scope.

## References

- [RunPod operation reference](https://docs.runpod.io/serverless/endpoints/operation-reference)
- [RunPod job states](https://docs.runpod.io/serverless/endpoints/job-states)
- [RunPod endpoint settings](https://docs.runpod.io/serverless/endpoints/endpoint-configurations)
- [RunPod Hugging Face model caching](https://docs.runpod.io/serverless/development/huggingface-models)
- [Community Forensics source](https://github.com/JeongsooP/Community-Forensics)
- [Pinned Community Forensics model](https://huggingface.co/OwensLab/commfor-model-384/tree/6076002bf0d9dd37537f965ee2f06f826c333b61)
