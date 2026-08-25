# ADR 0011: Queue-only RunPod Serverless validation

- Status: Accepted for Phase 6; cloud execution pending
- Date: 2026-08-24
- Updated: 2026-08-25
- Scope: first controlled Community Forensics GPU validation

## Context

The Phase 5 container pipeline packages the pinned Community Forensics adapter
without model weights. Real checkpoint loading, CUDA fitness, upstream parity,
and inference remain unverified. Phase 6 authorizes preparation for one private
queue-based RunPod Serverless endpoint, but no billable operation is allowed
until an exact configuration and cost proposal receives the exact approval
phrase.

Pull requests for Phases 2 through 6 preparation and release-verifier repair PR
#16 are merged. Protected publication accepted source commit
`4062b946a29288330242d108dbbed9ded4d9d736` as private Linux AMD64 image
`ghcr.io/aiforram1-stack/forensic-image-community@sha256:190618d75aad8dd38bac264c5a1eb48e9b5ee248262f25c49c67e14ec5a44437`.
The GitHub repository is public, the GHCR package remains private and
source-linked, and every release gate passed. The checkpoint remains absent and
CUDA has not run.

The read-only RunPod audit reports a USD 10.00 balance, USD 0 recent
Serverless/storage spend, and zero endpoints, workers, jobs, Pods, volumes,
templates, or registry credentials. The account worker quota is not exposed by
the available control surfaces. No RunPod resource has been created.

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
endpoint creation does not expose the cached-model field. The supported
`runpodctl` Serverless path exposes `--model-reference` and accepts a full
Hugging Face URL plus `:ref`; Phase 6 requires `runpodctl` 2.4.0 or newer and
the exact 40-character model revision.

## Decision

### Approval, budget, and infrastructure boundary

The endpoint proposal is immutable for approval purposes: private GHCR digest,
source commit, registry-credential reference, cached-model reference and
separate required revision, complete observed GPU-pool membership, approved and
excluded type IDs, CUDA floor, current rate, disk size, min/max workers,
timeout, scaling, and cost estimate are canonically hashed. Only the exact phrase
`APPROVE PHASE 6 SERVERLESS COST` authorizes that proposal.

The budget record separately binds expected and worst-case cold-start seconds.
The current proposal uses a 600-second expected cold start and a conservative
1,200-second worst case, 180 seconds for bootstrap, 360 seconds for validation,
and at most 600 execution seconds for a diagnostic retry. At the audited
`AMPERE_24` rate of USD 0.69/hour, the two-job normal estimate is USD 0.34; the
three-job compute estimate with worst-case starts is USD 1.04. The approved
proposal allocates a conservative USD 0.01 for ephemeral container disk and
reserves USD 1.20 overall while retaining the hard USD 2.00 stop.

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
`model.safetensors`. Snapshot and reference paths cannot escape the model cache.
Canonical Hugging Face snapshot symlinks must resolve into that model's blob
store. RunPod's host cache may instead materialize the checkpoint as a regular
file directly inside the exact snapshot; that representation is accepted only
without a symlink or nested path and still receives the full length, SHA-256,
and bounded safetensors checks. Unexpected additional weight files,
inconsistent refs, malformed bounded safetensors metadata, byte-length
mismatches, and SHA-256 mismatches fail closed. Runtime downloads remain
disabled.

The RunPod model reference is
`https://huggingface.co/OwensLab/commfor-model-384:6076002bf0d9dd37537f965ee2f06f826c333b61`.
The current REST v2/MCP creation surface cannot attach it, so an authenticated
`runpodctl serverless create --model-reference` control path must attach and
then prove it before a job. The worker independently requires the exact pinned
snapshot directory and consistent ref; a default-branch move fails closed
instead of becoming a model update.

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
- The first approved bootstrap worker found that the cached checkpoint was not
  backed by the model-local blob path required by the pre-repair resolver and
  failed closed before CUDA or model loading. The endpoint was locked at zero
  while bounded support for RunPod's documented snapshot-local representation,
  a CPU regression fixture, and a replacement image were prepared. The next
  bootstrap receipt must identify the observed layout. The controlled no-job
  startup diagnostic is conservatively counted as the one allowed diagnostic
  attempt, so the replacement digest and remaining budget require a refreshed
  proposal and exact cost approval before another worker starts.
- The first RunPod mutation must wait for private-registry readiness planning,
  current pricing, and exact user approval. Because no registry credential
  exists and policy also gates credential creation, the stored credential ID
  must be bound into a refreshed proposal and approved before endpoint creation.
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
