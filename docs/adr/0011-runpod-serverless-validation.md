# ADR 0011: Queue-only RunPod Serverless validation

- Status: Accepted for Phase 6; execution safety-stopped
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

Pull requests for Phases 2 through 6 preparation and repair PRs #16, #18, #19,
#20, and #21 are merged. Protected publication accepted source commit
`18f499d79aed272064a0653f1d615cc5816ab6e0` as private
Linux AMD64 image
`ghcr.io/aiforram1-stack/forensic-image-community@sha256:c2fdf5625301683beb18c71e04685a205fb2e7e34911e6efac177f452e7a0117`.
The GitHub repository is public, the GHCR package remains private and
source-linked, and every release gate passed. The checkpoint remains absent
from the image and CUDA validation has not completed.

One queue endpoint and its private-registry credential now exist. The first
bootstrap failed closed at cache-layout resolution. After repair, protected
publication and renewed exact cost approval, a second bootstrap worker entered
a repeated start loop and RunPod introduced an unexpected replacement worker.
The queued job was cancelled immediately. The endpoint is retained at minimum
zero/maximum zero with no workers or jobs; no Pod or network volume exists. The
observed balance delta is approximately USD 0.0085, below the USD 2.00 cap.
The account worker quota remains unexposed by available control surfaces.

The retained endpoint log later proved that the image entrypoint and repaired
cache resolver completed before the pre-queue GPU fitness probe failed. Because
that generic startup exception discarded the specific fitness error code,
bootstrap mode now starts the RunPod request loop after cache validation and
runs full fitness inside the one controlled bootstrap request. A failed probe is
therefore returned as a structured error without creating a platform restart
loop. Verified validation still requires the full fitness gate before starting
its request loop.

The exact four-job continuation proposal was later approved and used that
protected digest. The approval-time `AMPERE_24` catalog listed only RTX A5000
and RTX 3090, but the scheduler assigned
`NVIDIA RTX PRO 6000 Blackwell Server Edition MIG 1g.24gb`. The controller
observed the disallowed identity while the job remained `IN_QUEUE`, cancelled
it, and restored maximum workers to zero before handler execution. No
checkpoint, CUDA, model-load, inference, or platform-retry result exists from
that submission.

Current official RunPod documentation describes asynchronous queue operations
(`/run`, `/status`, `/cancel`, `/retry`, `/purge-queue`, `/health`), scale-to-zero
worker limits, five-second idle timeout, queue-delay scaling, ordinary
FlashBoot, and host-cached Hugging Face models. RunPod's supported model cache
root is `/runpod-volume/huggingface-cache/hub`.

The current REST v2 endpoint-create surface selects GPU pools, not exact GPU
type IDs. On the latest audit, `AMPERE_24` costs USD 0.69/hour and its catalog
response reported RTX A5000 and RTX 3090. Both are approved by this phase, but
the scheduler proved that the response is not a complete placement allowlist.
Proposal membership is therefore the union of the current catalog response and
all scheduler-observed types. The known 24 GB Blackwell MIG type must remain
explicitly excluded even when absent from the latest catalog response. The
current `set-endpoint-gpus` operation supports pool selection plus explicit
type exclusions and a minimum CUDA version. REST v2 endpoint creation does not expose
the cached-model field. The supported
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

The budget record separately binds prior spend, the number of already submitted
jobs, expected and worst-case cold-start seconds, and the remaining submission
count. The hidden-GPU cancellation consumed submission three without handler
execution. On 2026-08-25 the user explicitly raised the total ceiling to five.
Breaking budget schema 1.2 therefore binds three consumed submissions, exactly
two planned jobs, zero diagnostic retries, and five submissions total. A fresh
exact cost proposal remains required before another paid worker starts.

The consumed continuation proposal used a 600-second expected cold start and a
conservative 1,200-second worst case, 180 seconds for bootstrap, and 360 seconds
for validation. At the audited `AMPERE_24` rate of USD 0.69/hour, remaining
normal compute is approximately USD 0.3355. Two worst-case starts plus both
600-second execution ceilings and idle charges are approximately USD 0.6919.
Including incurred spend and USD 0.01 reserved for ephemeral container disk,
the total Phase 6 estimates were approximately USD 0.3540 normally and USD
0.7104 worst case. A replacement budget must be recalculated immediately before
the new exact proposal. The hard USD 2.00 stop remains unchanged.

The endpoint is queue based and selects `AMPERE_24`. Its current catalog and
historical scheduler observations must be completely partitioned into the
approved L4/A5000/RTX 3090 set and an explicit exclusion set before a job is
submitted. The scheduler-observed Blackwell MIG type is a mandatory exclusion.
The minimum host CUDA version
is 12.4 without an upper restriction. Minimum workers is zero, maximum workers
is one during approved
execution, one GPU is used per worker, the idle timeout is five seconds, and no
network volume or data-centre restriction is used by default. Maximum workers
becomes zero after validation. Total spend is capped at USD 2.00 and the current
paid ceiling is five: three consumed and exactly two remaining, with no retries.
No Pod fallback is permitted without separate approval.

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
- The refreshed proposal was approved and bound to the repaired publication,
  but its worker entered a repeated start loop and RunPod temporarily reported
  an unexpected second replacement worker. The job remained queued and was
  cancelled; no bootstrap receipt, checkpoint observation, CUDA fitness, model
  load or inference result was produced. Available live logs showed repeated
  system start events without application output. Retained endpoint logs later
  isolated the failure to the pre-queue GPU fitness stage, motivating the
  bootstrap-only deferred-fitness repair without weakening verified validation.
- All three paid bootstrap submissions and their approvals are consumed for
  execution purposes. The third was cancelled before handler execution when
  the scheduler assigned the known-denied Blackwell MIG type even though it was
  absent from the current catalog response. The proposal schema now requires
  that scheduler-observed type to remain explicitly excluded.
- The retained endpoint must remain maximum zero until a refreshed proposal and
  budget receive the exact approval phrase. The user authorized a
  five-submission total ceiling: three are consumed, exactly two remain, and no
  retry is allowed. This cap is not permission to bypass repeated-worker,
  unexpected-second-worker, GPU-identity, or spend stop conditions.
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
- [RunPod Serverless logs](https://docs.runpod.io/serverless/development/logs)
- [RunPod Hugging Face model caching](https://docs.runpod.io/serverless/development/huggingface-models)
- [Community Forensics source](https://github.com/JeongsooP/Community-Forensics)
- [Pinned Community Forensics model](https://huggingface.co/OwensLab/commfor-model-384/tree/6076002bf0d9dd37537f965ee2f06f826c333b61)
