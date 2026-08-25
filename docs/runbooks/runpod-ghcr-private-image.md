# RunPod Serverless validation runbook

This runbook governs the first Community Forensics GPU validation. It is a
queue-only, scale-to-zero Phase 6 procedure. Readiness pull requests do not
create a RunPod endpoint, worker, job, Pod, volume, registry credential, or
other billable resource.

## Hard gates

Before any endpoint creation or `/run` request:

1. All prerequisite GitHub pull requests must be reviewed and merged in order.
2. Protected publication from `main` must produce a private Linux AMD64 image,
   immutable digest, release manifest, SBOM, provenance, and a passing GitHub
   artifact-attestation verification.
3. A read-only RunPod audit must confirm balance, recent billing, endpoints,
   jobs, Pods, volumes, storage, credential names/IDs, GPU availability, rates,
   and worker quota. Stop if any unexpected billable resource is active.
4. A RunPod-managed, read-only GHCR credential must exist before endpoint
   creation. If absent, report the planned non-secret name and stop for the
   exact approval phrase before any credential mutation. The user creates the
   GitHub token and enters it directly in RunPod; never paste its value into
   Codex, Git, shell history, issues, logs, or reports.
5. The exact endpoint proposal and cost estimate must be recorded. When the
   registry credential is initially absent, the first approval authorizes only
   secure credential setup. Bind the returned stored credential ID into a
   refreshed proposal and obtain the exact phrase again before endpoint
   creation.
6. The user must send exactly `APPROVE PHASE 6 SERVERLESS COST` for the final
   proposal. Any material configuration, credential ID, catalog membership, or
   price change invalidates approval.

The maximum approved Phase 6 spend is USD 2.00. At most three paid jobs are
allowed: the planned bootstrap and validation jobs plus one explicitly recorded
transient diagnostic retry. Premium GPUs, Pods, and network volumes require
separate approval and are not part of this runbook.

The refreshed post-repair budget deliberately set diagnostic retries to zero.
Its cancelled bootstrap and unexpected second worker trigger mandatory stop;
the theoretical three-job ceiling is not permission to submit another job.

## Immutable release verification

The current Phase 6 bootstrap image is the protected publication of cache-layout
repair PR #18:

```text
ghcr.io/aiforram1-stack/forensic-image-community@sha256:8d6eb3b7b57f8cecc778d859ca62b3cfbd2fc3492f15f547f6890c30948f87c5
```

It is Linux AMD64, 6,629,477,656 bytes, and binds source commit
`847cad109e9d794e2060a3e116cb343a1de4daa3`. Protected run
[`32823075408`](https://github.com/aiforram1-stack/FInal-Boss-Detector/actions/runs/32823075408)
passed SBOM, provenance, GitHub attestation, vulnerability, source-link,
pull-by-digest, content, mock-smoke, and final fail-closed gates. The checkpoint
is absent and real GPU inference is marked not run.

Download the protected publication artifact, validate its checksum, and verify
that `container-release.json` matches the intended source commit, Linux AMD64
platform, checkpoint-absent state, OCI revision label, SBOM, provenance,
artifact attestation, and mock smoke result. Real GPU inference must still be
marked not run.

From a trusted authenticated workstation:

```bash
export IMAGE_DIGEST_REFERENCE='ghcr.io/aiforram1-stack/forensic-image-community@sha256:8d6eb3b7b57f8cecc778d859ca62b3cfbd2fc3492f15f547f6890c30948f87c5'
export GITHUB_REPOSITORY='aiforram1-stack/FInal-Boss-Detector'
make image-community-attestation-verify
scripts/verify_published_image.sh \
  "${IMAGE_DIGEST_REFERENCE}" \
  '847cad109e9d794e2060a3e116cb343a1de4daa3' \
  'https://github.com/aiforram1-stack/FInal-Boss-Detector'
```

Never substitute `latest`, `main`, `stable`, or a source-SHA tag for the digest.

## Current RunPod readiness audit

The final 2026-08-25 safety audit found:

- balance: USD 9.9915030333, for an observed USD 0.0084969667 Phase 6 balance
  delta from the USD 10.00 starting balance;
- itemized Serverless billing still lagged the balance and reported USD
  0.003202941734343767 at the final read;
- one retained queue endpoint, safety-locked at minimum zero/maximum zero;
- zero endpoint workers and zero queued/running jobs;
- zero Pods and zero network volumes;
- one endpoint-bound template and one private-registry credential;
- no billable network storage or competing resources observed;
- local `runpodctl` version: 2.11.0 and authenticated;
- account worker quota: not exposed by the connected v2/MCP or visible account
  settings and therefore unverified.

The planned credential name is `ghcr-aiforram1-phase6-readonly`. Use a
short-lived GitHub PAT classic with only `read:packages`; do not grant `repo`,
write, or delete scopes. The GitHub package remains private. Credential and CLI
authentication must be completed through the signed-in browser/local secure
flow only after approval, with no secret value entering Codex or repository
files.

## Cached model contract

The public MIT-licensed checkpoint is
`OwensLab/commfor-model-384`, revision
`6076002bf0d9dd37537f965ee2f06f826c333b61`, file
`model.safetensors`. Configure RunPod's one cached model for the endpoint. The
worker reads the standard cache root:

```text
/runpod-volume/huggingface-cache/hub
```

It resolves only `models--OwensLab--commfor-model-384/snapshots/<revision>`,
requires the exact revision, and permits only the expected checkpoint. Two
cache representations are accepted: the canonical Hugging Face snapshot
symlink must resolve inside that model's `blobs` directory, or RunPod may
materialize the checkpoint as a regular file directly inside the exact pinned
snapshot. A materialized file cannot be a symlink or nested path. Both layouts
receive the same bounded safetensors inspection, byte-length check, and full
SHA-256 calculation. Handler execution never downloads a model. No network
volume is attached.

The first approved bootstrap attempt on 2026-08-25 found that the checkpoint
was not backed by the model-local blob path required by the pre-repair resolver;
it did not establish the exact alternate layout. The worker failed before CUDA
or model loading, the job was cancelled, maximum workers was set to zero, and
no automatic retry was submitted. A replacement image must pass the CPU
materialized-cache fixture before the endpoint is unlocked again, and the next
receipt must record the observed layout. Treat the controlled no-job startup as
the one allowed diagnostic attempt: bind the replacement digest and remaining
budget into a refreshed proposal and obtain the exact cost-approval phrase
again before starting another worker.

The refreshed proposal received that exact approval and deployed repair source
`847cad109e9d794e2060a3e116cb343a1de4daa3` by immutable digest. During its one
bootstrap submission, an A5000 worker entered a repeated container-start loop.
RunPod retained that unhealthy worker while introducing a replacement, so the
observable worker total became two despite configured maximum one. The job
never left `IN_QUEUE`; the controller cancelled it and restored maximum zero.
No bootstrap receipt, checkpoint observation, CUDA fitness, model load or
inference result exists. Live logs showed repeated system start events without
application output. Worker logs disappeared when the workers terminated;
RunPod's retained endpoint log must be inspected for the exact startup
exception. This is the runbook's repeated-worker/unexpected-second-worker stop
condition. Do not unlock the endpoint under either prior approval.

RunPod's supported cached-model control is `runpodctl` 2.4.0 or newer using
`serverless create --model-reference`. The argument is the full Hugging Face URL
with a `:ref`; Phase 6 must use the immutable value:

```text
https://huggingface.co/OwensLab/commfor-model-384:6076002bf0d9dd37537f965ee2f06f826c333b61
```

The current REST v2/MCP endpoint-create operation does not expose this field.
After approval, use the authenticated `runpodctl` path, verify the returned
endpoint, and then apply the explicit GPU exclusions through the structured
control plane before submitting a job. The worker's exact
`snapshots/<revision>` check remains the independent fail-closed authority. If
the model reference cannot be attached and proved, stop; do not create a volume
or silently use another snapshot.

## Exact endpoint invariants

Use [the committed proposal template](../../infra/runpod/image-reference.example.yaml)
only as a review document. Copy it to an ignored `infra/runpod/phase6.local.*`
file for identifiers returned by RunPod.

- endpoint type: queue;
- REST v2 GPU pool: `AMPERE_24`, one GPU per worker;
- approved pool members: L4, RTX A5000, and RTX 3090 only;
- exclude every other observed member (currently the 24 GB Blackwell MIG SKU)
  with `set-endpoint-gpus` before submitting a job;
- minimum host CUDA version: 12.4; do not narrow the allowed-version list;
- minimum workers: zero;
- maximum workers: one during approved jobs, zero at final lock;
- idle timeout: five seconds;
- scaler: `QUEUE_DELAY`, value four;
- execution timeout: 600,000 ms;
- ordinary `FLASHBOOT` enabled;
- no data-centre restriction unless required for placement;
- no network volume;
- one private-registry credential reference;
- one cached-model reference;
- 10 GB ephemeral container disk, the smallest safe whole-GB value for the
  measured 6.629 GB image while leaving approximately 3.37 GB headroom.

Refresh the Serverless GPU catalog immediately before the cost proposal. The
proposal must record the complete observed membership of `AMPERE_24`, and that
set must be fully partitioned into approved and excluded IDs. A new or missing
pool member, changed rate, changed availability, changed CUDA compatibility, or
changed model-cache control path invalidates the proposal and requires a new
approval. Current REST v2 creation accepts pool IDs rather than GPU type IDs;
the exact SKU exclusions are a second configuration operation performed before
any `/run` request. Endpoint creation alone must not be treated as ready.

Production environment configuration must include the exact source commit,
container digest, and endpoint release identity. Bootstrap mode sets
`IMAGE_COMMUNITY_CHECKPOINT_BOOTSTRAP_MODE=true` and
`IMAGE_COMMUNITY_REQUIRE_VERIFIED_CHECKPOINT_HASH=false`. Verified mode reverses
those values. Both modes set `IMAGE_COMMUNITY_PHASE6_ONLY_MODE=true`, keep model
downloads disabled, and use the configured cache root. An ordinary
`DetectorJob` is rejected by this endpoint so private or user-submitted media
cannot enter the validation-only path. Never record a full environment dump.

## Audited cost proposal

The selected `AMPERE_24` pool is USD 0.69/hour, or approximately USD
0.0001916667/second. The observed members are RTX A5000 (high availability), L4
(low), RTX 3090 (low), and a 24 GB Blackwell MIG type (high). Only the first
three are approved; the Blackwell MIG type is excluded before any job.

Cost assumptions are 600 seconds expected cold start per job, 180 seconds
bootstrap execution, 360 seconds validation execution, and five seconds idle
per job. That yields approximately USD 0.1505 for bootstrap, USD 0.1850 for
validation, and USD 0.3355 compute normally. A conservative worst case uses
1,200 seconds cold start plus the 600-second execution limit and five-second
idle charge for each of the two planned jobs plus one diagnostic retry:
approximately USD 1.04 compute. At the documented approximately USD
0.10/GB/month rate, allocate USD
0.01 for the 10 GB ephemeral disk's five-minute billing intervals; the normal
rounded estimate is USD 0.35. Reserve USD 1.20 overall; the hard stop remains
USD 2.00. RunPod host caching uses the public model without billing worker time
for the model download and requires no network volume. See RunPod's current
[Serverless pricing](https://docs.runpod.io/serverless/pricing) and
[cached-model](https://docs.runpod.io/serverless/endpoints/model-caching)
documentation.

## Job 1: checkpoint bootstrap

After approval, create the endpoint with min zero/max one and first confirm no
worker started. Submit one asynchronous `/run` job using the versioned
`CheckpointBootstrapRequest`; do not use `/runsync`. The request policy is:

```json
{"executionTimeout":600000,"ttl":1800000}
```

Poll `/status/{job_id}` no faster than every five seconds. At the local client
deadline, call `/cancel/{job_id}`. Persist the sanitized response immediately,
then confirm health reports zero active, queued, and running work after the
idle timeout.

The receipt must say `OBSERVED_BOOTSTRAP_HASH`; it is not final production
verification. Scan it for secrets and internal cache paths. Update the model
manifest, model card, verification notes, and Phase 6 issue through a pull
request using `chore(model): record Community Forensics checkpoint hash`. Do
not merge automatically.

After review and merge, protected publication must create and verify a new
immutable image digest whose manifest contains the observed checkpoint hash
while the checkpoint bytes remain absent.

Current status: both submitted bootstrap jobs were cancelled before execution,
so this job remains incomplete and the manifest must not be promoted to
`OBSERVED_BOOTSTRAP_HASH`. Resume only after retained endpoint logs identify the
startup failure, any repair is reviewed and republished, and a fresh proposal
receives the exact cost-approval phrase.

## Job 2: complete GPU validation

First require an empty queue and zero active workers, set maximum workers to
zero, update the endpoint to the republished digest and verified-mode
configuration, verify identity, then restore maximum workers to one. Submit one
asynchronous `GpuValidationRequest`.

The single job performs checkpoint identity verification, CUDA/one-GPU/VRAM
fitness, evaluation-mode and inference-mode loading, official-upstream parity,
one controlled generated fixture inference, one warm-up, at least five measured
repetitions, output stability, wrong-input-hash rejection, wrong-checkpoint-hash
rejection without changing bytes, mock-mode rejection, timings, and VRAM
telemetry. A raw logit is uncalibrated supporting evidence, never a probability
or verdict.

Do not automatically retry checkpoint, revision, preprocessing, parity, input,
mock-mode, VRAM, or CUDA incompatibility failures. One transient retry is
possible only within the approved job and cost caps.

## Billing and final lock

After each paid job, query balance, billing, execution duration, and endpoint
health. Stop as spend approaches USD 2.00, on repeated restarts, on a second
worker, or on unexpected retry behavior.

At completion or failure:

1. cancel remaining work and purge queued jobs if necessary;
2. confirm queued jobs, running jobs, idle workers, and running workers are all
   zero;
3. set minimum workers to zero and maximum workers to zero;
4. verify no Pod or network volume exists;
5. query billing one final time;
6. leave the endpoint present but unable to start a worker unless the user asks
   for deletion.

The 2026-08-25 failure cleanup satisfies this lock: minimum and maximum workers
are zero, the queue and in-progress count are zero, no workers are listed, and
no Pod or network volume exists. The endpoint remains present for diagnosis.

Only sanitized, small, versioned validation summaries may enter Git. Endpoint
credentials, API keys, registry identifiers, signed URLs, full logs, model
bytes, cache paths, full endpoint IDs, and private evidence stay out of Git.

The queue lifecycle and state names follow RunPod's current official
[operation reference](https://docs.runpod.io/serverless/endpoints/operation-reference),
[job-state reference](https://docs.runpod.io/serverless/endpoints/job-states),
[endpoint settings](https://docs.runpod.io/serverless/endpoints/endpoint-configurations),
and [log-retention guidance](https://docs.runpod.io/serverless/development/logs).
