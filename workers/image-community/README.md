# Community Forensics image worker

This adapter, container pipeline, and Phase 6 preparation consume the shared versioned `DetectorJob`, securely
acquires and verifies one image, performs the pinned Community Forensics
evaluation preprocessing, invokes an injected backend, and returns the shared
`DetectorResult`. Local and CI execution use a deterministic mock. The CUDA
backend and queue-based RunPod entry point are present for controlled validation
but have not been run or deployed.

## Commands

From the repository root:

```bash
make image-community-setup
make image-community-lint
make image-community-typecheck
make image-community-test
make image-community-manifest-check
make image-community-checkpoint-dry-run
make image-community-docker-lint
make image-community-mock
make image-community-container-check
make phase6-check
```

These ordinary commands require neither CUDA nor torch and do not download a
model or make a live input request. The local invocation reads
`tests/fixtures/job-valid.json` and supplies the documented generated PNG
through `MemoryInputFetcher`.

`make image-community-gpu-test` is future scaffolding. It requires the explicit
`RUN_GPU_TESTS=1` gate and still skips without CUDA and the verified checkpoint.

## Design

- `input_fetcher.py`: injectable memory and constrained HTTPS retrieval;
- `image_decoder.py`: signature-aware bounded Pillow verification and RGB decode;
- `preprocessing.py`: pinned resize, crop, scaling, normalization, and fingerprint;
- `mock_backend.py`: deterministic local-only raw output;
- `community_backend.py`: lazy CUDA model loading and checkpoint verification;
- `cache_resolver.py`: strict pinned RunPod Hugging Face snapshot resolution;
- `phase6_contracts.py`: versioned bootstrap and combined validation artifacts;
- `phase6_validation.py`: observational bootstrap plus one-job GPU validation;
- `phase6_control.py`: pure approval, budget, polling, cancellation, sanitization,
  and final endpoint-lock controls;
- `job_service.py`: framework-independent orchestration and cleanup;
- `result_builder.py`: shared result construction and complete identity;
- `fitness.py`: structured mock/real readiness;
- `handler.py`: thin event validation and structured success/failure mapping.

The real backend records a raw pre-sigmoid logit. It never labels that value a
probability or forensic confidence, and calibration fields remain null.

## Checkpoint and container policy

`model-manifest.yaml` pins the official source commit, model/preprocessor
revisions, checkpoint length/SHA-256, runtime versions, and a digest-addressed
Linux AMD64 PyTorch/CUDA base. `scripts/fetch_checkpoint.py` requires both
`IMAGE_COMMUNITY_ALLOW_MODEL_DOWNLOAD=true` and `ALLOW_MODEL_DOWNLOAD=1`, uses
an external cache, and fails closed on identity mismatch. Model weights, tokens,
evidence, and caches must never enter the repository or container context.

The Dockerfile exposes two digest-pinned Linux AMD64 targets:

- `mock-test` uses Python 3.11 and CPU-only dependencies. Its entrypoint runs
  the generated-fixture smoke path; it does not install PyTorch, CUDA, RunPod,
  timm, safetensors, or Hugging Face tooling.
- `gpu-runtime` retains PyTorch 2.7.1, CUDA 12.6, cuDNN 9, the real backend and
  RunPod runtime, but no checkpoint. It defaults to production/community and
  verified-checkpoint mode, reads only the standard RunPod model cache, and
  cannot pass readiness until the endpoint supplies CUDA, the exact cached
  snapshot, immutable container digest, source commit, and release identity.
  Phase 6 sets `IMAGE_COMMUNITY_PHASE6_ONLY_MODE=true` so this validation
  endpoint rejects ordinary evidence jobs.

Both targets run as UID/GID 10001, separate `/models` from `/work/tmp`, use the
same contracts and job service, and contain no stored media fixture. Builds must
use the repository root so `.dockerignore` protects the real context and only
shared contracts plus worker source are copied.

The pull-request workflow builds and mock-smokes both targets without publishing.
The protected main/manual workflow pushes only `sha-<full-commit>` to private
GHCR and then treats the returned digest as authoritative. It adds an SBOM,
maximum BuildKit provenance, a GitHub artifact attestation where the GitHub plan
supports private-repository attestations, vulnerability reports, pull-by-digest
verification, and a versioned release manifest. It fails closed if any protected
verification is unsuccessful.

Optional Docker-host commands (authoritative only on a Linux AMD64 runner):

```bash
IMAGE=local/image-community-mock:test make image-community-container-build-mock
IMAGE=local/image-community-mock:test make image-community-container-smoke
IMAGE=local/image-community-mock:test make image-community-container-scan
```

`make image-community-attestation-verify` is for an authenticated operator or
protected workflow and requires `IMAGE_DIGEST_REFERENCE` and
`GITHUB_REPOSITORY`. It never creates an attestation or credential.

See the [architecture note](../../docs/architecture/image-detector-worker.md),
[model card](../../docs/model-cards/community-forensics.md), and
[Phase 6 Serverless runbook](../../docs/runbooks/runpod-ghcr-private-image.md).
Publication decisions are in
[ADR 0010](../../docs/adr/0010-container-publication-and-attestation.md); the
queue, approval, budget, cache, and final-lock decisions are in
[ADR 0011](../../docs/adr/0011-runpod-serverless-validation.md).
