# Community Forensics image worker

This Phase 4 adapter consumes the shared versioned `DetectorJob`, securely
acquires and verifies one image, performs the pinned Community Forensics
evaluation preprocessing, invokes an injected backend, and returns the shared
`DetectorResult`. Local and CI execution use a deterministic mock. The CUDA
backend and RunPod entry point are present for later validation but are not run
or deployed in Phase 4.

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

The Dockerfile runs as UID/GID 10001, separates `/models` from `/work/tmp`, and
starts the RunPod loop through an explicit entry point. It must later be built
from the repository root so the root `.dockerignore` protects the actual context
and only shared contracts plus worker source are copied. The image is not built
or published by ordinary CI.

See the [architecture note](../../docs/architecture/image-detector-worker.md),
[model card](../../docs/model-cards/community-forensics.md), and
[future GPU runbook](../../docs/runbooks/image-worker-future-gpu.md).
