# Future Community Forensics GPU validation

This is a preparation runbook, not authorization to execute. Do not run these
steps, rent a GPU, publish an image, or download weights until the corresponding
phase is explicitly approved.

## Required platform

- Linux AMD64 host with a compatible NVIDIA GPU and driver;
- digest-pinned worker image built from the reviewed commit;
- writable external model cache and temporary work directories;
- sufficient free VRAM for the configured readiness threshold;
- only short-lived least-privilege credentials, injected at runtime;
- outbound network policy restricted to the approved model/object hosts.

## Controlled checkpoint acquisition

Review the dry-run first:

```bash
make image-community-checkpoint-dry-run
```

An authorized operator would then set both download gates and an external
cache. The second generic gate prevents an image-specific environment variable
from enabling downloads by accident:

```bash
export IMAGE_COMMUNITY_ALLOW_MODEL_DOWNLOAD=true
export ALLOW_MODEL_DOWNLOAD=1
export IMAGE_COMMUNITY_MODEL_CACHE=/models/community-forensics
workers/image-community/scripts/fetch_checkpoint.py
```

The script pins the Hugging Face repository and revision, writes atomically,
verifies 87,262,324 bytes and SHA-256
`b89f36275f3bf5e2b040eee36597a8f19db051bff9a473a9cf7b2466284fb387`,
and emits a machine-readable receipt outside Git. A mismatch is terminal.

## Readiness and integration test prerequisites

Set production configuration only after the built image digest is known:

```bash
export IMAGE_COMMUNITY_ENVIRONMENT=production
export IMAGE_COMMUNITY_BACKEND=community
export IMAGE_COMMUNITY_CONTAINER_DIGEST=sha256:REPLACE_WITH_64_HEX_DIGEST
export IMAGE_COMMUNITY_ALLOWED_INPUT_HOSTS=approved-object-host.example
export RUN_GPU_TESTS=1
make image-community-gpu-test
```

The test also independently skips unless CUDA is available and the exact
checkpoint exists and verifies. Readiness must prove mock disablement, checkpoint
identity, CUDA availability, model evaluation mode, free VRAM, controlled probe
success, and `(1,1)` output shape.

## Manual parity review

Before accepting a real result, compare the pinned official implementation and
the minimal wrapper on the same rights-cleared fixture. Confirm identical
preprocessing tensors, strict checkpoint keys, output shape, and numerically
equivalent logits under the same runtime. Record GPU model, CUDA/PyTorch
versions, image digest, checkpoint receipt, preprocessing fingerprint, and any
variance. Do not claim cross-device bitwise determinism.
