# Run the image worker locally in mock mode

This runbook is the only Phase 4 execution path on a Mac. It uses a tiny image
generated in memory, performs no network call, and cannot load model weights.

## Setup and checks

```bash
make setup
make image-community-manifest-check
make image-community-checkpoint-dry-run
make image-community-lint
make image-community-typecheck
make image-community-test
make image-community-docker-lint
```

The dry-run prints the immutable repository, revision, filename, expected byte
length, expected SHA-256, and external cache path. It does not import the model
client or create a checkpoint.

Run the generated-fixture event:

```bash
make image-community-mock
```

The response must validate as shared `DetectorResult`, identify
`community-forensics-mock`, set `mock_backend` to true, leave calibrated score
metadata null, and record a deterministic raw score. The raw score is test data,
not Community Forensics output.

## Safe configuration defaults

- `IMAGE_COMMUNITY_BACKEND=mock`
- `IMAGE_COMMUNITY_ENVIRONMENT=local`
- `IMAGE_COMMUNITY_ALLOW_MODEL_DOWNLOAD=false`
- `IMAGE_COMMUNITY_ALLOW_REDIRECTS=false`
- `IMAGE_COMMUNITY_ALLOWED_INPUT_HOSTS` empty
- bounded byte, dimension, pixel, decoded-memory, chunk, and timeout values

Never put secrets in `.env`, attach real evidence to the fixture event, or
change the local Make target to enable the real backend. Mac CUDA execution is
outside this phase.
