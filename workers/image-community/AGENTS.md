# Community Forensics worker scope

- Phase 6 only. Prepare and validate the existing worker for one controlled,
  queue-based RunPod Serverless endpoint. Do not connect it to the main API,
  create a Pod or network volume, add a detector, train a model, or begin
  Phase 7.
- Local and ordinary CI commands remain CPU-only. A real checkpoint and CUDA
  may be used only inside an explicitly cost-approved RunPod Serverless job.
- Before the exact approval phrase `APPROVE PHASE 6 SERVERLESS COST`, only
  repository work and read-only RunPod/GitHub checks are allowed.
- Ordinary local and CI commands must use the mock backend and must not perform
  real network requests, import CUDA libraries, or download model weights.
- Treat URLs and media as hostile. Fetch only HTTPS from exact configured
  hosts, reject unsafe resolved addresses, bound bytes/time/redirects, verify
  SHA-256 and length before decode, and never expose signed URLs.
- Decode only JPEG, PNG and WebP with bounded dimensions, pixels and estimated
  decoded memory. Close every file/image and remove every temporary file.
- The real backend must verify the safetensors checkpoint before loading, run
  only with CUDA in production, load once per process, use evaluation and
  inference modes, and return the raw upstream logit.
- Never describe a score as a probability, confidence, certainty, proof or
  verdict. Calibration fields remain null in Phase 4.
- Mock identity and results must be unmistakable and cannot pass production
  readiness.
- Do not use mutable source, model, dependency, container or checkpoint
  references. Preserve the upstream MIT notice.
- Do not add media, weights, cache files, receipts, credentials or user evidence
  to Git.
- Pull-request workflows are read-only and cannot publish. Protected
  publication uses the repository `GITHUB_TOKEN`, a full source-SHA tag, and the
  returned digest as authoritative identity. RunPod must use that digest, never
  a moving deployment tag.
- Both `mock-test` and `gpu-runtime` targets use the same contracts and job
  service. Neither target may contain a checkpoint; the mock smoke fixture must
  be generated in memory.
- `checkpoint_bootstrap` may observe and report a cached checkpoint hash but
  must not label it final production verification. `gpu_validation` must fail
  closed until the checked-in manifest records an observed bootstrap hash and
  must combine fitness, upstream parity, inference, repeatability,
  performance, and negative tests in one paid job.
