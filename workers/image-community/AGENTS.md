# Community Forensics worker scope

- Phase 4 only. Do not connect this worker to the API or implement Phase 5.
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
