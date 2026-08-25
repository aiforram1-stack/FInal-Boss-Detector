# Model card: Community Forensics 384 adapter

## Summary

Community Forensics is a research detector trained to distinguish synthetic
from real images using data from many image generators. Phase 4 adds an adapter
for its 384-pixel checkpoint because the official project publishes source,
evaluation behavior, weights, and licensing that can be pinned and reviewed.

> A detector output is supporting evidence and is not proof that an image is synthetic or authentic.

The adapter does not establish authorship, editing history, intent, provenance,
or ground truth. It does not generate a final case verdict.

## Immutable identity

- official source: `https://github.com/JeongsooP/Community-Forensics`
- source commit: `ee5b71d43db0f3779e1edd64ee927b13f2dd6ad4`
- source license: MIT
- model: `OwensLab/commfor-model-384`
- model revision: `6076002bf0d9dd37537f965ee2f06f826c333b61`
- checkpoint: `model.safetensors` in safetensors format
- checkpoint size: 87,262,324 bytes
- checkpoint SHA-256: `b89f36275f3bf5e2b040eee36597a8f19db051bff9a473a9cf7b2466284fb387`
- preprocessor revision: `3540a3f0d688f8bf492a8aed48613b891f88047e`

The checkpoint digest is the verified Hugging Face Git LFS object identifier.
The Phase 4 Mac did not download or independently hash the checkpoint bytes; a
future cost-approved bootstrap job must resolve the pinned RunPod cache snapshot,
calculate the bytes independently, and record an `OBSERVED_BOOTSTRAP_HASH`
receipt before final GPU validation.

Phase 6 preparation adds no weight download or CUDA claim. Bootstrap mode is
observational. Normal validation fails closed until the observed hash status is
checked into the manifest and a new immutable container digest is published.

The first approved Serverless bootstrap attempt on 2026-08-25 failed closed
before CUDA or model loading because the cached checkpoint was not backed by
the model-local blob path required by the pre-repair resolver. The endpoint was
immediately locked at zero workers. The repair adds bounded support for
RunPod's documented snapshot-local regular-file representation while retaining
exact snapshot containment, single-checkpoint, byte-length, SHA-256, and
bounded safetensors verification. The next receipt must identify the observed
layout rather than infer it from the original failure.

## Inputs and preprocessing

The worker accepts JPEG, PNG, and WebP after independent byte-signature and
bounded Pillow validation. EXIF orientation is applied, metadata is discarded,
and the decoded output is RGB.

The pinned evaluation transform resizes the shorter edge to 440 with Pillow
bilinear antialiasing and preserved aspect ratio, center-crops to 384 by 384,
scales RGB values to float32 `[0,1]`, normalizes by mean
`[0.485,0.456,0.406]` and standard deviation `[0.229,0.224,0.225]`, and adds an
NCHW batch dimension. The result records every parameter and a deterministic
preprocessing SHA-256.

## Outputs

The model produces tensor shape `[batch,1]`: one pre-sigmoid binary
classification logit per image. The official mapping is real `0`, fake `1`.
The adapter records the raw logit, the mapping, and the upstream thresholded
class separately. The score is uncalibrated. It is not an AI probability,
certainty, forensic confidence, or authenticity finding. Calibrated score and
calibrator identity are null.

## Limitations and model risk

- Benchmark performance is not evidence of performance on a particular case,
  generator family, image domain, compression level, or post-processing path.
- Training data composition can create unknown domain and demographic biases.
- Related detectors may have correlated errors; agreement is not independence.
- A real image may be classified as fake and a generated image as real.
- The minimal model wrapper needs authorized GPU parity validation against the
  pinned official implementation.
- The upstream repository does not declare a minimum Python version; this
  worker selects Python 3.11.
- The upstream repository does not declare a minimum CUDA version; the future
  image selects a digest-pinned CUDA 12.6.3/PyTorch 2.7.1 runtime.
- No checkpoint loading or GPU inference has yet been performed by this project.
- The detector is not connected to reports or API orchestration in Phase 6.
- One generated-fixture parity run will not establish calibration, general
  detector accuracy, production throughput, or cross-GPU determinism.

## License and data

The official source/model notice is MIT and is retained under the worker
licenses directory. Dataset and source-image licenses are distinct; Phase 4
does not download, redistribute, or train on the Community Forensics dataset.
