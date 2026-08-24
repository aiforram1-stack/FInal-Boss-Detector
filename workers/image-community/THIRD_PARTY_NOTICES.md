# Third-party notices

## Community Forensics

- Project: Community Forensics: Using Thousands of Generators to Train Fake
  Image Detectors
- Authors: Jeongsoo Park and Andrew Owens
- Source: https://github.com/JeongsooP/Community-Forensics
- Source commit: `ee5b71d43db0f3779e1edd64ee927b13f2dd6ad4`
- Model: https://huggingface.co/OwensLab/commfor-model-384
- Model revision: `6076002bf0d9dd37537f965ee2f06f826c333b61`
- Preprocessor: https://huggingface.co/OwensLab/commfor-data-preprocessor
- Preprocessor revision: `3540a3f0d688f8bf492a8aed48613b891f88047e`
- License: MIT; the full notice is retained in
  `licenses/Community-Forensics-LICENSE`.

This repository does not vendor the upstream implementation, model weights or
training dataset. It implements a minimal attributed wrapper around the pinned
architecture because the upstream constructor requests separate mutable timm
pretraining weights before loading the complete final safetensors state. The
wrapper disables that unrelated download, retains the exact architecture and
evaluation transform, and must pass a future GPU parity check before use.

The Community Forensics dataset and the licenses of individual source images
are separate from the code/model MIT notice. Phase 4 neither downloads,
redistributes nor trains on that dataset.

## PyTorch container

- Image: `pytorch/pytorch:2.7.1-cuda12.6-cudnn9-runtime`
- Linux AMD64 digest:
  `sha256:2b59b1b91885677814f78be1f8df48a25d5dc952eb6580eaecfefca510f9afd3`
- Project: https://pytorch.org/

Its bundled dependencies retain their own notices and licenses in the image.

The root project does not currently declare a repository-wide open-source
license. The OCI image therefore uses `LicenseRef-Proprietary`; this does not
alter or replace the retained MIT terms for Community Forensics.
