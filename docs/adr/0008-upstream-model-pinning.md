# ADR 0008: Pin upstream code and model without vendoring

- Status: accepted for Phase 4; GPU parity required before production use
- Date: 2026-08-24

## Context

The official Community Forensics constructor creates a timm architecture with
pretrained weights and then loads the final model state. Invoking it unchanged
would request an additional mutable upstream artifact. The worker must not make
an undeclared download, and the final checkpoint already contains the complete
model state.

Five integration options were evaluated:

| Option | Reproducibility and operational consequence |
| --- | --- |
| Vendor source | Reviewable, but duplicates upstream code and raises drift and attribution risk. |
| Git submodule | Immutable when pinned, but complicates checkout and Docker build behavior. |
| Pinned Git dependency | Immutable in a lock, but upstream is not packaged as a stable worker library and may still trigger secondary downloads. |
| Clone exact commit in Docker | Reproducible only with network access during build and adds unused training/evaluation code. |
| Minimal model wrapper | Smallest runtime surface and disables secondary downloads, but requires explicit future parity testing. |

## Decision

Use a project-owned adapter and a minimal attributed model wrapper. It creates
the exact official timm architecture with `pretrained=False`, replaces the head
with the verified one-output linear layer, and strictly loads the complete
safetensors checkpoint. It does not vendor or silently modify upstream source.

Pin and validate these immutable identities:

- source repository `https://github.com/JeongsooP/Community-Forensics` at
  `ee5b71d43db0f3779e1edd64ee927b13f2dd6ad4`;
- model `OwensLab/commfor-model-384` at
  `6076002bf0d9dd37537f965ee2f06f826c333b61`;
- checkpoint `model.safetensors`, 87,262,324 bytes, SHA-256
  `b89f36275f3bf5e2b040eee36597a8f19db051bff9a473a9cf7b2466284fb387`;
- preprocessing repository `OwensLab/commfor-data-preprocessor` at
  `3540a3f0d688f8bf492a8aed48613b891f88047e`;
- Linux AMD64 PyTorch base image by full manifest digest.

The upstream MIT license and notice are retained. Dataset and individual image
rights are separate and are not asserted or exercised by Phase 4.

## Consequences

Builds need no Git clone and ordinary tests need no model. The checkpoint may
only be acquired into an external cache through the double-gated script, which
verifies size and SHA-256. Before production, an authorized GPU test must prove
state loading, preprocessing, output shape, and numeric parity against the
pinned official implementation.
