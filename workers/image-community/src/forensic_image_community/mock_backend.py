"""Deterministic local backend with an unmistakably synthetic identity."""

from __future__ import annotations

import hashlib

from forensic_contracts import DetectorIdentity

from forensic_image_community.contracts import BackendOutput, PreprocessedImage

MOCK_REPOSITORY_COMMIT = hashlib.sha1(b"community-forensics-mock-source").hexdigest()  # noqa: S324
MOCK_CHECKPOINT_SHA256 = hashlib.sha256(b"community-forensics-mock-checkpoint").hexdigest()
MOCK_CONTAINER_DIGEST = (
    "sha256:" + hashlib.sha256(b"community-forensics-mock-container").hexdigest()
)


class MockCommunityBackend:
    @property
    def mock_backend(self) -> bool:
        return True

    def identity(self) -> DetectorIdentity:
        return DetectorIdentity(
            schema_version="1.0",
            detector_name="community-forensics-384-mock",
            detector_version="mock-1.0.0",
            repository_url="https://example.invalid/community-forensics-mock",
            repository_commit=MOCK_REPOSITORY_COMMIT,
            container_digest=MOCK_CONTAINER_DIGEST,
            model_revision="mock-community-forensics-384-v1",
            checkpoint_sha256=MOCK_CHECKPOINT_SHA256,
            mock_backend=True,
        )

    def infer(self, preprocessed: PreprocessedImage) -> BackendOutput:
        digest = hashlib.sha256(preprocessed.tensor.tobytes(order="C")).digest()
        unit_value = int.from_bytes(digest[:8], "big") / float(2**64 - 1)
        raw_logit = round((unit_value * 8.0) - 4.0, 8)
        predicted = "fake" if raw_logit >= 0 else "real"
        return BackendOutput(
            raw_logit=raw_logit,
            raw_outputs={
                "raw_logit": raw_logit,
                "output_shape": [1, 1],
                "mock_backend": True,
                "score_semantics": "deterministic_mock_logit",
            },
            class_mapping={"0": "real", "1": "fake"},
            upstream_predicted_class=predicted,
            mock_backend=True,
            device_metadata={"device_type": "cpu", "runtime": "mock"},
            determinism={
                "random_seed": 0,
                "algorithm": "sha256-derived deterministic mock logit",
                "precision": "float64-derived mock scalar",
                "device_type": "cpu",
            },
            model_load_ms=0,
            inference_ms=0,
        )
