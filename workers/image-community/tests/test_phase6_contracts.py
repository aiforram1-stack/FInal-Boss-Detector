from __future__ import annotations

from datetime import UTC, datetime

import pytest
from forensic_image_community.phase6_contracts import (
    ArtifactEnvelope,
    CheckpointBootstrapRequest,
    CheckpointBootstrapResponse,
    GpuValidationResponse,
    ReleaseIdentity,
    build_artifact_envelope,
)
from pydantic import ValidationError


def identity() -> ReleaseIdentity:
    return ReleaseIdentity(
        schema_version="1.0",
        project_source_commit="a" * 40,
        container_digest=f"sha256:{'b' * 64}",
        endpoint_release_identity="phase6-bootstrap-r1",
        detector_id="community-forensics-384",
        upstream_repository_commit="c" * 40,
        model_repository="OwensLab/commfor-model-384",
        model_revision="d" * 40,
        checkpoint_sha256="e" * 64,
    )


def artifact(artifact_type: str, payload: dict[str, object]) -> ArtifactEnvelope:
    return build_artifact_envelope(
        artifact_type=artifact_type,
        created_at=datetime(2026, 8, 24, 12, 0, tzinfo=UTC),
        identity=identity(),
        fixture_sha256="f" * 64,
        runtime_versions={"python_version": "3.11"},
        status="PASSED",
        payload=payload,  # type: ignore[arg-type]
    )


def test_artifact_round_trip_validates_canonical_hash() -> None:
    original = artifact("performance_result", {"warm_inference_mean_ms": 12.5})
    restored = ArtifactEnvelope.model_validate_json(original.model_dump_json())
    assert restored == original
    changed = original.model_dump(mode="json")
    changed["status"] = "FAILED"
    with pytest.raises(ValidationError, match="artifact SHA-256"):
        ArtifactEnvelope.model_validate(changed)


def test_artifact_rejects_naive_or_non_utc_timestamp() -> None:
    values = artifact("performance_result", {"passed": True}).model_dump(mode="python")
    values["created_at"] = datetime(2026, 8, 24, 12, 0)
    with pytest.raises(ValidationError, match="timezone-aware UTC"):
        ArtifactEnvelope.model_validate(values)


def test_gpu_bundle_rejects_calibrated_or_mock_result_metadata() -> None:
    fields = {
        "schema_version": "1.0",
        "fitness": artifact(
            "gpu_fitness_result", {"runpod_job_id": "validation-job-1", "passed": True}
        ),
        "upstream_parity": artifact("upstream_parity_result", {"passed": True}),
        "detector_result": artifact(
            "real_detector_result",
            {
                "raw_score": 0.25,
                "raw_score_semantics": "uncalibrated_pre_sigmoid_binary_logit",
                "calibrated_score": None,
                "calibrator": None,
                "mock_backend": False,
            },
        ),
        "performance": artifact("performance_result", {"passed": True}),
        "repeatability": artifact("repeatability_result", {"passed": True}),
        "negative_tests": artifact("negative_tests_result", {"passed": True}),
        "summary": artifact(
            "phase6_serverless_validation_summary",
            {
                "runpod_job_id": "validation-job-1",
                "cuda_fitness": "PASSED",
                "official_upstream_parity": "PASSED",
                "real_inference": "PASSED",
                "repeatability": "PASSED",
                "negative_tests": "PASSED",
                "downloads_disabled": True,
            },
        ),
    }
    assert GpuValidationResponse.model_validate(fields).detector_result.payload["raw_score"] == 0.25

    mismatched_identity = identity().model_copy(update={"container_digest": f"sha256:{'0' * 64}"})
    fields["performance"] = build_artifact_envelope(
        artifact_type="performance_result",
        created_at=datetime(2026, 8, 24, 12, 0, tzinfo=UTC),
        identity=mismatched_identity,
        fixture_sha256="f" * 64,
        runtime_versions={"python_version": "3.11"},
        status="PASSED",
        payload={"passed": True},
    )
    with pytest.raises(ValidationError, match="identity does not match"):
        GpuValidationResponse.model_validate(fields)
    fields["performance"] = artifact("performance_result", {"passed": True})

    fields["detector_result"] = artifact(
        "real_detector_result",
        {
            "raw_score": 0.25,
            "raw_score_semantics": "uncalibrated_pre_sigmoid_binary_logit",
            "calibrated_score": 0.8,
            "calibrator": "unreviewed",
            "mock_backend": True,
        },
    )
    with pytest.raises(ValidationError, match="uncalibrated"):
        GpuValidationResponse.model_validate(fields)


def test_bootstrap_receipt_requires_job_and_consistent_observed_identity() -> None:
    receipt = build_artifact_envelope(
        artifact_type="checkpoint_bootstrap_receipt",
        created_at=datetime(2026, 8, 24, 12, 0, tzinfo=UTC),
        identity=identity(),
        fixture_sha256="f" * 64,
        runtime_versions={"python_version": "3.11"},
        status="OBSERVED_BOOTSTRAP_HASH",
        payload={
            "checkpoint_sha256": "e" * 64,
            "requested_model_revision": "d" * 40,
            "resolved_snapshot_revision": "d" * 40,
        },
    )
    with pytest.raises(ValidationError, match="valid RunPod job ID"):
        CheckpointBootstrapResponse(schema_version="1.0", receipt=receipt)


def test_phase6_json_schemas_are_strict_and_versioned() -> None:
    schema = GpuValidationResponse.model_json_schema()
    assert schema["additionalProperties"] is False
    assert "schema_version" in schema["properties"]
    assert "artifact_sha256" in str(schema)


def test_bootstrap_requires_basic_model_load() -> None:
    with pytest.raises(ValidationError):
        CheckpointBootstrapRequest.model_validate(
            {
                "schema_version": "1.0",
                "operation": "checkpoint_bootstrap",
                "detector_id": "community-forensics-384",
                "expected_model_repository": "OwensLab/commfor-model-384",
                "expected_model_revision": "d" * 40,
                "expected_checkpoint_filename": "model.safetensors",
                "fixture_id": "phase6-generated-fixture",
                "perform_basic_load": False,
            }
        )
