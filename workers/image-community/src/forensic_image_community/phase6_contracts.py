"""Versioned contracts for controlled Phase 6 Serverless validation jobs."""

from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import UTC, datetime
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator, model_validator

from forensic_image_community.errors import WorkerErrorCode

SHA256_PATTERN = r"^[a-f0-9]{64}$"
COMMIT_PATTERN = r"^[a-f0-9]{40}$"
DIGEST_PATTERN = r"^sha256:[a-f0-9]{64}$"
RUNPOD_JOB_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


class Phase6Record(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
        allow_inf_nan=False,
    )

    schema_version: Literal["1.0"]


class SanitizedWorkerError(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
        allow_inf_nan=False,
    )

    code: WorkerErrorCode
    message: str = Field(min_length=1, max_length=1000)
    retryable: bool


class RunpodWorkerErrorResponse(Phase6Record):
    """Structured failure that avoids RunPod SDK's reserved top-level `error` key."""

    status: Literal["WORKER_ERROR"] = "WORKER_ERROR"
    worker_error: SanitizedWorkerError


class CheckpointBootstrapRequest(Phase6Record):
    operation: Literal["checkpoint_bootstrap"]
    detector_id: Literal["community-forensics-384"]
    expected_model_repository: str = Field(min_length=3, max_length=255)
    expected_model_revision: str = Field(pattern=COMMIT_PATTERN)
    expected_checkpoint_filename: str = Field(pattern=r"^[A-Za-z0-9._-]+$")
    fixture_id: Literal["phase6-generated-fixture"]
    perform_basic_load: Literal[True] = True


class GpuValidationRequest(Phase6Record):
    operation: Literal["gpu_validation"]
    detector_id: Literal["community-forensics-384"]
    expected_model_repository: str = Field(min_length=3, max_length=255)
    expected_model_revision: str = Field(pattern=COMMIT_PATTERN)
    expected_checkpoint_filename: str = Field(pattern=r"^[A-Za-z0-9._-]+$")
    expected_checkpoint_byte_length: int = Field(gt=0)
    expected_checkpoint_sha256: str = Field(pattern=SHA256_PATTERN)
    fixture_id: Literal["phase6-generated-fixture"]
    expected_fixture_sha256: str = Field(pattern=SHA256_PATTERN)
    measured_repetitions: int = Field(default=5, ge=5, le=20)
    parity_absolute_tolerance: float = Field(default=1e-6, gt=0, le=1e-4)


class ReleaseIdentity(Phase6Record):
    project_source_commit: str = Field(pattern=COMMIT_PATTERN)
    container_digest: str = Field(pattern=DIGEST_PATTERN)
    endpoint_release_identity: str = Field(min_length=1, max_length=255)
    detector_id: Literal["community-forensics-384"]
    upstream_repository_commit: str = Field(pattern=COMMIT_PATTERN)
    model_repository: str = Field(min_length=3, max_length=255)
    model_revision: str = Field(pattern=COMMIT_PATTERN)
    checkpoint_sha256: str = Field(pattern=SHA256_PATTERN)


class ArtifactEnvelope(Phase6Record):
    artifact_type: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]+$")
    created_at: datetime
    identity: ReleaseIdentity
    fixture_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    runtime_versions: dict[str, JsonValue]
    status: str = Field(pattern=r"^[A-Z][A-Z0-9_]+$")
    warnings: tuple[str, ...] = ()
    payload: dict[str, JsonValue]
    artifact_sha256: str = Field(pattern=SHA256_PATTERN)

    @field_validator("created_at")
    @classmethod
    def validate_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
            raise ValueError("artifact timestamp must be timezone-aware UTC")
        return value

    @model_validator(mode="after")
    def validate_artifact_hash(self) -> Self:
        unsigned = self.model_dump(mode="json", exclude={"artifact_sha256"})
        if _canonical_sha256(unsigned) != self.artifact_sha256:
            raise ValueError("artifact SHA-256 does not match its canonical content")
        return self


class CheckpointBootstrapResponse(Phase6Record):
    operation: Literal["checkpoint_bootstrap"] = "checkpoint_bootstrap"
    receipt: ArtifactEnvelope

    @model_validator(mode="after")
    def validate_receipt(self) -> Self:
        if self.receipt.artifact_type != "checkpoint_bootstrap_receipt":
            raise ValueError("bootstrap response requires a bootstrap receipt")
        if self.receipt.status != "OBSERVED_BOOTSTRAP_HASH":
            raise ValueError("bootstrap hash must remain explicitly observational")
        payload = self.receipt.payload
        job_id = payload.get("runpod_job_id")
        if not isinstance(job_id, str) or not RUNPOD_JOB_ID_RE.fullmatch(job_id):
            raise ValueError("bootstrap receipt requires a valid RunPod job ID")
        if payload.get("checkpoint_sha256") != self.receipt.identity.checkpoint_sha256:
            raise ValueError("bootstrap checkpoint hash must match the release identity")
        if (
            payload.get("requested_model_revision") != self.receipt.identity.model_revision
            or payload.get("resolved_snapshot_revision") != self.receipt.identity.model_revision
        ):
            raise ValueError("bootstrap model revisions must match the release identity")
        return self


class GpuValidationResponse(Phase6Record):
    operation: Literal["gpu_validation"] = "gpu_validation"
    fitness: ArtifactEnvelope
    upstream_parity: ArtifactEnvelope
    detector_result: ArtifactEnvelope
    performance: ArtifactEnvelope
    repeatability: ArtifactEnvelope
    negative_tests: ArtifactEnvelope
    summary: ArtifactEnvelope

    @model_validator(mode="after")
    def validate_artifact_types(self) -> Self:
        expected = {
            "fitness": "gpu_fitness_result",
            "upstream_parity": "upstream_parity_result",
            "detector_result": "real_detector_result",
            "performance": "performance_result",
            "repeatability": "repeatability_result",
            "negative_tests": "negative_tests_result",
            "summary": "phase6_serverless_validation_summary",
        }
        artifacts = {field_name: getattr(self, field_name) for field_name in expected}
        for field_name, artifact_type in expected.items():
            if artifacts[field_name].artifact_type != artifact_type:
                raise ValueError(f"{field_name} has the wrong artifact type")
        reference = self.fitness
        if reference.fixture_sha256 is None:
            raise ValueError("GPU validation artifacts require the generated fixture hash")
        for field_name, envelope in artifacts.items():
            if envelope.identity != reference.identity:
                raise ValueError(f"{field_name} identity does not match the validation bundle")
            if envelope.fixture_sha256 != reference.fixture_sha256:
                raise ValueError(f"{field_name} fixture hash does not match the validation bundle")
            if envelope.created_at != reference.created_at:
                raise ValueError(f"{field_name} timestamp does not match the validation bundle")
            if envelope.runtime_versions != reference.runtime_versions:
                raise ValueError(f"{field_name} runtime does not match the validation bundle")
            if envelope.status != "PASSED":
                raise ValueError(f"{field_name} is not a passed validation artifact")
        detector_payload = self.detector_result.payload
        raw_score = detector_payload.get("raw_score")
        if (
            not isinstance(raw_score, (int, float))
            or isinstance(raw_score, bool)
            or not math.isfinite(raw_score)
            or detector_payload.get("raw_score_semantics")
            != "uncalibrated_pre_sigmoid_binary_logit"
            or detector_payload.get("calibrated_score") is not None
            or detector_payload.get("calibrator") is not None
            or detector_payload.get("mock_backend") is not False
        ):
            raise ValueError(
                "detector artifact must remain real, uncalibrated, and non-probabilistic"
            )
        fitness_job_id = self.fitness.payload.get("runpod_job_id")
        summary_job_id = self.summary.payload.get("runpod_job_id")
        if (
            not isinstance(fitness_job_id, str)
            or not RUNPOD_JOB_ID_RE.fullmatch(fitness_job_id)
            or summary_job_id != fitness_job_id
        ):
            raise ValueError("GPU validation artifacts require one consistent RunPod job ID")
        summary_payload = self.summary.payload
        if (
            any(
                summary_payload.get(field_name) != "PASSED"
                for field_name in (
                    "cuda_fitness",
                    "official_upstream_parity",
                    "real_inference",
                    "repeatability",
                    "negative_tests",
                )
            )
            or summary_payload.get("downloads_disabled") is not True
        ):
            raise ValueError("GPU validation summary does not describe a passed offline run")
        return self


def _canonical_sha256(value: object) -> str:
    body = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(body).hexdigest()


def build_artifact_envelope(
    *,
    artifact_type: str,
    created_at: datetime,
    identity: ReleaseIdentity,
    fixture_sha256: str | None,
    runtime_versions: dict[str, JsonValue],
    status: str,
    warnings: tuple[str, ...] = (),
    payload: dict[str, JsonValue],
) -> ArtifactEnvelope:
    unsigned = {
        "schema_version": "1.0",
        "artifact_type": artifact_type,
        "created_at": created_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "identity": identity.model_dump(mode="json"),
        "fixture_sha256": fixture_sha256,
        "runtime_versions": runtime_versions,
        "status": status,
        "warnings": list(warnings),
        "payload": payload,
    }
    return ArtifactEnvelope(
        **unsigned,
        artifact_sha256=_canonical_sha256(unsigned),
    )


def utc_now() -> datetime:
    return datetime.now(UTC)
