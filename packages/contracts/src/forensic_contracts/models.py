"""Pydantic v2 contracts shared by future platform components.

The models accept and preserve unknown fields to prevent an older reader from
discarding data written by a compatible newer producer. Current code must never
act on unknown fields without a schema-aware upgrade.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Annotated, Self
from uuid import UUID

from pydantic import (
    AfterValidator,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
    JsonValue,
    field_validator,
    model_validator,
)

SCHEMA_VERSION_PATTERN = r"^1\.[0-9]+$"
SHA256_PATTERN = r"^[a-f0-9]{64}$"
SHA512_PATTERN = r"^[a-f0-9]{128}$"
COMMIT_PATTERN = r"^[a-f0-9]{40}$"
CONTAINER_DIGEST_PATTERN = r"^sha256:[a-f0-9]{64}$"

Sha256 = Annotated[str, Field(pattern=SHA256_PATTERN)]
Sha512 = Annotated[str, Field(pattern=SHA512_PATTERN)]


def _require_utc(value: datetime) -> datetime:
    if value.utcoffset() != timedelta(0):
        raise ValueError("timestamp must be timezone-aware UTC")
    return value.astimezone(UTC)


UtcDateTime = Annotated[AwareDatetime, AfterValidator(_require_utc)]


class VersionedContract(BaseModel):
    """Immutable versioned record with lossless compatible-field round trips."""

    model_config = ConfigDict(
        extra="allow",
        frozen=True,
        str_strip_whitespace=True,
        validate_default=True,
    )

    schema_version: str = Field(pattern=SCHEMA_VERSION_PATTERN)


class CaseStatus(StrEnum):
    CREATED = "CREATED"
    UPLOADING = "UPLOADING"
    SEALED = "SEALED"
    SUBMITTED = "SUBMITTED"
    RUNNING = "RUNNING"
    ANALYZED = "ANALYZED"
    REVIEWED = "REVIEWED"
    FAILED = "FAILED"


class PrivacyMode(StrEnum):
    STANDARD = "STANDARD"
    RESTRICTED = "RESTRICTED"


class DetectorRunStatus(StrEnum):
    PENDING = "PENDING"
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    CANCELLED = "CANCELLED"


class ForensicTestStatus(StrEnum):
    EXECUTED = "EXECUTED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNSUPPORTED_INPUT = "UNSUPPORTED_INPUT"
    FAILED = "FAILED"
    PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"
    SKIPPED_BY_PRIVACY_POLICY = "SKIPPED_BY_PRIVACY_POLICY"
    REQUIRES_MANUAL_REVIEW = "REQUIRES_MANUAL_REVIEW"


class StructuralAnalysisStatus(StrEnum):
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    REFUSED = "REFUSED"
    FAILED = "FAILED"


class IntegrityStatus(StrEnum):
    VERIFIED = "VERIFIED"
    OBJECT_MISSING = "OBJECT_MISSING"
    HASH_MISMATCH = "HASH_MISMATCH"
    SIZE_MISMATCH = "SIZE_MISMATCH"


class ToolAvailabilityStatus(StrEnum):
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"


class FindingSeverity(StrEnum):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


class Case(VersionedContract):
    case_id: UUID
    created_at: UtcDateTime
    status: CaseStatus
    claim: str | None = Field(default=None, max_length=4000)
    privacy_mode: PrivacyMode = PrivacyMode.RESTRICTED


class EvidenceAsset(VersionedContract):
    evidence_id: UUID
    case_id: UUID
    filename: str = Field(min_length=1, max_length=255)
    byte_length: int = Field(ge=0)
    mime_type: str = Field(min_length=1, max_length=127)
    sha256: Sha256
    sha512: Sha512
    storage_uri: str = Field(min_length=1, max_length=2048)
    object_version: str = Field(min_length=1, max_length=255)
    created_at: UtcDateTime


class EvidenceDerivative(VersionedContract):
    derivative_id: UUID
    case_id: UUID
    parent_evidence_id: UUID
    parent_sha256: Sha256
    filename: str = Field(min_length=1, max_length=255)
    byte_length: int = Field(ge=0)
    mime_type: str = Field(min_length=1, max_length=127)
    output_sha256: Sha256
    output_sha512: Sha512
    storage_uri: str = Field(min_length=1, max_length=2048)
    transformation_tool: str = Field(min_length=1, max_length=255)
    tool_version: str = Field(min_length=1, max_length=255)
    exact_parameters: dict[str, JsonValue] = Field(default_factory=dict)
    lossy: bool
    created_at: UtcDateTime

    @field_validator("tool_version")
    @classmethod
    def reject_mutable_tool_version(cls, value: str) -> str:
        if value.lower() in {"latest", "main", "master"}:
            raise ValueError("tool_version must be immutable")
        return value


class DetectorIdentity(VersionedContract):
    detector_name: str = Field(min_length=1, max_length=255)
    detector_version: str = Field(min_length=1, max_length=255)
    repository_url: HttpUrl
    repository_commit: str = Field(pattern=COMMIT_PATTERN)
    container_digest: str = Field(pattern=CONTAINER_DIGEST_PATTERN)
    model_revision: str = Field(min_length=1, max_length=255)
    checkpoint_sha256: Sha256

    @field_validator("model_revision", "detector_version")
    @classmethod
    def reject_mutable_identity(cls, value: str) -> str:
        if value.lower() in {"latest", "main", "master"}:
            raise ValueError("detector and model versions must be immutable")
        return value


class CalibrationMetadata(VersionedContract):
    calibrator_name: str = Field(min_length=1, max_length=255)
    calibrator_version: str = Field(min_length=1, max_length=255)
    method: str = Field(min_length=1, max_length=255)
    calibration_dataset_revision: str = Field(min_length=1, max_length=255)
    applicability: dict[str, JsonValue] = Field(default_factory=dict)

    @field_validator("calibrator_version", "calibration_dataset_revision")
    @classmethod
    def reject_mutable_calibrator_identity(cls, value: str) -> str:
        if value.lower() in {"latest", "main", "master"}:
            raise ValueError("calibrator metadata must use immutable revisions")
        return value


class ArtifactReference(VersionedContract):
    artifact_id: UUID
    kind: str = Field(min_length=1, max_length=100)
    storage_uri: str = Field(min_length=1, max_length=2048)
    sha256: Sha256
    byte_length: int = Field(ge=0)
    mime_type: str = Field(min_length=1, max_length=127)
    parent_sha256: Sha256
    transformation_tool: str = Field(min_length=1, max_length=255)
    tool_version: str = Field(min_length=1, max_length=255)
    exact_parameters: dict[str, JsonValue] = Field(default_factory=dict)
    lossy: bool


class DetectorJob(VersionedContract):
    job_id: UUID
    run_id: UUID
    case_id: UUID
    evidence_id: UUID
    requested_detector_name: str = Field(min_length=1, max_length=255)
    download_url: HttpUrl
    expected_sha256: Sha256
    expected_byte_length: int = Field(ge=0)
    expected_mime_type: str = Field(min_length=1, max_length=127)
    created_at: UtcDateTime
    expires_at: UtcDateTime

    @model_validator(mode="after")
    def validate_expiration(self) -> Self:
        if self.expires_at <= self.created_at:
            raise ValueError("expires_at must be later than created_at")
        return self


class DetectorRun(VersionedContract):
    run_id: UUID
    case_id: UUID
    evidence_id: UUID
    detector: DetectorIdentity
    status: DetectorRunStatus
    input_sha256: Sha256
    external_job_id: str | None = Field(default=None, max_length=255)
    created_at: UtcDateTime
    started_at: UtcDateTime | None = None
    completed_at: UtcDateTime | None = None
    error_code: str | None = Field(default=None, max_length=255)
    error_message: str | None = Field(default=None, max_length=2000)

    @model_validator(mode="after")
    def validate_lifecycle(self) -> Self:
        if self.started_at and self.started_at < self.created_at:
            raise ValueError("started_at cannot precede created_at")
        if self.completed_at and self.started_at and self.completed_at < self.started_at:
            raise ValueError("completed_at cannot precede started_at")
        terminal = {
            DetectorRunStatus.SUCCEEDED,
            DetectorRunStatus.FAILED,
            DetectorRunStatus.TIMED_OUT,
            DetectorRunStatus.CANCELLED,
        }
        if self.status in terminal and self.completed_at is None:
            raise ValueError("terminal detector runs require completed_at")
        return self


class DetectorResult(VersionedContract):
    result_id: UUID
    run_id: UUID
    case_id: UUID
    evidence_id: UUID
    detector: DetectorIdentity
    status: DetectorRunStatus
    input_sha256: Sha256
    raw_outputs: dict[str, JsonValue] = Field(default_factory=dict)
    raw_score: float | None = None
    calibrated_score: float | None = Field(default=None, ge=0.0, le=1.0)
    calibration: CalibrationMetadata | None = None
    preprocessing: dict[str, JsonValue]
    runtime_ms: int = Field(ge=0)
    warnings: list[str] = Field(default_factory=list)
    artifacts: list[ArtifactReference] = Field(default_factory=list)
    started_at: UtcDateTime
    completed_at: UtcDateTime

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        if self.completed_at < self.started_at:
            raise ValueError("completed_at cannot precede started_at")
        terminal = {
            DetectorRunStatus.SUCCEEDED,
            DetectorRunStatus.FAILED,
            DetectorRunStatus.TIMED_OUT,
            DetectorRunStatus.CANCELLED,
        }
        if self.status not in terminal:
            raise ValueError("a detector result must have a terminal status")
        if self.status == DetectorRunStatus.SUCCEEDED and self.raw_score is None:
            raise ValueError("a successful detector result requires raw_score")
        if (self.calibrated_score is None) != (self.calibration is None):
            raise ValueError("calibrated_score and calibration metadata must appear together")
        return self


class ForensicTestResult(VersionedContract):
    test_result_id: UUID
    case_id: UUID
    evidence_id: UUID
    test_name: str = Field(min_length=1, max_length=255)
    test_version: str = Field(min_length=1, max_length=255)
    status: ForensicTestStatus
    status_reason: str | None = Field(default=None, max_length=2000)
    raw_outputs: dict[str, JsonValue] = Field(default_factory=dict)
    findings: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    artifacts: list[ArtifactReference] = Field(default_factory=list)
    runtime_ms: int | None = Field(default=None, ge=0)
    started_at: UtcDateTime | None = None
    completed_at: UtcDateTime | None = None

    @model_validator(mode="after")
    def validate_execution_record(self) -> Self:
        if self.status == ForensicTestStatus.EXECUTED:
            if self.started_at is None or self.completed_at is None or self.runtime_ms is None:
                raise ValueError("executed tests require timestamps and runtime_ms")
        elif not self.status_reason:
            raise ValueError("non-executed tests require status_reason")
        if self.started_at and self.completed_at and self.completed_at < self.started_at:
            raise ValueError("completed_at cannot precede started_at")
        return self


class ReportEvidenceReference(VersionedContract):
    evidence_id: UUID
    sha256: Sha256
    sha512: Sha512


class ReportArtifact(VersionedContract):
    format: str = Field(pattern=r"^(json|html|markdown)$")
    storage_uri: str = Field(min_length=1, max_length=2048)
    sha256: Sha256
    byte_length: int = Field(ge=0)


class TestCoverageEntry(VersionedContract):
    test_name: str = Field(min_length=1, max_length=255)
    status: ForensicTestStatus
    test_result_id: UUID | None = None


class ReportManifest(VersionedContract):
    report_id: UUID
    case_id: UUID
    generated_at: UtcDateTime
    generator_name: str = Field(min_length=1, max_length=255)
    generator_version: str = Field(min_length=1, max_length=255)
    generator_repository_commit: str = Field(pattern=COMMIT_PATTERN)
    evidence: list[ReportEvidenceReference] = Field(min_length=1)
    detector_result_ids: list[UUID] = Field(default_factory=list)
    forensic_test_result_ids: list[UUID] = Field(default_factory=list)
    test_coverage: list[TestCoverageEntry] = Field(default_factory=list)
    artifacts: list[ReportArtifact] = Field(min_length=1)


class StructuralTestDefinition(VersionedContract):
    test_id: str = Field(pattern=r"^structural\.[a-z0-9-]+\.v[0-9]+$")
    test_version: str = Field(min_length=1, max_length=32)
    description: str = Field(min_length=1, max_length=1000)
    applicable_mime_categories: list[str] = Field(min_length=1)
    required_tool: str | None = Field(default=None, max_length=255)
    timeout_seconds: float = Field(gt=0, le=3600)
    expected_output_type: str = Field(min_length=1, max_length=255)
    known_limitations: list[str] = Field(default_factory=list)


class ToolInventoryEntry(VersionedContract):
    tool_name: str = Field(min_length=1, max_length=255)
    status: ToolAvailabilityStatus
    version: str | None = Field(default=None, max_length=500)
    required_by_test_ids: list[str] = Field(default_factory=list)
    status_reason: str | None = Field(default=None, max_length=1000)

    @model_validator(mode="after")
    def validate_availability(self) -> Self:
        if self.status == ToolAvailabilityStatus.AVAILABLE and not self.version:
            raise ValueError("available tools require a version")
        if self.status == ToolAvailabilityStatus.UNAVAILABLE and not self.status_reason:
            raise ValueError("unavailable tools require a status_reason")
        return self


class IntegrityVerification(VersionedContract):
    evidence_id: UUID
    expected_sha256: Sha256
    verified_sha256: Sha256 | None = None
    expected_sha512: Sha512
    verified_sha512: Sha512 | None = None
    expected_byte_length: int = Field(ge=0)
    verified_byte_length: int | None = Field(default=None, ge=0)
    status: IntegrityStatus
    started_at: UtcDateTime
    completed_at: UtcDateTime
    status_reason: str | None = Field(default=None, max_length=1000)

    @model_validator(mode="after")
    def validate_integrity(self) -> Self:
        if self.completed_at < self.started_at:
            raise ValueError("completed_at cannot precede started_at")
        if self.status == IntegrityStatus.VERIFIED:
            expected = (self.expected_sha256, self.expected_sha512, self.expected_byte_length)
            verified = (self.verified_sha256, self.verified_sha512, self.verified_byte_length)
            if expected != verified:
                raise ValueError("verified integrity values must match expected values")
        elif not self.status_reason:
            raise ValueError("integrity failures require a status_reason")
        return self


class StructuralCommonSummary(VersionedContract):
    original_filename: str = Field(min_length=1, max_length=255)
    detected_mime_type: str = Field(min_length=1, max_length=127)
    client_mime_type: str | None = Field(default=None, max_length=127)
    byte_length: int = Field(ge=0)
    sha256: Sha256
    sha512: Sha512
    storage_uri: str = Field(min_length=1, max_length=2048)
    extension_signature_consistent: bool | None = None
    tool_availability: list[ToolInventoryEntry]
    analysis_started_at: UtcDateTime
    analysis_completed_at: UtcDateTime
    warnings: list[str] = Field(default_factory=list)


class ImageStructuralSummary(VersionedContract):
    format: str | None = None
    width: int | None = Field(default=None, ge=0)
    height: int | None = Field(default=None, ge=0)
    orientation: str | None = None
    color_space: str | None = None
    bit_depth: int | None = Field(default=None, ge=0)
    alpha_channel: bool | None = None
    icc_profile: bool | None = None
    exif_present: bool | None = None
    camera_make: str | None = None
    camera_model: str | None = None
    capture_timestamp: str | None = None
    gps_present: bool | None = None
    editing_software: str | None = None
    embedded_thumbnail: bool | None = None
    compression: dict[str, JsonValue] = Field(default_factory=dict)


class AudioStructuralSummary(VersionedContract):
    container: str | None = None
    codec: str | None = None
    duration_seconds: float | None = Field(default=None, ge=0)
    bit_rate: int | None = Field(default=None, ge=0)
    sample_rate: int | None = Field(default=None, ge=0)
    bit_depth: int | None = Field(default=None, ge=0)
    channel_count: int | None = Field(default=None, ge=0)
    channel_layout: str | None = None
    encoder: str | None = None
    metadata_tags: dict[str, JsonValue] = Field(default_factory=dict)
    start_time_seconds: float | None = None
    audio_stream_count: int = Field(default=0, ge=0)


class VideoStructuralSummary(VersionedContract):
    container: str | None = None
    duration_seconds: float | None = Field(default=None, ge=0)
    file_bit_rate: int | None = Field(default=None, ge=0)
    video_stream_count: int = Field(default=0, ge=0)
    audio_stream_count: int = Field(default=0, ge=0)
    subtitle_stream_count: int = Field(default=0, ge=0)
    video_codec: str | None = None
    codec_profile: str | None = None
    width: int | None = Field(default=None, ge=0)
    height: int | None = Field(default=None, ge=0)
    pixel_format: str | None = None
    nominal_frame_rate: str | None = None
    average_frame_rate: str | None = None
    time_base: str | None = None
    color_primaries: str | None = None
    transfer_characteristics: str | None = None
    audio_codecs: list[str] = Field(default_factory=list)
    audio_sample_rates: list[int] = Field(default_factory=list)
    channel_layouts: list[str] = Field(default_factory=list)
    encoder_tags: dict[str, JsonValue] = Field(default_factory=dict)
    start_time_differences: list[float] = Field(default_factory=list)


class StructuralSummary(VersionedContract):
    common: StructuralCommonSummary
    image: ImageStructuralSummary | None = None
    audio: AudioStructuralSummary | None = None
    video: VideoStructuralSummary | None = None
    metadata: dict[str, JsonValue] = Field(default_factory=dict)
    streams: list[dict[str, JsonValue]] = Field(default_factory=list)


class ConsistencyFinding(VersionedContract):
    finding_id: str = Field(pattern=r"^structural\.finding\.[a-z0-9-]+\.v[0-9]+$")
    severity: FindingSeverity
    description: str = Field(min_length=1, max_length=2000)
    compared_fields: list[str] = Field(min_length=1)
    observed_values: dict[str, JsonValue]
    tool_sources: list[str] = Field(min_length=1)
    source_test_ids: list[str] = Field(min_length=1)
    limitations: list[str] = Field(default_factory=list)

    @field_validator("description")
    @classmethod
    def reject_verdict_language(cls, value: str) -> str:
        upper = value.upper()
        prohibited = {"FAKE", "MANIPULATED", "AI_GENERATED"}
        if any(term in upper for term in prohibited):
            raise ValueError("structural findings cannot contain verdict language")
        return value


class StructuralSoftwareIdentity(VersionedContract):
    application_version: str = Field(min_length=1, max_length=255)
    git_commit: str | None = Field(default=None, pattern=COMMIT_PATTERN)


class StructuralReportCase(VersionedContract):
    case_id: UUID
    status: CaseStatus
    privacy_mode: PrivacyMode
    claim: str | None = Field(default=None, max_length=4000)


class StructuralReportEvidence(VersionedContract):
    evidence_id: UUID
    filename: str = Field(min_length=1, max_length=255)
    mime_type: str = Field(min_length=1, max_length=127)
    client_mime_type: str | None = Field(default=None, max_length=127)
    byte_length: int = Field(ge=0)
    sha256: Sha256
    sha512: Sha512
    storage_uri: str = Field(min_length=1, max_length=2048)


class StructuralReport(VersionedContract):
    report_id: UUID
    analysis_run_id: UUID
    case: StructuralReportCase
    evidence: StructuralReportEvidence
    integrity: IntegrityVerification
    tool_inventory: list[ToolInventoryEntry]
    tests: list[ForensicTestResult]
    structural_summary: StructuralSummary
    consistency_findings: list[ConsistencyFinding]
    warnings: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    generated_at: UtcDateTime
    software: StructuralSoftwareIdentity


class StructuralAnalysisRun(VersionedContract):
    analysis_run_id: UUID
    case_id: UUID
    evidence_id: UUID
    analysis_profile: str = Field(min_length=1, max_length=255)
    status: StructuralAnalysisStatus
    input_sha256: Sha256
    started_at: UtcDateTime
    completed_at: UtcDateTime | None = None
    integrity: IntegrityVerification | None = None
    test_results: list[ForensicTestResult] = Field(default_factory=list)
    summary: StructuralSummary | None = None
    consistency_findings: list[ConsistencyFinding] = Field(default_factory=list)
    report_manifest: ReportManifest | None = None

    @model_validator(mode="after")
    def validate_analysis_lifecycle(self) -> Self:
        if self.status == StructuralAnalysisStatus.RUNNING and self.completed_at is not None:
            raise ValueError("running analyses cannot have completed_at")
        if self.status != StructuralAnalysisStatus.RUNNING and self.completed_at is None:
            raise ValueError("terminal analyses require completed_at")
        if self.completed_at is not None and self.completed_at < self.started_at:
            raise ValueError("completed_at cannot precede started_at")
        if self.status == StructuralAnalysisStatus.COMPLETED and self.report_manifest is None:
            raise ValueError("completed analyses require a report manifest")
        return self
