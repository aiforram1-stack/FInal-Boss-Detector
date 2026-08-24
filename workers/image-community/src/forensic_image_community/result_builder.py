"""Build the shared DetectorResult without adding verdict language."""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from forensic_contracts import DetectorIdentity, DetectorJob, DetectorResult, DetectorRunStatus
from pydantic import JsonValue

from forensic_image_community.contracts import (
    BackendOutput,
    DecodeMetadata,
    PreprocessingRecord,
)
from forensic_image_community.errors import WorkerError, WorkerErrorCode


class ResultBuilder:
    def build(
        self,
        *,
        job: DetectorJob,
        identity: DetectorIdentity,
        input_sha256: str,
        decoder: DecodeMetadata,
        preprocessing: PreprocessingRecord,
        backend_output: BackendOutput,
        stage_durations_ms: dict[str, int],
        total_runtime_ms: int,
        started_at: datetime,
        completed_at: datetime,
    ) -> DetectorResult:
        identity_is_mock = bool(identity.model_extra and identity.model_extra.get("mock_backend"))
        if identity_is_mock != backend_output.mock_backend:
            raise WorkerError(
                WorkerErrorCode.OUTPUT_CONTRACT_INVALID,
                "Backend identity and output mode do not agree.",
            )
        raw_outputs: dict[str, JsonValue] = dict(backend_output.raw_outputs)
        class_mapping: dict[str, JsonValue] = {
            key: value for key, value in backend_output.class_mapping.items()
        }
        raw_outputs.update(
            {
                "class_mapping": class_mapping,
                "upstream_predicted_class": backend_output.upstream_predicted_class,
                "uncalibrated": True,
                "mock_backend": backend_output.mock_backend,
            }
        )
        telemetry: dict[str, object] = {
            "preprocessing_duration_ms": stage_durations_ms.get("preprocessing", 0),
            "inference_duration_ms": backend_output.inference_ms,
            "total_job_duration_ms": total_runtime_ms,
        }
        if backend_output.model_load_ms is not None:
            telemetry["model_load_duration_ms"] = backend_output.model_load_ms
        try:
            return DetectorResult(
                schema_version="1.0",
                result_id=uuid4(),
                run_id=job.run_id,
                job_id=job.job_id,
                case_id=job.case_id,
                evidence_id=job.evidence_id,
                detector=identity,
                status=DetectorRunStatus.SUCCEEDED,
                input_sha256=input_sha256,
                raw_outputs=raw_outputs,
                raw_score=backend_output.raw_logit,
                calibrated_score=None,
                calibration=None,
                preprocessing=preprocessing.model_dump(mode="json"),
                runtime_ms=total_runtime_ms,
                warnings=["Raw logit is uncalibrated and must not be interpreted as a verdict."],
                artifacts=[],
                started_at=started_at,
                completed_at=completed_at,
                decoder=decoder.model_dump(mode="json"),
                preprocessing_sha256=preprocessing.preprocessing_sha256,
                mock_backend=backend_output.mock_backend,
                upstream_repository_commit=identity.repository_commit,
                model_repository_revision=identity.model_revision,
                upstream_predicted_class=backend_output.upstream_predicted_class,
                device_metadata=backend_output.device_metadata,
                determinism=backend_output.determinism,
                telemetry=telemetry,
            )
        except ValueError as exc:
            raise WorkerError(
                WorkerErrorCode.OUTPUT_CONTRACT_INVALID,
                "Detector output did not satisfy the shared result contract.",
                internal_detail=type(exc).__name__,
            ) from exc
