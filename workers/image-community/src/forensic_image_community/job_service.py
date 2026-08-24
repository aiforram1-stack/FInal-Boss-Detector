"""Framework-independent Community Forensics worker job orchestration."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

from forensic_contracts import DetectorJob, DetectorResult

from forensic_image_community.errors import WorkerError, WorkerErrorCode
from forensic_image_community.image_decoder import ImageDecoder
from forensic_image_community.input_fetcher import ALLOWED_MIME_TYPES, InputFetcher
from forensic_image_community.manifest import ModelManifest
from forensic_image_community.model_backend import DetectorBackend
from forensic_image_community.preprocessing import ImagePreprocessor
from forensic_image_community.result_builder import ResultBuilder
from forensic_image_community.telemetry import StageTelemetry


class ImageCommunityJobService:
    def __init__(
        self,
        *,
        manifest: ModelManifest,
        input_fetcher: InputFetcher,
        image_decoder: ImageDecoder,
        preprocessor: ImagePreprocessor,
        backend: DetectorBackend,
        result_builder: ResultBuilder,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.manifest = manifest
        self.input_fetcher = input_fetcher
        self.image_decoder = image_decoder
        self.preprocessor = preprocessor
        self.backend = backend
        self.result_builder = result_builder
        self.now = now or (lambda: datetime.now(UTC))

    def _validate_job_policy(self, job: DetectorJob, current_time: datetime) -> None:
        if job.created_at > current_time:
            raise WorkerError(WorkerErrorCode.INVALID_JOB, "Detector job is not yet valid.")
        if current_time >= job.expires_at:
            raise WorkerError(WorkerErrorCode.INVALID_JOB, "Detector job has expired.")
        if job.download_url.scheme != "https":
            raise WorkerError(
                WorkerErrorCode.INPUT_HOST_REJECTED,
                "Only approved HTTPS input references are supported.",
            )
        if job.requested_detector_name != self.manifest.detector.detector_id:
            raise WorkerError(
                WorkerErrorCode.INVALID_JOB,
                "Detector job requested a different detector.",
            )
        if job.expected_mime_type not in ALLOWED_MIME_TYPES:
            raise WorkerError(
                WorkerErrorCode.UNSUPPORTED_MIME_TYPE,
                "Input MIME type is not supported by this worker.",
            )
        extras = job.model_extra or {}
        profile = extras.get("analysis_profile", "image-community-v1")
        if profile != "image-community-v1":
            raise WorkerError(WorkerErrorCode.INVALID_JOB, "Analysis profile is not supported.")

    def execute(self, job: DetectorJob) -> DetectorResult:
        started_at = self.now()
        self._validate_job_policy(job, started_at)
        telemetry = StageTelemetry()
        fetched = None
        decoded = None
        try:
            with telemetry.stage("fetch"):
                fetched = self.input_fetcher.fetch(job)
            if fetched.sha256 != job.expected_sha256:
                raise WorkerError(
                    WorkerErrorCode.INPUT_HASH_MISMATCH,
                    "Verified input hash does not match the detector job.",
                )
            with telemetry.stage("decode"):
                decoded = self.image_decoder.decode(
                    fetched, expected_mime_type=job.expected_mime_type
                )
            with telemetry.stage("preprocessing"):
                preprocessed = self.preprocessor.preprocess(decoded)
            with telemetry.stage("inference"):
                backend_output = self.backend.infer(preprocessed)
            completed_at = self.now()
            total_ms = telemetry.total_ms()
            return self.result_builder.build(
                job=job,
                identity=self.backend.identity(),
                input_sha256=fetched.sha256,
                decoder=decoded.metadata,
                preprocessing=preprocessed.record,
                backend_output=backend_output,
                stage_durations_ms=telemetry.durations_ms,
                total_runtime_ms=total_ms,
                started_at=started_at,
                completed_at=completed_at,
            )
        finally:
            if decoded is not None:
                decoded.close()
            if fetched is not None:
                fetched.cleanup()
