from __future__ import annotations

import json
from pathlib import Path

from forensic_contracts import DetectorResult
from forensic_image_community.errors import WorkerError, WorkerErrorCode
from forensic_image_community.factory import build_job_service
from forensic_image_community.fixture_data import generated_rgb_png
from forensic_image_community.handler import WorkerHandler, build_ready_handler
from forensic_image_community.input_fetcher import MemoryInputFetcher
from helpers import FIXTURE_URL, detector_job, settings


def ready_handler(tmp_path: Path) -> tuple[WorkerHandler, Path]:
    configured = settings(tmp_path)
    temp_root = configured.ensure_temp_root()
    fixture = generated_rgb_png()
    handler = build_ready_handler(
        configured,
        input_fetcher=MemoryInputFetcher({FIXTURE_URL: (fixture, "image/png")}, temp_root),
    )
    return handler, temp_root


def test_complete_mock_job_returns_shared_result_and_removes_temporary_input(
    tmp_path: Path,
) -> None:
    handler, temp_root = ready_handler(tmp_path)
    job = detector_job()
    response = handler.handle({"input": job.model_dump(mode="json")})
    result = DetectorResult.model_validate(response["result"])
    assert response["schema_version"] == "1.0"
    assert result.run_id == job.run_id
    assert result.case_id == job.case_id
    assert result.evidence_id == job.evidence_id
    assert result.input_sha256 == job.expected_sha256
    assert result.raw_score is not None
    assert result.calibrated_score is None
    assert result.calibration is None
    assert result.detector.detector_name == "community-forensics-384-mock"
    assert result.preprocessing["preprocessing_sha256"]
    assert result.runtime_ms >= 0
    assert result.model_extra is not None
    assert result.model_extra["mock_backend"] is True
    assert result.model_extra["upstream_repository_commit"] == result.detector.repository_commit
    assert result.model_extra["telemetry"]["total_job_duration_ms"] >= 0
    assert list(temp_root.iterdir()) == []


def test_mock_result_json_round_trip_and_language_policy(tmp_path: Path) -> None:
    handler, _ = ready_handler(tmp_path)
    response = handler.handle({"input": detector_job().model_dump(mode="json")})
    result = DetectorResult.model_validate(response["result"])
    restored = DetectorResult.model_validate_json(result.model_dump_json())
    assert restored == result
    serialized = json.dumps(response).lower()
    for prohibited in (
        "ai probability",
        "certainty",
        "forensic confidence",
        "verified fake",
        "definitely synthetic",
    ):
        assert prohibited not in serialized
    assert "raw_logit" in serialized
    assert "uncalibrated" in serialized


def test_handler_rejects_malformed_missing_and_invalid_input(tmp_path: Path) -> None:
    handler, _ = ready_handler(tmp_path)
    for event in (
        None,
        {},
        {"input": []},
        {"input": {"schema_version": "1.0", "job_id": "not-a-uuid"}},
    ):
        response = handler.handle(event)
        assert response["schema_version"] == "1.0"
        assert response["error"]["code"] == "INVALID_JOB"
        assert "traceback" not in json.dumps(response).lower()


def test_inference_exception_becomes_structured_failure_and_cleans_input(
    tmp_path: Path,
) -> None:
    configured = settings(tmp_path)
    temp_root = configured.ensure_temp_root()
    fixture = generated_rgb_png()
    service, _ = build_job_service(
        configured,
        input_fetcher=MemoryInputFetcher({FIXTURE_URL: (fixture, "image/png")}, temp_root),
    )

    def fail_inference(_: object) -> None:
        raise WorkerError(WorkerErrorCode.INFERENCE_FAILED, "Controlled inference failure.")

    service.backend.infer = fail_inference  # type: ignore[method-assign,assignment]
    response = WorkerHandler(service).handle({"input": detector_job().model_dump(mode="json")})
    assert response["error"]["code"] == "INFERENCE_FAILED"
    assert response["error"]["retryable"] is False
    assert list(temp_root.iterdir()) == []


def test_job_policy_rejects_expired_wrong_detector_profile_and_scheme(tmp_path: Path) -> None:
    handler, _ = ready_handler(tmp_path)
    jobs = (
        detector_job(expires_at="2026-08-24T10:00:01Z"),
        detector_job(created_at="2099-08-24T10:01:00Z"),
        detector_job(requested_detector_name="other-detector"),
        detector_job(analysis_profile="unsupported-profile"),
        detector_job(url="http://fixtures.example.invalid/generated.png"),
    )
    expected = (
        "INVALID_JOB",
        "INVALID_JOB",
        "INVALID_JOB",
        "INVALID_JOB",
        "INPUT_HOST_REJECTED",
    )
    for job, code in zip(jobs, expected, strict=True):
        response = handler.handle({"input": job.model_dump(mode="json")})
        assert response["error"]["code"] == code
