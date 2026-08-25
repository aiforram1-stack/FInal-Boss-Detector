"""Thin RunPod-compatible and local command-line handler."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import time
from pathlib import Path
from typing import Any

from forensic_contracts import DetectorJob
from pydantic import ValidationError

from forensic_image_community.config import ImageCommunitySettings
from forensic_image_community.errors import WorkerError, WorkerErrorCode
from forensic_image_community.factory import build_job_service, build_phase6_validation_service
from forensic_image_community.fixture_data import generated_rgb_png
from forensic_image_community.input_fetcher import MemoryInputFetcher
from forensic_image_community.job_service import ImageCommunityJobService
from forensic_image_community.phase6_contracts import (
    CheckpointBootstrapRequest,
    GpuValidationRequest,
)
from forensic_image_community.phase6_validation import Phase6ValidationService

MAX_LOCAL_EVENT_BYTES = 1024 * 1024
_default_handler: WorkerHandler | None = None
_phase6_service: Phase6ValidationService | None = None
RUNPOD_JOB_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
WORKER_PROCESS_STARTED_NS = time.perf_counter_ns()


class WorkerHandler:
    def __init__(self, service: ImageCommunityJobService) -> None:
        self.service = service

    def handle(self, event: object) -> dict[str, object]:
        try:
            if not isinstance(event, dict) or "input" not in event:
                raise WorkerError(
                    WorkerErrorCode.INVALID_JOB,
                    "RunPod event must contain an input object.",
                )
            raw_input = event["input"]
            if not isinstance(raw_input, dict):
                raise WorkerError(WorkerErrorCode.INVALID_JOB, "Job input must be an object.")
            job = DetectorJob.model_validate(raw_input)
            result = self.service.execute(job)
            return {
                "schema_version": "1.0",
                "result": result.model_dump(mode="json"),
            }
        except WorkerError as exc:
            return exc.external_dict()
        except ValidationError:
            return WorkerError(
                WorkerErrorCode.INVALID_JOB,
                "Job input did not satisfy the shared DetectorJob contract.",
            ).external_dict()
        except Exception as exc:
            return WorkerError(
                WorkerErrorCode.INTERNAL_ERROR,
                "Worker encountered an internal error.",
                internal_detail=type(exc).__name__,
            ).external_dict()


def build_ready_handler(
    settings: ImageCommunitySettings,
    *,
    input_fetcher: MemoryInputFetcher | None = None,
) -> WorkerHandler:
    service, fitness = build_job_service(settings, input_fetcher=input_fetcher)
    readiness = fitness.check()
    if not readiness.ready:
        raise WorkerError(
            WorkerErrorCode.WORKER_NOT_READY,
            "Worker did not pass startup readiness checks.",
            internal_detail=readiness.error_code,
        )
    return WorkerHandler(service)


def _safe_runpod_job_id(event: dict[str, Any]) -> str:
    value = event.get("id")
    if value is None:
        raise WorkerError(WorkerErrorCode.INVALID_JOB, "RunPod job identifier is required.")
    if not isinstance(value, str) or not RUNPOD_JOB_ID_RE.fullmatch(value):
        raise WorkerError(WorkerErrorCode.INVALID_JOB, "RunPod job identifier is invalid.")
    return value


def _phase6_handle(event: dict[str, Any], service: Phase6ValidationService) -> dict[str, object]:
    raw_input = event.get("input")
    if not isinstance(raw_input, dict):
        raise WorkerError(WorkerErrorCode.INVALID_JOB, "Job input must be an object.")
    operation = raw_input.get("operation")
    runpod_job_id = _safe_runpod_job_id(event)
    if operation == "checkpoint_bootstrap":
        bootstrap_request = CheckpointBootstrapRequest.model_validate(raw_input)
        return service.checkpoint_bootstrap(
            bootstrap_request,
            runpod_job_id=runpod_job_id,
        ).model_dump(mode="json")
    if operation == "gpu_validation":
        validation_request = GpuValidationRequest.model_validate(raw_input)
        return service.gpu_validation(
            validation_request,
            runpod_job_id=runpod_job_id,
        ).model_dump(mode="json")
    raise WorkerError(WorkerErrorCode.INVALID_JOB, "Phase 6 operation is unsupported.")


def _initialize_phase6_worker(settings: ImageCommunitySettings) -> Phase6ValidationService:
    service = build_phase6_validation_service(settings)
    if settings.checkpoint_bootstrap_mode:
        if not settings.phase6_only_mode:
            raise WorkerError(
                WorkerErrorCode.WORKER_NOT_READY,
                "Phase 6 bootstrap startup requires validation-only mode.",
            )
    else:
        service.assert_startup_ready()
    service.record_worker_initialization_ms(
        max(0, round((time.perf_counter_ns() - WORKER_PROCESS_STARTED_NS) / 1_000_000))
    )
    return service


def runpod_handler(event: dict[str, Any]) -> dict[str, object]:
    global _default_handler, _phase6_service
    try:
        settings = ImageCommunitySettings()
        raw_input = event.get("input")
        if isinstance(raw_input, dict) and raw_input.get("operation") in {
            "checkpoint_bootstrap",
            "gpu_validation",
        }:
            if _phase6_service is None:
                _phase6_service = _initialize_phase6_worker(settings)
            return _phase6_handle(event, _phase6_service)
        if settings.phase6_only_mode:
            raise WorkerError(
                WorkerErrorCode.INVALID_JOB,
                "This endpoint accepts only controlled Phase 6 operations.",
            )
        if _default_handler is None:
            _default_handler = build_ready_handler(settings)
        return _default_handler.handle(event)
    except WorkerError as exc:
        return exc.external_dict()
    except ValidationError:
        return WorkerError(
            WorkerErrorCode.INVALID_JOB,
            "Job input did not satisfy the Phase 6 contract.",
        ).external_dict()
    except Exception as exc:
        return WorkerError(
            WorkerErrorCode.INTERNAL_ERROR,
            "Worker encountered an internal error.",
            internal_detail=type(exc).__name__,
        ).external_dict()


def _read_local_event(path: Path) -> dict[str, object]:
    try:
        if path.stat().st_size > MAX_LOCAL_EVENT_BYTES:
            raise ValueError("event file is too large")
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise WorkerError(
            WorkerErrorCode.INVALID_JOB,
            "Local event file could not be read.",
            internal_detail=type(exc).__name__,
        ) from exc
    if not isinstance(payload, dict):
        raise WorkerError(WorkerErrorCode.INVALID_JOB, "Local event must be an object.")
    return payload


def _local_mock_handler(
    settings: ImageCommunitySettings, event: dict[str, object]
) -> WorkerHandler:
    if settings.backend != "mock":
        return build_ready_handler(settings)
    fixture = generated_rgb_png()
    raw_input = event.get("input")
    if not isinstance(raw_input, dict):
        raise WorkerError(WorkerErrorCode.INVALID_JOB, "Local event must contain input.")
    expected_hash = hashlib.sha256(fixture).hexdigest()
    if (
        raw_input.get("local_fixture_id") != "generated-rgb-png-v1"
        or raw_input.get("expected_sha256") != expected_hash
        or raw_input.get("expected_byte_length") != len(fixture)
    ):
        raise WorkerError(
            WorkerErrorCode.INVALID_JOB,
            "Local mock event does not match the generated fixture manifest.",
        )
    temp_root = settings.ensure_temp_root()
    fetcher = MemoryInputFetcher(
        {str(raw_input.get("download_url")): (fixture, "image/png")}, temp_root
    )
    return build_ready_handler(settings, input_fetcher=fetcher)


def main() -> None:
    parser = argparse.ArgumentParser(description="Community Forensics worker adapter")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--input", type=Path, help="Run one local event from JSON")
    mode.add_argument("--runpod", action="store_true", help="Start the RunPod serverless loop")
    args = parser.parse_args()
    if args.runpod:
        try:
            import runpod  # type: ignore[import-not-found]
        except ImportError as exc:
            raise SystemExit("RunPod dependency is unavailable in this runtime") from exc
        settings = ImageCommunitySettings()
        if settings.environment == "production":
            global _phase6_service
            _phase6_service = _initialize_phase6_worker(settings)
        runpod.serverless.start({"handler": runpod_handler})
        return
    settings = ImageCommunitySettings()
    event = _read_local_event(args.input)
    handler = _local_mock_handler(settings, event)
    print(json.dumps(handler.handle(event), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
