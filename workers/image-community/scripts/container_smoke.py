#!/usr/bin/env python3
"""Run the normal worker path against a generated in-memory fixture."""

from __future__ import annotations

import hashlib
import json
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

from forensic_contracts import DetectorJob, DetectorResult
from forensic_image_community.config import ImageCommunitySettings
from forensic_image_community.fixture_data import generated_rgb_png
from forensic_image_community.handler import build_ready_handler
from forensic_image_community.input_fetcher import MemoryInputFetcher

FIXTURE_URL = "https://fixtures.example.invalid/generated-rgb-png-v1"
PROHIBITED_LANGUAGE = (
    "ai probability",
    "certainty",
    "forensic confidence",
    "verified fake",
    "definitely synthetic",
    "authenticity verdict",
)


def run_smoke(temp_root: Path) -> dict[str, object]:
    fixture = generated_rgb_png()
    now = datetime.now(UTC)
    job = DetectorJob(
        schema_version="1.0",
        job_id=UUID("00000000-0000-4000-8000-000000000501"),
        run_id=UUID("00000000-0000-4000-8000-000000000502"),
        case_id=UUID("00000000-0000-4000-8000-000000000503"),
        evidence_id=UUID("00000000-0000-4000-8000-000000000504"),
        requested_detector_name="community-forensics-384",
        download_url=FIXTURE_URL,
        expected_sha256=hashlib.sha256(fixture).hexdigest(),
        expected_byte_length=len(fixture),
        expected_mime_type="image/png",
        created_at=now,
        expires_at=now + timedelta(minutes=5),
        analysis_profile="image-community-v1",
        trace_id="generated-container-smoke",
        local_fixture_id="generated-rgb-png-v1",
    )
    settings = ImageCommunitySettings(
        environment="test",
        backend="mock",
        allow_model_download=False,
        require_cuda=False,
        temp_root=temp_root,
    )
    if settings.allow_model_download or settings.require_cuda:
        raise RuntimeError("mock smoke safety settings were not applied")
    fetcher = MemoryInputFetcher({FIXTURE_URL: (fixture, "image/png")}, temp_root)
    response = build_ready_handler(settings, input_fetcher=fetcher).handle(
        {"input": job.model_dump(mode="json")}
    )
    if "error" in response:
        raise RuntimeError("mock container smoke returned a structured worker error")
    result_data = response.get("result")
    result = DetectorResult.model_validate(result_data)
    if result.input_sha256 != job.expected_sha256:
        raise RuntimeError("mock container smoke did not preserve the input hash")
    if not result.detector.detector_name.endswith("-mock"):
        raise RuntimeError("mock container smoke identity is not unmistakably mock")
    if result.calibrated_score is not None or result.calibration is not None:
        raise RuntimeError("mock container smoke unexpectedly reported calibration")
    if not result.preprocessing.get("preprocessing_sha256"):
        raise RuntimeError("mock container smoke omitted the preprocessing fingerprint")
    if any(temp_root.iterdir()):
        raise RuntimeError("mock container smoke left temporary worker files behind")
    serialized = json.dumps(response, sort_keys=True).lower()
    if any(term in serialized for term in PROHIBITED_LANGUAGE):
        raise RuntimeError("mock container smoke emitted prohibited verdict language")
    if "/users/" in serialized or "/home/" in serialized or "/work/tmp" in serialized:
        raise RuntimeError("mock container smoke leaked an internal path")
    return response


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="image-community-smoke-") as directory:
        response = run_smoke(Path(directory))
    print(json.dumps(response, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
