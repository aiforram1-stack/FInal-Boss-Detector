from __future__ import annotations

import hashlib
import io
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from forensic_contracts import DetectorJob
from forensic_image_community.config import ImageCommunitySettings
from forensic_image_community.contracts import FetchedInput
from forensic_image_community.fixture_data import generated_rgb_png
from forensic_image_community.manifest import ModelManifest, load_model_manifest
from PIL import Image

WORKER_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_URL = "https://fixtures.example.invalid/generated.png"


def manifest() -> ModelManifest:
    return load_model_manifest(WORKER_ROOT / "model-manifest.yaml")


def settings(tmp_path: Path, **overrides: object) -> ImageCommunitySettings:
    values: dict[str, object] = {
        "environment": "test",
        "backend": "mock",
        "model_manifest": WORKER_ROOT / "model-manifest.yaml",
        "temp_root": tmp_path / "worker-temp",
        "allowed_input_hosts": frozenset({"objects.example.test"}),
    }
    values.update(overrides)
    return ImageCommunitySettings.model_validate(values)


def detector_job(
    content: bytes | None = None,
    *,
    url: str = FIXTURE_URL,
    mime_type: str = "image/png",
    **overrides: object,
) -> DetectorJob:
    body = content if content is not None else generated_rgb_png()
    values: dict[str, object] = {
        "schema_version": "1.0",
        "job_id": uuid4(),
        "run_id": uuid4(),
        "case_id": uuid4(),
        "evidence_id": uuid4(),
        "requested_detector_name": "community-forensics-384",
        "download_url": url,
        "expected_sha256": hashlib.sha256(body).hexdigest(),
        "expected_byte_length": len(body),
        "expected_mime_type": mime_type,
        "created_at": datetime(2026, 8, 24, 10, 0, tzinfo=UTC),
        "expires_at": datetime(2099, 8, 24, 10, 5, tzinfo=UTC),
        "analysis_profile": "image-community-v1",
        "trace_id": "generated-test-trace",
    }
    values.update(overrides)
    return DetectorJob.model_validate(values)


def generated_image_bytes(
    image_format: str,
    *,
    size: tuple[int, int] = (8, 6),
    mode: str = "RGB",
    exif_orientation: int | None = None,
) -> bytes:
    image = Image.new(mode, size, (20, 80, 160) if mode == "RGB" else 120)
    try:
        output = io.BytesIO()
        kwargs: dict[str, object] = {}
        if exif_orientation is not None:
            exif = Image.Exif()
            exif[274] = exif_orientation
            kwargs["exif"] = exif
        image.save(output, format=image_format, **kwargs)
        return output.getvalue()
    finally:
        image.close()


def fetched_file(
    tmp_path: Path, content: bytes, mime_type: str, *, name: str = "input.part"
) -> FetchedInput:
    path = tmp_path / name
    path.write_bytes(content)
    return FetchedInput(
        path=path,
        sha256=hashlib.sha256(content).hexdigest(),
        byte_length=len(content),
        response_mime_type=mime_type,
    )
