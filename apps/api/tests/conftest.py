from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any, Protocol, cast

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from forensic_api.config import Settings
from forensic_api.main import create_app

PNG_A = b"\x89PNG\r\n\x1a\n" + b"A" * 80
PNG_B = b"\x89PNG\r\n\x1a\n" + b"B" * 80
WAV = b"RIFF" + (36).to_bytes(4, "little") + b"WAVEfmt " + b"\x00" * 40
MP4 = b"\x00\x00\x00\x18ftypisom" + b"\x00" * 48

AppClient = tuple[TestClient, FastAPI]


class CaseFactory(Protocol):
    def __call__(self, **overrides: object) -> dict[str, Any]: ...


@pytest.fixture
def app_client(tmp_path: Path) -> Iterator[AppClient]:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'phase2.db'}",
        evidence_storage_root=tmp_path / "evidence",
        max_upload_bytes=256,
        upload_chunk_bytes=16,
        allowed_media_types="image/png,audio/wav,video/mp4",
        log_level="CRITICAL",
    )
    app = create_app(settings, initialize_schema=True)
    with TestClient(app, raise_server_exceptions=False) as client:
        yield client, app


@pytest.fixture
def client(app_client: AppClient) -> TestClient:
    return app_client[0]


@pytest.fixture
def create_case(client: TestClient) -> CaseFactory:
    def create(**overrides: object) -> dict[str, Any]:
        payload: dict[str, object] = {
            "schema_version": "1.0",
            "claim": "Generated Phase 2 test",
            "privacy_mode": "RESTRICTED",
        }
        payload.update(overrides)
        response = client.post("/v1/cases", json=payload)
        assert response.status_code == 201
        return cast(dict[str, Any], response.json())

    return create
