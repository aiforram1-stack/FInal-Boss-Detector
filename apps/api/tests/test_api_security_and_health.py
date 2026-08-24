from __future__ import annotations

from pathlib import Path

import pytest
from conftest import PNG_A, AppClient, CaseFactory
from fastapi.testclient import TestClient
from forensic_contracts import Case


def test_openapi_has_only_metadata_and_intake_paths(client: TestClient) -> None:
    document = client.get("/openapi.json")
    assert document.status_code == 200
    paths = document.json()["paths"]
    assert "/v1/cases/{case_id}/evidence/{evidence_id}" in paths
    assert paths["/v1/cases/{case_id}/evidence/{evidence_id}"].keys() == {"get"}
    assert not any("download" in path for path in paths)


def test_responses_do_not_expose_physical_storage_path(
    client: TestClient, app_client: AppClient, create_case: CaseFactory
) -> None:
    app = app_client[1]
    case = Case.model_validate(create_case())
    upload = client.post(
        f"/v1/cases/{case.case_id}/evidence",
        files={"file": ("../../private/generated.png", PNG_A, "image/png")},
    )
    assert upload.status_code == 201
    serialized = upload.text + client.get(f"/v1/cases/{case.case_id}").text
    assert str(app.state.storage.root) not in serialized
    assert upload.json()["filename"] == "../../private/generated.png"
    assert upload.json()["storage_uri"].startswith("local-sha256://")
    assert len(app.state.storage.iter_content_hashes()) == 1


def test_health_healthy_and_dependency_failure_is_path_safe(
    client: TestClient, app_client: AppClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = app_client[1]
    healthy = client.get("/health")
    assert healthy.status_code == 200
    assert healthy.json()["status"] == "healthy"

    monkeypatch.setattr(app.state.storage, "healthcheck", lambda: False)
    degraded = client.get("/health")
    assert degraded.status_code == 503
    assert degraded.json() == {
        "schema_version": "1.0",
        "status": "degraded",
        "dependencies": {"database": "healthy", "storage": "unavailable"},
    }
    assert str(app.state.storage.root) not in degraded.text


def test_tests_use_only_temporary_storage(app_client: AppClient) -> None:
    app = app_client[1]
    root = Path(app.state.storage.root)
    assert "pytest-" in str(root)
    assert root.name == "evidence"
