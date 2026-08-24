from __future__ import annotations

from datetime import datetime

from conftest import CaseFactory
from fastapi.testclient import TestClient
from forensic_contracts import Case, CaseStatus, PrivacyMode


def test_create_and_retrieve_case_uses_shared_contract(
    client: TestClient, create_case: CaseFactory
) -> None:
    created_payload = create_case()
    created = Case.model_validate(created_payload)
    assert created.status is CaseStatus.CREATED
    assert created.privacy_mode is PrivacyMode.RESTRICTED
    assert created.created_at.utcoffset() is not None
    assert datetime.fromisoformat(created_payload["created_at"]).utcoffset() is not None

    response = client.get(f"/v1/cases/{created.case_id}")
    assert response.status_code == 200
    assert Case.model_validate(response.json()["case"]) == created
    assert response.json()["evidence"] == []


def test_unknown_case_and_invalid_uuid_are_structured(client: TestClient) -> None:
    response = client.get("/v1/cases/00000000-0000-4000-8000-000000000001")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "CASE_NOT_FOUND"
    assert response.json()["schema_version"] == "1.0"

    invalid = client.get("/v1/cases/not-a-uuid")
    assert invalid.status_code == 422
    assert invalid.json()["error"]["code"] == "VALIDATION_ERROR"


def test_invalid_privacy_mode_is_rejected(client: TestClient) -> None:
    response = client.post("/v1/cases", json={"claim": "test", "privacy_mode": "LOCAL_ONLY"})
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"
