from __future__ import annotations

import hashlib

import pytest
from conftest import MP4, PNG_A, PNG_B, WAV, AppClient, CaseFactory
from fastapi.testclient import TestClient
from forensic_contracts import Case, EvidenceAsset


@pytest.mark.parametrize(
    ("name", "declared", "content", "detected"),
    [
        ("generated.png", "text/plain", PNG_A, "image/png"),
        ("generated.wav", "application/octet-stream", WAV, "audio/wav"),
        ("generated.mp4", "image/jpeg", MP4, "video/mp4"),
    ],
)
def test_upload_detects_bytes_hashes_and_returns_shared_contract(
    client: TestClient,
    create_case: CaseFactory,
    name: str,
    declared: str,
    content: bytes,
    detected: str,
) -> None:
    case = Case.model_validate(create_case())
    response = client.post(
        f"/v1/cases/{case.case_id}/evidence",
        files={"file": (name, content, declared)},
    )
    assert response.status_code == 201
    evidence = EvidenceAsset.model_validate(response.json())
    assert evidence.case_id == case.case_id
    assert evidence.filename == name
    assert evidence.mime_type == detected
    assert evidence.byte_length == len(content)
    assert evidence.sha256 == hashlib.sha256(content).hexdigest()
    assert evidence.sha512 == hashlib.sha512(content).hexdigest()
    assert evidence.storage_uri == f"local-sha256://{evidence.sha256}"
    assert response.headers["X-Content-Deduplicated"] == "false"

    metadata = client.get(f"/v1/cases/{case.case_id}/evidence/{evidence.evidence_id}")
    assert metadata.status_code == 200
    assert EvidenceAsset.model_validate(metadata.json()) == evidence
    detail = client.get(f"/v1/cases/{case.case_id}").json()
    assert detail["case"]["status"] == "SEALED"
    assert detail["evidence"] == [response.json()]


def test_same_content_deduplicates_within_and_across_cases(
    client: TestClient, create_case: CaseFactory
) -> None:
    first_case = Case.model_validate(create_case(claim="one"))
    second_case = Case.model_validate(create_case(claim="two"))
    first = client.post(
        f"/v1/cases/{first_case.case_id}/evidence",
        files={"file": ("first.png", PNG_A, "image/png")},
    )
    repeated = client.post(
        f"/v1/cases/{first_case.case_id}/evidence",
        files={"file": ("../ignored-name.png", PNG_A, "image/png")},
    )
    cross_case = client.post(
        f"/v1/cases/{second_case.case_id}/evidence",
        files={"file": ("/absolute/name.png", PNG_A, "image/png")},
    )

    assert first.status_code == 201
    assert repeated.status_code == 200
    assert repeated.json() == first.json()
    assert repeated.headers["X-Evidence-Association-Reused"] == "true"
    assert repeated.headers["X-Content-Deduplicated"] == "true"
    assert cross_case.status_code == 201
    assert cross_case.headers["X-Content-Deduplicated"] == "true"
    assert cross_case.json()["evidence_id"] != first.json()["evidence_id"]
    assert cross_case.json()["filename"] == "/absolute/name.png"
    assert cross_case.json()["sha256"] == first.json()["sha256"]


def test_same_filename_with_different_bytes_is_distinct(
    client: TestClient, create_case: CaseFactory
) -> None:
    case_id = create_case()["case_id"]
    first = client.post(
        f"/v1/cases/{case_id}/evidence",
        files={"file": ("same.png", PNG_A, "image/png")},
    )
    second = client.post(
        f"/v1/cases/{case_id}/evidence",
        files={"file": ("same.png", PNG_B, "image/png")},
    )
    assert first.status_code == second.status_code == 201
    assert first.json()["sha256"] != second.json()["sha256"]
    assert first.json()["evidence_id"] != second.json()["evidence_id"]


@pytest.mark.parametrize(
    ("content", "expected_status", "expected_code"),
    [
        (b"", 400, "EMPTY_EVIDENCE"),
        (b"not supported media", 415, "UNSUPPORTED_MEDIA_TYPE"),
        (b"\x89PNG\r\n\x1a\n" + b"X" * 300, 413, "UPLOAD_TOO_LARGE"),
    ],
)
def test_rejected_uploads_are_structured_and_leave_no_staging_file(
    client: TestClient,
    app_client: AppClient,
    create_case: CaseFactory,
    content: bytes,
    expected_status: int,
    expected_code: str,
) -> None:
    case_id = create_case()["case_id"]
    response = client.post(
        f"/v1/cases/{case_id}/evidence",
        files={"file": ("untrusted.bin", content, "application/octet-stream")},
    )
    assert response.status_code == expected_status
    assert response.json()["error"]["code"] == expected_code
    app = app_client[1]
    assert list(app.state.storage.staging_root.iterdir()) == []
    assert client.get(f"/v1/cases/{case_id}").json()["evidence"] == []


def test_malformed_multipart_is_structured(client: TestClient, create_case: CaseFactory) -> None:
    case_id = create_case()["case_id"]
    response = client.post(
        f"/v1/cases/{case_id}/evidence",
        content=b"not multipart",
        headers={"Content-Type": "multipart/form-data; boundary=missing"},
    )
    assert response.status_code in {400, 422}
    assert response.json()["schema_version"] == "1.0"
    assert "error" in response.json()
