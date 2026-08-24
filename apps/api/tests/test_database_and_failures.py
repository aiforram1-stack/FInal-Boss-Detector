from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from conftest import PNG_A, AppClient, CaseFactory
from fastapi.testclient import TestClient
from forensic_api.db.models import EvidenceAssetRecord
from sqlalchemy.exc import IntegrityError, OperationalError


def test_sqlite_foreign_keys_and_case_blob_uniqueness(
    client: TestClient, app_client: AppClient, create_case: CaseFactory
) -> None:
    app = app_client[1]
    case_id = create_case()["case_id"]
    upload = client.post(
        f"/v1/cases/{case_id}/evidence",
        files={"file": ("generated.png", PNG_A, "image/png")},
    )
    assert upload.status_code == 201
    stored = upload.json()

    with pytest.raises(IntegrityError), app.state.database.sessions.begin() as session:
        session.add(
            EvidenceAssetRecord(
                evidence_id=str(uuid4()),
                schema_version="1.0",
                case_id=str(uuid4()),
                blob_sha256=stored["sha256"],
                original_filename="unknown-case.png",
                client_mime_type="image/png",
                created_at=stored["created_at"],
            )
        )

    with pytest.raises(IntegrityError), app.state.database.sessions.begin() as session:
        session.add(
            EvidenceAssetRecord(
                evidence_id=str(uuid4()),
                schema_version="1.0",
                case_id=case_id,
                blob_sha256=stored["sha256"],
                original_filename="duplicate.png",
                client_mime_type="image/png",
                created_at=stored["created_at"],
            )
        )


def test_database_failure_never_returns_false_success(
    client: TestClient,
    app_client: AppClient,
    create_case: CaseFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = app_client[1]
    case_id = create_case()["case_id"]

    def fail_record(**_: object) -> None:
        raise OperationalError("insert", {}, RuntimeError("simulated"))

    monkeypatch.setattr(app.state.repository, "record_evidence", fail_record)
    response = client.post(
        f"/v1/cases/{case_id}/evidence",
        files={"file": ("generated.png", PNG_A, "image/png")},
    )
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "DATABASE_UNAVAILABLE"
    assert client.get(f"/v1/cases/{case_id}").json()["evidence"] == []
    assert len(app.state.storage.iter_content_hashes()) == 1


def test_failed_post_commit_storage_check_compensates_metadata(
    client: TestClient,
    app_client: AppClient,
    create_case: CaseFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = app_client[1]
    case_id = create_case()["case_id"]
    monkeypatch.setattr(app.state.storage, "contains", lambda *args, **kwargs: False)
    response = client.post(
        f"/v1/cases/{case_id}/evidence",
        files={"file": ("generated.png", PNG_A, "image/png")},
    )
    assert response.status_code == 503
    detail = client.get(f"/v1/cases/{case_id}").json()
    assert detail["evidence"] == []
    assert detail["case"]["status"] == "CREATED"


def test_alembic_upgrade_creates_schema(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    database_path = tmp_path / "migrated.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{database_path}")
    config = Config("alembic.ini")
    command.upgrade(config, "head")
    assert database_path.exists()
