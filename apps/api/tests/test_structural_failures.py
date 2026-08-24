from __future__ import annotations

from pathlib import Path

import pytest
from conftest import PNG_A, AppClient, CaseFactory
from fastapi.testclient import TestClient
from forensic_contracts import ForensicTestStatus, StructuralAnalysisRun
from forensic_structural.adapters import AdapterResult


def upload(client: TestClient, create_case: CaseFactory) -> tuple[str, dict[str, object]]:
    case_id = create_case()["case_id"]
    response = client.post(
        f"/v1/cases/{case_id}/evidence",
        files={"file": ("generated.png", PNG_A, "image/png")},
    )
    assert response.status_code == 201
    return case_id, response.json()


@pytest.mark.parametrize("failure_mode", ["tampered", "missing"])
def test_integrity_failure_is_persisted_and_analysis_refused(
    client: TestClient,
    app_client: AppClient,
    create_case: CaseFactory,
    failure_mode: str,
) -> None:
    case_id, evidence = upload(client, create_case)
    app = app_client[1]
    path: Path = app.state.storage.path_for_sha256(evidence["sha256"])
    if failure_mode == "tampered":
        path.chmod(0o600)
        path.write_bytes(b"X" * len(PNG_A))
        path.chmod(0o444)
        changed = path.read_bytes()
    else:
        path.unlink()
        changed = None
    endpoint = f"/v1/cases/{case_id}/evidence/{evidence['evidence_id']}/structural-analysis"
    response = client.post(endpoint)
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "EVIDENCE_INTEGRITY_FAILURE"

    runs = client.get(endpoint)
    assert runs.status_code == 200
    run = StructuralAnalysisRun.model_validate(runs.json()["runs"][0])
    assert run.status.value == "REFUSED"
    assert run.test_results[0].status == ForensicTestStatus.FAILED
    assert run.report_manifest is None
    if changed is not None:
        assert path.read_bytes() == changed


def test_tool_failure_still_produces_partial_report(
    client: TestClient,
    app_client: AppClient,
    create_case: CaseFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case_id, evidence = upload(client, create_case)
    engine = app_client[1].state.structural_service.engine
    ffprobe = engine.tool_adapters["structural.ffprobe-container.v1"]
    monkeypatch.setattr(
        ffprobe,
        "execute",
        lambda _: AdapterResult(
            status=ForensicTestStatus.FAILED,
            status_reason="Controlled parser failure.",
            error_code="CONTROLLED_FAILURE",
        ),
    )
    response = client.post(
        f"/v1/cases/{case_id}/evidence/{evidence['evidence_id']}/structural-analysis"
    )
    assert response.status_code == 201
    run = StructuralAnalysisRun.model_validate(response.json())
    assert run.status.value == "PARTIAL"
    result = next(
        item for item in run.test_results if item.test_name == "structural.ffprobe-container.v1"
    )
    assert result.status == ForensicTestStatus.FAILED
    report = client.get(f"/v1/cases/{case_id}/reports/structural.json")
    assert report.status_code == 200
    assert "CONTROLLED_FAILURE" in report.text


def test_disabled_analysis_is_explicit(
    client: TestClient,
    app_client: AppClient,
    create_case: CaseFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case_id, evidence = upload(client, create_case)
    monkeypatch.setattr(app_client[1].state.structural_service, "enabled", False)
    response = client.post(
        f"/v1/cases/{case_id}/evidence/{evidence['evidence_id']}/structural-analysis"
    )
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "STRUCTURAL_ANALYSIS_DISABLED"
