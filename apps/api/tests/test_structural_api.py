from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from uuid import uuid4

from conftest import PNG_A, AppClient, CaseFactory
from fastapi.testclient import TestClient
from forensic_api.services.structural import ANALYSIS_PROFILE, APPLICATION_VERSION
from forensic_contracts import (
    Case,
    ForensicTestStatus,
    StructuralAnalysisRun,
    StructuralAnalysisStatus,
    StructuralReport,
)


def upload_png(
    client: TestClient, create_case: CaseFactory, *, name: str = "generated.png"
) -> tuple[Case, dict[str, object]]:
    case = Case.model_validate(create_case())
    response = client.post(
        f"/v1/cases/{case.case_id}/evidence",
        files={"file": (name, PNG_A, "image/png")},
    )
    assert response.status_code == 201
    return case, response.json()


def test_start_retrieve_and_report_endpoints_use_shared_contracts(
    client: TestClient, app_client: AppClient, create_case: CaseFactory
) -> None:
    case, evidence = upload_png(client, create_case)
    endpoint = f"/v1/cases/{case.case_id}/evidence/{evidence['evidence_id']}/structural-analysis"
    response = client.post(endpoint)
    assert response.status_code == 201
    run = StructuralAnalysisRun.model_validate(response.json())
    assert run.status == StructuralAnalysisStatus.PARTIAL
    assert run.integrity is not None and run.integrity.status.value == "VERIFIED"
    assert len(run.test_results) == 8
    statuses = {item.test_name: item.status for item in run.test_results}
    assert statuses["structural.file-signature.v1"] == ForensicTestStatus.EXECUTED
    assert statuses["structural.exiftool-metadata.v1"] == ForensicTestStatus.PROVIDER_UNAVAILABLE
    assert statuses["structural.audio-summary.v1"] == ForensicTestStatus.NOT_APPLICABLE
    assert run.report_manifest is not None
    assert {item.format for item in run.report_manifest.artifacts} == {"json", "html"}

    retrieved = client.get(endpoint)
    assert retrieved.status_code == 200
    assert retrieved.json()["schema_version"] == "1.0"
    assert StructuralAnalysisRun.model_validate(retrieved.json()["runs"][0]) == run

    json_response = client.get(f"/v1/cases/{case.case_id}/reports/structural.json")
    assert json_response.status_code == 200
    report = StructuralReport.model_validate(json_response.json())
    assert report.analysis_run_id == run.analysis_run_id
    assert report.evidence.evidence_id == run.evidence_id
    assert len(report.tests) == 8
    assert {item.status for item in report.tool_inventory} >= {
        item.status
        for item in run.summary.common.tool_availability  # type: ignore[union-attr]
    }
    assert all(item.source_test_ids for item in report.consistency_findings)

    html_response = client.get(f"/v1/cases/{case.case_id}/reports/structural.html")
    assert html_response.status_code == 200
    assert "Structural media report" in html_response.text
    assert "<script" not in html_response.text.lower()
    app = app_client[1]
    serialized = response.text + json_response.text + html_response.text
    assert str(app.state.storage.root) not in serialized
    assert str(app.state.result_storage.root) not in serialized
    assert PNG_A not in json_response.content

    location = app.state.repository.latest_structural_report(case.case_id)
    assert location is not None
    assert hashlib.sha256(json_response.content).hexdigest() == location.json_sha256


def test_unknown_case_evidence_cross_case_and_missing_report_are_safe(
    client: TestClient, create_case: CaseFactory
) -> None:
    unknown_case = "00000000-0000-4000-8000-000000000001"
    unknown_evidence = "00000000-0000-4000-8000-000000000002"
    response = client.post(
        f"/v1/cases/{unknown_case}/evidence/{unknown_evidence}/structural-analysis"
    )
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "CASE_NOT_FOUND"

    first, evidence = upload_png(client, create_case)
    second = Case.model_validate(create_case(claim="other"))
    cross_case = client.post(
        f"/v1/cases/{second.case_id}/evidence/{evidence['evidence_id']}/structural-analysis"
    )
    assert cross_case.status_code == 404
    assert cross_case.json()["error"]["code"] == "EVIDENCE_NOT_FOUND"

    missing = client.post(
        f"/v1/cases/{first.case_id}/evidence/{unknown_evidence}/structural-analysis"
    )
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "EVIDENCE_NOT_FOUND"
    no_report = client.get(f"/v1/cases/{first.case_id}/reports/structural.json")
    assert no_report.status_code == 404
    assert no_report.json()["error"]["code"] == "STRUCTURAL_REPORT_NOT_FOUND"


def test_duplicate_active_analysis_is_prevented(
    client: TestClient, app_client: AppClient, create_case: CaseFactory
) -> None:
    case, evidence = upload_png(client, create_case)
    app = app_client[1]
    app.state.repository.create_structural_run(
        run_id=uuid4(),
        case_id=case.case_id,
        evidence_id=evidence["evidence_id"],
        analysis_profile=ANALYSIS_PROFILE,
        input_sha256=evidence["sha256"],
        software_version=APPLICATION_VERSION,
        git_commit=None,
        started_at=datetime.now(UTC),
    )
    response = client.post(
        f"/v1/cases/{case.case_id}/evidence/{evidence['evidence_id']}/structural-analysis"
    )
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "STRUCTURAL_ANALYSIS_ACTIVE"


def test_case_status_becomes_analyzed_after_partial_report(
    client: TestClient, create_case: CaseFactory
) -> None:
    case, evidence = upload_png(client, create_case)
    response = client.post(
        f"/v1/cases/{case.case_id}/evidence/{evidence['evidence_id']}/structural-analysis"
    )
    assert response.status_code == 201
    detail = client.get(f"/v1/cases/{case.case_id}")
    assert detail.json()["case"]["status"] == "ANALYZED"
