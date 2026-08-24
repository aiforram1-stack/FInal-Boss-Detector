import json
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from forensic_contracts import (
    CalibrationMetadata,
    Case,
    CaseStatus,
    DetectorIdentity,
    DetectorJob,
    DetectorResult,
    DetectorRun,
    DetectorRunStatus,
    EvidenceAsset,
    EvidenceDerivative,
    ForensicTestResult,
    ForensicTestStatus,
    PrivacyMode,
    ReportArtifact,
    ReportEvidenceReference,
    ReportManifest,
)
from forensic_contracts import (
    TestCoverageEntry as CoverageEntry,
)
from pydantic import ValidationError

from scripts.generate_schemas import SCHEMA_DIR, generate_schema_documents

ROOT = Path(__file__).resolve().parents[3]
SHA256 = "a" * 64
SHA512 = "b" * 128
NOW = datetime(2026, 8, 24, 10, 0, tzinfo=UTC)


def detector_identity_data() -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "detector_name": "synthetic-example-detector",
        "detector_version": "1.0.0",
        "repository_url": "https://example.invalid/synthetic-detector",
        "repository_commit": "c" * 40,
        "container_digest": f"sha256:{'d' * 64}",
        "model_revision": "synthetic-revision-1",
        "checkpoint_sha256": "e" * 64,
    }


def detector_result_data() -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "result_id": str(uuid4()),
        "run_id": str(uuid4()),
        "case_id": str(uuid4()),
        "evidence_id": str(uuid4()),
        "detector": detector_identity_data(),
        "status": "SUCCEEDED",
        "input_sha256": SHA256,
        "raw_outputs": {"logit": 1.7432},
        "raw_score": 1.7432,
        "calibrated_score": None,
        "calibration": None,
        "preprocessing": {"decoder": "synthetic", "input_size": 384},
        "runtime_ms": 842,
        "warnings": ["Raw score is uncalibrated."],
        "artifacts": [],
        "started_at": NOW,
        "completed_at": NOW + timedelta(milliseconds=842),
    }


def evidence_data() -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "evidence_id": str(uuid4()),
        "case_id": str(uuid4()),
        "filename": "synthetic.txt",
        "byte_length": 42,
        "mime_type": "application/octet-stream",
        "sha256": SHA256,
        "sha512": SHA512,
        "storage_uri": f"evidence://sha256/{SHA256}",
        "object_version": SHA256,
        "created_at": NOW,
    }


def test_all_required_root_contracts_can_be_created() -> None:
    case_id = uuid4()
    evidence_id = uuid4()
    run_id = uuid4()
    detector = DetectorIdentity.model_validate(detector_identity_data())
    case = Case(
        schema_version="1.0",
        case_id=case_id,
        created_at=NOW,
        status=CaseStatus.SEALED,
        claim=None,
        privacy_mode=PrivacyMode.RESTRICTED,
    )
    evidence = EvidenceAsset(**(evidence_data() | {"case_id": case_id, "evidence_id": evidence_id}))
    derivative = EvidenceDerivative(
        schema_version="1.0",
        derivative_id=uuid4(),
        case_id=case_id,
        parent_evidence_id=evidence_id,
        parent_sha256=evidence.sha256,
        filename="synthetic-preview.png",
        byte_length=123,
        mime_type="image/png",
        output_sha256="f" * 64,
        output_sha512="1" * 128,
        storage_uri="artifact://synthetic-preview",
        transformation_tool="synthetic-transformer",
        tool_version="1.2.3",
        exact_parameters={"width": 384, "mode": "fit"},
        lossy=False,
        created_at=NOW,
    )
    job = DetectorJob(
        schema_version="1.0",
        job_id=uuid4(),
        run_id=run_id,
        case_id=case_id,
        evidence_id=evidence_id,
        requested_detector_name=detector.detector_name,
        download_url="https://example.invalid/signed/evidence",
        expected_sha256=evidence.sha256,
        expected_byte_length=evidence.byte_length,
        expected_mime_type=evidence.mime_type,
        created_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
    )
    run = DetectorRun(
        schema_version="1.0",
        run_id=run_id,
        case_id=case_id,
        evidence_id=evidence_id,
        detector=detector,
        status=DetectorRunStatus.SUCCEEDED,
        input_sha256=evidence.sha256,
        created_at=NOW,
        started_at=NOW,
        completed_at=NOW + timedelta(seconds=1),
    )
    result = DetectorResult.model_validate(
        detector_result_data()
        | {
            "run_id": run_id,
            "case_id": case_id,
            "evidence_id": evidence_id,
            "detector": detector,
        }
    )
    test_result = ForensicTestResult(
        schema_version="1.0",
        test_result_id=uuid4(),
        case_id=case_id,
        evidence_id=evidence_id,
        test_name="synthetic-header-test",
        test_version="1.0.0",
        status=ForensicTestStatus.EXECUTED,
        raw_outputs={"header_valid": True},
        runtime_ms=2,
        started_at=NOW,
        completed_at=NOW,
    )
    report = ReportManifest(
        schema_version="1.0",
        report_id=uuid4(),
        case_id=case_id,
        generated_at=NOW,
        generator_name="synthetic-report-builder",
        generator_version="1.0.0",
        generator_repository_commit="2" * 40,
        evidence=[
            ReportEvidenceReference(
                schema_version="1.0",
                evidence_id=evidence_id,
                sha256=evidence.sha256,
                sha512=evidence.sha512,
            )
        ],
        detector_result_ids=[result.result_id],
        forensic_test_result_ids=[test_result.test_result_id],
        test_coverage=[
            CoverageEntry(
                schema_version="1.0",
                test_name=test_result.test_name,
                status=test_result.status,
                test_result_id=test_result.test_result_id,
            )
        ],
        artifacts=[
            ReportArtifact(
                schema_version="1.0",
                format="json",
                storage_uri="report://synthetic/report.json",
                sha256="3" * 64,
                byte_length=100,
            )
        ],
    )

    assert case.status == CaseStatus.SEALED
    assert derivative.parent_sha256 == evidence.sha256
    assert job.expected_sha256 == run.input_sha256 == result.input_sha256
    assert report.detector_result_ids == [result.result_id]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("sha256", "a" * 63),
        ("sha256", "A" * 64),
        ("sha512", "b" * 127),
    ],
)
def test_invalid_hashes_are_rejected(field: str, value: str) -> None:
    payload = evidence_data()
    payload[field] = value
    with pytest.raises(ValidationError):
        EvidenceAsset.model_validate(payload)


def test_naive_and_non_utc_timestamps_are_rejected() -> None:
    base = {
        "schema_version": "1.0",
        "case_id": str(uuid4()),
        "status": "CREATED",
        "privacy_mode": "RESTRICTED",
    }
    with pytest.raises(ValidationError, match="timezone"):
        Case.model_validate(base | {"created_at": datetime(2026, 8, 24, 10, 0)})
    with pytest.raises(ValidationError, match="UTC"):
        Case.model_validate(
            base
            | {
                "created_at": datetime(
                    2026, 8, 24, 10, 0, tzinfo=timezone(timedelta(hours=5, minutes=30))
                )
            }
        )


def test_invalid_uuid_is_rejected() -> None:
    with pytest.raises(ValidationError, match="uuid"):
        Case(
            schema_version="1.0",
            case_id="not-a-uuid",
            created_at=NOW,
            status=CaseStatus.CREATED,
            privacy_mode=PrivacyMode.RESTRICTED,
        )


def test_incompatible_major_schema_version_is_rejected() -> None:
    with pytest.raises(ValidationError, match="schema_version"):
        Case(
            schema_version="2.0",
            case_id=uuid4(),
            created_at=NOW,
            status=CaseStatus.CREATED,
            privacy_mode=PrivacyMode.RESTRICTED,
        )


def test_missing_detector_metadata_is_rejected() -> None:
    payload = detector_identity_data()
    del payload["checkpoint_sha256"]
    with pytest.raises(ValidationError, match="checkpoint_sha256"):
        DetectorIdentity.model_validate(payload)


def test_invalid_calibrated_score_metadata_is_rejected() -> None:
    payload = detector_result_data()
    payload["calibrated_score"] = 0.75
    with pytest.raises(ValidationError, match="must appear together"):
        DetectorResult.model_validate(payload)

    payload = detector_result_data()
    payload["calibration"] = {
        "schema_version": "1.0",
        "calibrator_name": "synthetic-platt",
        "calibrator_version": "1.0.0",
        "method": "platt-scaling",
        "calibration_dataset_revision": "synthetic-dataset-1",
    }
    with pytest.raises(ValidationError, match="must appear together"):
        DetectorResult.model_validate(payload)

    with pytest.raises(ValidationError, match="calibration_dataset_revision"):
        CalibrationMetadata(
            schema_version="1.0",
            calibrator_name="synthetic-platt",
            calibrator_version="1.0.0",
            method="platt-scaling",
        )  # type: ignore[call-arg]


def test_derivative_lineage_round_trips_exact_parameters() -> None:
    derivative = EvidenceDerivative(
        schema_version="1.0",
        derivative_id=uuid4(),
        case_id=uuid4(),
        parent_evidence_id=uuid4(),
        parent_sha256=SHA256,
        filename="preview.webp",
        byte_length=100,
        mime_type="image/webp",
        output_sha256="c" * 64,
        output_sha512="d" * 128,
        storage_uri="artifact://preview",
        transformation_tool="ffmpeg",
        tool_version="7.1.1",
        exact_parameters={"quality": 80, "filters": ["scale=384:-2"]},
        lossy=True,
        created_at=NOW,
    )
    restored = EvidenceDerivative.model_validate_json(derivative.model_dump_json())
    assert restored == derivative
    assert restored.exact_parameters["quality"] == 80
    assert restored.parent_sha256 == SHA256
    assert restored.output_sha256 == "c" * 64


def test_json_serialization_preserves_unknown_future_fields() -> None:
    payload = detector_result_data() | {
        "future_evidence_family": "SYNTHETIC_CLASSIFICATION",
        "future_details": {"producer_version": 2},
    }
    result = DetectorResult.model_validate(payload)
    serialized = json.loads(result.model_dump_json())
    restored = DetectorResult.model_validate(serialized)
    assert restored.model_extra == {
        "future_evidence_family": "SYNTHETIC_CLASSIFICATION",
        "future_details": {"producer_version": 2},
    }


@pytest.mark.parametrize("test_status", list(ForensicTestStatus))
def test_every_forensic_test_status_is_supported(test_status: ForensicTestStatus) -> None:
    common: dict[str, Any] = {
        "schema_version": "1.0",
        "test_result_id": str(uuid4()),
        "case_id": str(uuid4()),
        "evidence_id": str(uuid4()),
        "test_name": "synthetic-test",
        "test_version": "1.0.0",
        "status": test_status,
    }
    if test_status == ForensicTestStatus.EXECUTED:
        common |= {"runtime_ms": 1, "started_at": NOW, "completed_at": NOW}
    else:
        common["status_reason"] = "Synthetic coverage state."
    assert ForensicTestResult.model_validate(common).status == test_status


def test_json_schemas_are_generated_and_committed() -> None:
    generated = generate_schema_documents()
    assert len(generated) == 9
    for filename, expected in generated.items():
        assert (SCHEMA_DIR / filename).read_text(encoding="utf-8") == expected
        schema = json.loads(expected)
        assert "schema_version" in schema["properties"]
        assert "schema_version" in schema["required"]
        assert schema["additionalProperties"] is True


def test_detector_schema_never_names_a_score_probability() -> None:
    schema_text = generate_schema_documents()["DetectorResult.schema.json"].lower()
    assert '"probability"' not in schema_text
    assert '"raw_score"' in schema_text


@pytest.mark.parametrize(
    ("filename", "model"),
    [
        ("example-case.json", Case),
        ("example-detector-result.json", DetectorResult),
    ],
)
def test_versioned_examples_load_and_reserialize(
    filename: str, model: type[Case] | type[DetectorResult]
) -> None:
    source = json.loads((ROOT / "docs" / "examples" / filename).read_text(encoding="utf-8"))
    loaded = model.model_validate(source)
    restored = model.model_validate_json(loaded.model_dump_json())
    assert restored == loaded
    assert restored.schema_version == "1.0"
