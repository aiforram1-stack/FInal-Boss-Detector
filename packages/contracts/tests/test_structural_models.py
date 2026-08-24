from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from forensic_contracts import (
    ConsistencyFinding,
    FindingSeverity,
    IntegrityStatus,
    IntegrityVerification,
    StructuralAnalysisRun,
    StructuralAnalysisStatus,
    ToolAvailabilityStatus,
    ToolInventoryEntry,
)
from pydantic import ValidationError

NOW = datetime(2026, 8, 24, 12, 0, tzinfo=UTC)
SHA256 = "a" * 64
SHA512 = "b" * 128


def verified_integrity() -> IntegrityVerification:
    return IntegrityVerification(
        schema_version="1.0",
        evidence_id=uuid4(),
        expected_sha256=SHA256,
        verified_sha256=SHA256,
        expected_sha512=SHA512,
        verified_sha512=SHA512,
        expected_byte_length=10,
        verified_byte_length=10,
        status=IntegrityStatus.VERIFIED,
        started_at=NOW,
        completed_at=NOW,
    )


def test_integrity_contract_requires_exact_verified_values() -> None:
    with pytest.raises(ValidationError, match="must match"):
        IntegrityVerification(
            schema_version="1.0",
            evidence_id=uuid4(),
            expected_sha256=SHA256,
            verified_sha256="c" * 64,
            expected_sha512=SHA512,
            verified_sha512=SHA512,
            expected_byte_length=10,
            verified_byte_length=10,
            status=IntegrityStatus.VERIFIED,
            started_at=NOW,
            completed_at=NOW,
        )


def test_tool_inventory_requires_version_or_unavailable_reason() -> None:
    with pytest.raises(ValidationError, match="require a version"):
        ToolInventoryEntry(
            schema_version="1.0",
            tool_name="ffprobe",
            status=ToolAvailabilityStatus.AVAILABLE,
        )
    with pytest.raises(ValidationError, match="status_reason"):
        ToolInventoryEntry(
            schema_version="1.0",
            tool_name="ffprobe",
            status=ToolAvailabilityStatus.UNAVAILABLE,
        )


@pytest.mark.parametrize("term", ["FAKE", "MANIPULATED", "AI_GENERATED"])
def test_structural_finding_rejects_verdict_language(term: str) -> None:
    with pytest.raises(ValidationError, match="verdict language"):
        ConsistencyFinding(
            schema_version="1.0",
            finding_id="structural.finding.test.v1",
            severity=FindingSeverity.WARNING,
            description=f"This is {term}.",
            compared_fields=["one", "two"],
            observed_values={"one": 1, "two": 2},
            tool_sources=["synthetic"],
            source_test_ids=["structural.synthetic.v1"],
        )


def test_structural_run_lifecycle_and_future_fields_round_trip() -> None:
    payload = {
        "schema_version": "1.0",
        "analysis_run_id": str(uuid4()),
        "case_id": str(uuid4()),
        "evidence_id": str(uuid4()),
        "analysis_profile": "structural-default-v1",
        "status": "REFUSED",
        "input_sha256": SHA256,
        "started_at": NOW.isoformat(),
        "completed_at": NOW.isoformat(),
        "integrity": verified_integrity().model_dump(mode="json"),
        "future_parser_family": {"revision": 2},
    }
    run = StructuralAnalysisRun.model_validate(payload)
    restored = StructuralAnalysisRun.model_validate_json(run.model_dump_json())
    assert restored == run
    assert restored.model_extra == {"future_parser_family": {"revision": 2}}

    with pytest.raises(ValidationError, match="terminal analyses require"):
        StructuralAnalysisRun(
            schema_version="1.0",
            analysis_run_id=uuid4(),
            case_id=uuid4(),
            evidence_id=uuid4(),
            analysis_profile="structural-default-v1",
            status=StructuralAnalysisStatus.FAILED,
            input_sha256=SHA256,
            started_at=NOW,
        )
