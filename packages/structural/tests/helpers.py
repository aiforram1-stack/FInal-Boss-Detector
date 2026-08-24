from __future__ import annotations

import hashlib
import io
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from forensic_contracts import (
    CaseStatus,
    EvidenceAsset,
    ForensicTestResult,
    ForensicTestStatus,
    IntegrityStatus,
    IntegrityVerification,
    PrivacyMode,
    StructuralCommonSummary,
    StructuralReport,
    StructuralReportCase,
    StructuralReportEvidence,
    StructuralSoftwareIdentity,
    StructuralSummary,
    ToolAvailabilityStatus,
    ToolInventoryEntry,
)
from forensic_evidence import LocalContentAddressedStorage

PNG = b"\x89PNG\r\n\x1a\n" + b"phase-three-generated" * 8
NOW = datetime(2026, 8, 24, 12, 0, tzinfo=UTC)


def stored_evidence(
    tmp_path: Path,
) -> tuple[LocalContentAddressedStorage, EvidenceAsset, Path]:
    backend = LocalContentAddressedStorage(
        tmp_path / "evidence",
        max_upload_bytes=4096,
        upload_chunk_bytes=17,
        allowed_media_types=frozenset({"image/png"}),
    )
    blob = backend.put_stream(io.BytesIO(PNG))
    evidence = EvidenceAsset(
        schema_version="1.0",
        evidence_id=uuid4(),
        case_id=uuid4(),
        filename="generated.png",
        byte_length=blob.byte_length,
        mime_type=blob.detected_mime_type,
        sha256=blob.sha256,
        sha512=blob.sha512,
        storage_uri=blob.storage_uri,
        object_version=blob.object_version,
        created_at=NOW,
    )
    return backend, evidence, backend.path_for_sha256(blob.sha256)


def sample_report(
    *, filename: str = "generated.png", metadata_value: str = "safe"
) -> StructuralReport:
    case_id = uuid4()
    evidence_id = uuid4()
    report_id = uuid4()
    run_id = uuid4()
    sha256 = hashlib.sha256(PNG).hexdigest()
    sha512 = hashlib.sha512(PNG).hexdigest()
    inventory = [
        ToolInventoryEntry(
            schema_version="1.0",
            tool_name="exiftool",
            status=ToolAvailabilityStatus.UNAVAILABLE,
            required_by_test_ids=["structural.exiftool-metadata.v1"],
            status_reason="The configured executable is unavailable.",
        )
    ]
    integrity = IntegrityVerification(
        schema_version="1.0",
        evidence_id=evidence_id,
        expected_sha256=sha256,
        verified_sha256=sha256,
        expected_sha512=sha512,
        verified_sha512=sha512,
        expected_byte_length=len(PNG),
        verified_byte_length=len(PNG),
        status=IntegrityStatus.VERIFIED,
        started_at=NOW,
        completed_at=NOW,
    )
    test = ForensicTestResult(
        schema_version="1.0",
        test_result_id=uuid4(),
        case_id=case_id,
        evidence_id=evidence_id,
        test_name="structural.exiftool-metadata.v1",
        test_version="1.0.0",
        status=ForensicTestStatus.PROVIDER_UNAVAILABLE,
        status_reason="The configured metadata tool is unavailable.",
    )
    summary = StructuralSummary(
        schema_version="1.0",
        common=StructuralCommonSummary(
            schema_version="1.0",
            original_filename=filename,
            detected_mime_type="image/png",
            client_mime_type="image/png",
            byte_length=len(PNG),
            sha256=sha256,
            sha512=sha512,
            storage_uri=f"local-sha256://{sha256}",
            extension_signature_consistent=True,
            tool_availability=inventory,
            analysis_started_at=NOW,
            analysis_completed_at=NOW,
        ),
        metadata={"Comment": metadata_value},
    )
    return StructuralReport(
        schema_version="1.0",
        report_id=report_id,
        analysis_run_id=run_id,
        case=StructuralReportCase(
            schema_version="1.0",
            case_id=case_id,
            status=CaseStatus.SEALED,
            privacy_mode=PrivacyMode.RESTRICTED,
            claim="Synthetic structural test",
        ),
        evidence=StructuralReportEvidence(
            schema_version="1.0",
            evidence_id=evidence_id,
            filename=filename,
            mime_type="image/png",
            client_mime_type="image/png",
            byte_length=len(PNG),
            sha256=sha256,
            sha512=sha512,
            storage_uri=f"local-sha256://{sha256}",
        ),
        integrity=integrity,
        tool_inventory=inventory,
        tests=[test],
        structural_summary=summary,
        consistency_findings=[],
        limitations=["Structural observations are non-conclusive."],
        generated_at=NOW,
        software=StructuralSoftwareIdentity(
            schema_version="1.0", application_version="0.3.0", git_commit=None
        ),
    )
