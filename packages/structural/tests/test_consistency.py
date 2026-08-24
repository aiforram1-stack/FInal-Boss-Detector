from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from forensic_contracts import (
    FindingSeverity,
    IntegrityStatus,
    IntegrityVerification,
    ToolAvailabilityStatus,
    ToolInventoryEntry,
)
from forensic_structural.consistency import build_consistency_findings
from forensic_structural.summaries import build_structural_summary
from pydantic import JsonValue

from .helpers import stored_evidence


def test_all_required_mismatches_are_structured_without_verdict_language(tmp_path: Path) -> None:
    _, evidence, _ = stored_evidence(tmp_path)
    evidence = evidence.model_copy(update={"filename": "renamed.jpg"})
    now = datetime.now(UTC)
    outputs: dict[str, dict[str, JsonValue]] = {
        "structural.file-signature.v1": {
            "extension_mime_type": "image/jpeg",
            "extension_signature_consistent": False,
        },
        "structural.exiftool-metadata.v1": {
            "EXIF:ImageWidth": 640,
            "EXIF:ImageHeight": 480,
            "EXIF:DateTimeOriginal": "2026:08:24 10:00:00",
            "EXIF:Software": "Routine Exporter",
        },
        "structural.ffprobe-container.v1": {
            "format": {
                "size": str(evidence.byte_length + 1),
                "duration": "1.0",
                "tags": {"creation_time": "2026-08-24T10:01:00Z"},
            },
            "streams": [
                {"codec_type": "video", "width": 320, "height": 200},
                {"codec_type": "audio"},
            ],
        },
        "structural.mediainfo.v1": {
            "media": {
                "track": [
                    {
                        "@type": "General",
                        "Duration": "2.0",
                        "Encoded_Date": "2026-08-24T10:02:00Z",
                    },
                    {"@type": "Video"},
                ]
            }
        },
    }
    inventory = [
        ToolInventoryEntry(
            schema_version="1.0",
            tool_name="controlled",
            status=ToolAvailabilityStatus.AVAILABLE,
            version="1.0",
        )
    ]
    summary = build_structural_summary(
        evidence=evidence,
        client_mime_type="text/plain",
        tool_inventory=inventory,
        started_at=now,
        completed_at=now,
        outputs=outputs,
        warnings=[],
    )
    integrity = IntegrityVerification(
        schema_version="1.0",
        evidence_id=evidence.evidence_id,
        expected_sha256=evidence.sha256,
        verified_sha256=evidence.sha256,
        expected_sha512=evidence.sha512,
        verified_sha512=evidence.sha512,
        expected_byte_length=evidence.byte_length,
        verified_byte_length=evidence.byte_length + 2,
        status=IntegrityStatus.SIZE_MISMATCH,
        started_at=now,
        completed_at=now,
        status_reason="Controlled mismatch.",
    )
    findings = build_consistency_findings(
        evidence=evidence,
        client_mime_type="text/plain",
        integrity=integrity,
        summary=summary,
        outputs=outputs,
    )
    identifiers = {item.finding_id for item in findings}
    assert "structural.finding.extension-mime-mismatch.v1" in identifiers
    assert "structural.finding.client-mime-mismatch.v1" in identifiers
    assert "structural.finding.byte-size-mismatch.v1" in identifiers
    assert "structural.finding.ffprobe-size-mismatch.v1" in identifiers
    assert "structural.finding.dimension-mismatch.v1" in identifiers
    assert "structural.finding.height-mismatch.v1" in identifiers
    assert "structural.finding.duration-mismatch.v1" in identifiers
    assert "structural.finding.stream-count-mismatch.v1" in identifiers
    assert "structural.finding.creation-time-mismatch.v1" in identifiers
    assert "structural.finding.software-tag-present.v1" in identifiers
    assert all(item.source_test_ids for item in findings)
    assert all(item.compared_fields and item.tool_sources for item in findings)
    assert any(item.severity == FindingSeverity.ERROR for item in findings)
    combined = " ".join(item.description for item in findings).upper()
    assert "FAKE" not in combined
    assert "MANIPULATED" not in combined
    assert "AI_GENERATED" not in combined
