from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from forensic_contracts import ForensicTestStatus, IntegrityStatus
from forensic_structural.adapters import ExifToolAdapter, FfprobeAdapter, MediaInfoAdapter
from forensic_structural.integrity import IntegrityVerifier
from forensic_structural.registry import STRUCTURAL_TESTS, StructuralTestRegistry
from forensic_structural.runner import CommandOutcome, CommandResult, SafeSubprocessRunner
from forensic_structural.service import StructuralAnalysisEngine

from .helpers import stored_evidence


class ControlledRunner(SafeSubprocessRunner):
    def __init__(self, result: CommandResult) -> None:
        super().__init__(timeout_seconds=1, max_output_bytes=4096)
        self.result = result

    def run(
        self,
        *,
        binary: str,
        arguments: Sequence[str],
        version_arguments: Sequence[str],
        evidence_path: Path,
    ) -> CommandResult:
        return self.result


def command_result(
    stdout: str, *, outcome: CommandOutcome = CommandOutcome.SUCCEEDED
) -> CommandResult:
    return CommandResult(
        outcome=outcome,
        stdout=stdout,
        stderr="controlled failure" if outcome != CommandOutcome.SUCCEEDED else "",
        exit_code=0 if outcome == CommandOutcome.SUCCEEDED else 2,
        runtime_ms=3,
        tool_version="controlled-tool 1.0",
    )


def test_registry_has_exact_unique_phase3_tests() -> None:
    expected = {
        "structural.file-signature.v1",
        "structural.exiftool-metadata.v1",
        "structural.ffprobe-container.v1",
        "structural.mediainfo.v1",
        "structural.image-summary.v1",
        "structural.audio-summary.v1",
        "structural.video-summary.v1",
        "structural.metadata-consistency.v1",
    }
    assert {item.test_id for item in STRUCTURAL_TESTS} == expected
    registry = StructuralTestRegistry()
    assert registry.is_applicable("structural.image-summary.v1", "image/png")
    assert not registry.is_applicable("structural.image-summary.v1", "audio/wav")
    for definition in STRUCTURAL_TESTS:
        assert definition.description
        assert definition.timeout_seconds > 0
        assert definition.expected_output_type
        assert definition.known_limitations


def test_controlled_adapters_parse_json_and_strip_physical_paths(tmp_path: Path) -> None:
    evidence_path = tmp_path / "private evidence.png"
    evidence_path.write_bytes(b"synthetic")
    exif = ExifToolAdapter(
        ControlledRunner(
            command_result(
                json.dumps(
                    [
                        {
                            "SourceFile": str(evidence_path),
                            "EXIF:Make": "Synthetic Camera",
                            "EXIF:ImageWidth": 640,
                        }
                    ]
                )
            )
        ),
        "exiftool",
    ).execute(evidence_path)
    assert exif.status == ForensicTestStatus.EXECUTED
    assert exif.structured_output["EXIF:Make"] == "Synthetic Camera"
    assert "SourceFile" not in exif.structured_output
    assert str(evidence_path) not in str(exif.structured_output)

    ffprobe = FfprobeAdapter(
        ControlledRunner(
            command_result(
                json.dumps(
                    {
                        "format": {"filename": str(evidence_path), "duration": "1.25"},
                        "streams": [{"codec_type": "video", "width": 640}],
                    }
                )
            )
        ),
        "ffprobe",
    ).execute(evidence_path)
    assert ffprobe.status == ForensicTestStatus.EXECUTED
    assert "filename" not in ffprobe.structured_output["format"]  # type: ignore[operator]

    mediainfo = MediaInfoAdapter(
        ControlledRunner(
            command_result(
                json.dumps(
                    {
                        "media": {
                            "@ref": str(evidence_path),
                            "track": [{"@type": "General", "CompleteName": str(evidence_path)}],
                        }
                    }
                )
            )
        ),
        "mediainfo",
    ).execute(evidence_path)
    assert mediainfo.status == ForensicTestStatus.EXECUTED
    assert str(evidence_path) not in str(mediainfo.structured_output)


def test_failed_and_missing_adapters_have_explicit_status(tmp_path: Path) -> None:
    evidence_path = tmp_path / "generated.png"
    evidence_path.write_bytes(b"synthetic")
    failed = FfprobeAdapter(
        ControlledRunner(command_result("", outcome=CommandOutcome.NONZERO_EXIT)),
        "ffprobe",
    ).execute(evidence_path)
    assert failed.status == ForensicTestStatus.FAILED
    assert failed.status_reason

    missing = MediaInfoAdapter(
        ControlledRunner(command_result("", outcome=CommandOutcome.EXECUTABLE_MISSING)),
        "mediainfo",
    ).execute(evidence_path)
    assert missing.status == ForensicTestStatus.PROVIDER_UNAVAILABLE
    assert missing.status_reason


def test_engine_emits_status_for_every_test_when_tools_are_missing(tmp_path: Path) -> None:
    backend, evidence, path = stored_evidence(tmp_path)
    check = IntegrityVerifier(backend).verify(evidence)
    assert check.verification.status == IntegrityStatus.VERIFIED
    engine = StructuralAnalysisEngine(
        runner=SafeSubprocessRunner(timeout_seconds=1, max_output_bytes=4096),
        exiftool_binary=str(tmp_path / "missing-exiftool"),
        ffprobe_binary=str(tmp_path / "missing-ffprobe"),
        mediainfo_binary=str(tmp_path / "missing-mediainfo"),
    )
    result = engine.analyze(
        evidence=evidence,
        client_mime_type="text/plain",
        evidence_path=path,
        integrity=check.verification,
        started_at=datetime.now(UTC),
    )
    assert [item.test_name for item in result.test_results] == [
        item.test_id for item in STRUCTURAL_TESTS
    ]
    statuses = {item.test_name: item.status for item in result.test_results}
    assert statuses["structural.file-signature.v1"] == ForensicTestStatus.EXECUTED
    assert statuses["structural.exiftool-metadata.v1"] == ForensicTestStatus.PROVIDER_UNAVAILABLE
    assert statuses["structural.audio-summary.v1"] == ForensicTestStatus.NOT_APPLICABLE
    assert statuses["structural.video-summary.v1"] == ForensicTestStatus.NOT_APPLICABLE
    assert statuses["structural.image-summary.v1"] == ForensicTestStatus.EXECUTED


def test_engine_marks_unsupported_mime_without_invoking_tools(tmp_path: Path) -> None:
    backend, evidence, path = stored_evidence(tmp_path)
    check = IntegrityVerifier(backend).verify(evidence)
    evidence = evidence.model_copy(update={"mime_type": "application/octet-stream"})
    engine = StructuralAnalysisEngine(
        runner=SafeSubprocessRunner(timeout_seconds=1, max_output_bytes=4096),
        exiftool_binary=str(tmp_path / "must-not-run-exiftool"),
        ffprobe_binary=str(tmp_path / "must-not-run-ffprobe"),
        mediainfo_binary=str(tmp_path / "must-not-run-mediainfo"),
    )
    result = engine.analyze(
        evidence=evidence,
        client_mime_type=None,
        evidence_path=path,
        integrity=check.verification,
        started_at=datetime.now(UTC),
    )
    assert len(result.test_results) == len(STRUCTURAL_TESTS)
    statuses = {item.test_name: item.status for item in result.test_results}
    assert statuses["structural.file-signature.v1"] == ForensicTestStatus.UNSUPPORTED_INPUT
    assert statuses["structural.ffprobe-container.v1"] == ForensicTestStatus.UNSUPPORTED_INPUT
    assert statuses["structural.image-summary.v1"] == ForensicTestStatus.NOT_APPLICABLE
