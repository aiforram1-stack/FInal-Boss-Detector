"""Persistence-independent orchestration of the complete structural test registry."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol
from uuid import uuid4

from forensic_contracts import (
    ConsistencyFinding,
    EvidenceAsset,
    ForensicTestResult,
    ForensicTestStatus,
    IntegrityVerification,
    StructuralAnalysisStatus,
    StructuralSummary,
    ToolAvailabilityStatus,
    ToolInventoryEntry,
)
from pydantic import JsonValue

from forensic_structural.adapters import (
    AdapterResult,
    ExifToolAdapter,
    FfprobeAdapter,
    FileSignatureAdapter,
    MediaInfoAdapter,
)
from forensic_structural.consistency import build_consistency_findings
from forensic_structural.registry import StructuralTestRegistry
from forensic_structural.runner import SafeSubprocessRunner
from forensic_structural.summaries import build_structural_summary


@dataclass(frozen=True, slots=True)
class StructuralEngineResult:
    status: StructuralAnalysisStatus
    completed_at: datetime
    test_results: list[ForensicTestResult]
    summary: StructuralSummary
    consistency_findings: list[ConsistencyFinding]
    tool_inventory: list[ToolInventoryEntry]
    raw_artifacts: dict[str, bytes]


class ToolAdapter(Protocol):
    def execute(self, evidence_path: Path) -> AdapterResult: ...


class StructuralAnalysisEngine:
    def __init__(
        self,
        *,
        runner: SafeSubprocessRunner,
        exiftool_binary: str,
        ffprobe_binary: str,
        mediainfo_binary: str,
        registry: StructuralTestRegistry | None = None,
    ) -> None:
        self.registry = registry or StructuralTestRegistry()
        self.file_signature = FileSignatureAdapter()
        self.tool_adapters: dict[str, ToolAdapter] = {
            "structural.exiftool-metadata.v1": ExifToolAdapter(runner, exiftool_binary),
            "structural.ffprobe-container.v1": FfprobeAdapter(runner, ffprobe_binary),
            "structural.mediainfo.v1": MediaInfoAdapter(runner, mediainfo_binary),
        }

    def analyze(
        self,
        *,
        evidence: EvidenceAsset,
        client_mime_type: str | None,
        evidence_path: Path,
        integrity: IntegrityVerification,
        started_at: datetime,
    ) -> StructuralEngineResult:
        category = self.registry.category_for_mime(evidence.mime_type)
        outputs: dict[str, dict[str, JsonValue]] = {}
        adapter_results: dict[str, AdapterResult] = {}
        raw_artifacts: dict[str, bytes] = {}

        signature_result = (
            self.file_signature.execute(evidence_path, evidence)
            if category is not None
            else AdapterResult(
                status=ForensicTestStatus.UNSUPPORTED_INPUT,
                status_reason="The detected MIME category is not supported by Phase 3.",
            )
        )
        adapter_results["structural.file-signature.v1"] = signature_result
        outputs["structural.file-signature.v1"] = signature_result.structured_output

        artifact_names = {
            "structural.exiftool-metadata.v1": "exiftool.json",
            "structural.ffprobe-container.v1": "ffprobe.json",
            "structural.mediainfo.v1": "mediainfo.json",
        }
        for test_id, adapter in self.tool_adapters.items():
            if category is None:
                result = AdapterResult(
                    status=ForensicTestStatus.UNSUPPORTED_INPUT,
                    status_reason=(
                        "The detected MIME category is not supported by this tool adapter."
                    ),
                )
            else:
                result = adapter.execute(evidence_path)
            adapter_results[test_id] = result
            outputs[test_id] = result.structured_output
            if result.raw_artifact is not None:
                raw_artifacts[artifact_names[test_id]] = result.raw_artifact

        completed_at = datetime.now(UTC)
        inventory = self._tool_inventory(adapter_results)
        warnings = [warning for result in adapter_results.values() for warning in result.warnings]
        summary = build_structural_summary(
            evidence=evidence,
            client_mime_type=client_mime_type,
            tool_inventory=inventory,
            started_at=started_at,
            completed_at=completed_at,
            outputs=outputs,
            warnings=warnings,
        )
        findings = build_consistency_findings(
            evidence=evidence,
            client_mime_type=client_mime_type,
            integrity=integrity,
            summary=summary,
            outputs=outputs,
        )
        tests = self._build_test_results(
            evidence=evidence,
            category=category,
            adapter_results=adapter_results,
            summary=summary,
            findings=findings,
            completed_at=completed_at,
            artifact_names=artifact_names,
        )
        status = (
            StructuralAnalysisStatus.PARTIAL
            if any(
                item.status in {ForensicTestStatus.FAILED, ForensicTestStatus.PROVIDER_UNAVAILABLE}
                for item in tests
            )
            else StructuralAnalysisStatus.COMPLETED
        )
        return StructuralEngineResult(
            status=status,
            completed_at=completed_at,
            test_results=tests,
            summary=summary,
            consistency_findings=findings,
            tool_inventory=inventory,
            raw_artifacts=raw_artifacts,
        )

    def _build_test_results(
        self,
        *,
        evidence: EvidenceAsset,
        category: str | None,
        adapter_results: dict[str, AdapterResult],
        summary: StructuralSummary,
        findings: list[ConsistencyFinding],
        completed_at: datetime,
        artifact_names: dict[str, str],
    ) -> list[ForensicTestResult]:
        tests: list[ForensicTestResult] = []
        for definition in self.registry.definitions:
            started_at = completed_at
            if definition.test_id in adapter_results:
                result = adapter_results[definition.test_id]
                raw_outputs: dict[str, JsonValue]
                if definition.test_id == "structural.file-signature.v1":
                    raw_outputs = result.structured_output
                else:
                    raw_outputs = {
                        "output_artifact": artifact_names[definition.test_id]
                        if result.raw_artifact is not None
                        else None,
                        "error_code": result.error_code,
                    }
                tests.append(
                    self._test_result(
                        evidence=evidence,
                        test_id=definition.test_id,
                        version=definition.test_version,
                        result=result,
                        raw_outputs=raw_outputs,
                        started_at=started_at,
                        completed_at=completed_at,
                    )
                )
                continue

            applicable = category in definition.applicable_mime_categories
            if not applicable:
                tests.append(
                    ForensicTestResult(
                        schema_version="1.0",
                        test_result_id=uuid4(),
                        case_id=evidence.case_id,
                        evidence_id=evidence.evidence_id,
                        test_name=definition.test_id,
                        test_version=definition.test_version,
                        status=ForensicTestStatus.NOT_APPLICABLE,
                        status_reason="This test does not apply to the detected MIME category.",
                    )
                )
                continue
            if definition.test_id.endswith("image-summary.v1"):
                output: JsonValue = summary.image.model_dump(mode="json") if summary.image else None
            elif definition.test_id.endswith("audio-summary.v1"):
                output = summary.audio.model_dump(mode="json") if summary.audio else None
            elif definition.test_id.endswith("video-summary.v1"):
                output = summary.video.model_dump(mode="json") if summary.video else None
            else:
                output = {"finding_ids": [item.finding_id for item in findings]}
            tests.append(
                ForensicTestResult(
                    schema_version="1.0",
                    test_result_id=uuid4(),
                    case_id=evidence.case_id,
                    evidence_id=evidence.evidence_id,
                    test_name=definition.test_id,
                    test_version=definition.test_version,
                    status=ForensicTestStatus.EXECUTED,
                    raw_outputs={"summary": output},
                    findings=[item.finding_id for item in findings]
                    if definition.test_id.endswith("metadata-consistency.v1")
                    else [],
                    runtime_ms=0,
                    started_at=started_at,
                    completed_at=completed_at,
                )
            )
        return tests

    @staticmethod
    def _test_result(
        *,
        evidence: EvidenceAsset,
        test_id: str,
        version: str,
        result: AdapterResult,
        raw_outputs: dict[str, JsonValue],
        started_at: datetime,
        completed_at: datetime,
    ) -> ForensicTestResult:
        executed = result.status == ForensicTestStatus.EXECUTED
        return ForensicTestResult(
            schema_version="1.0",
            test_result_id=uuid4(),
            case_id=evidence.case_id,
            evidence_id=evidence.evidence_id,
            test_name=test_id,
            test_version=version,
            status=result.status,
            status_reason=result.status_reason,
            raw_outputs=raw_outputs,
            warnings=result.warnings,
            runtime_ms=result.runtime_ms if executed else None,
            started_at=started_at if executed else None,
            completed_at=completed_at if executed else None,
        )

    @staticmethod
    def _tool_inventory(results: dict[str, AdapterResult]) -> list[ToolInventoryEntry]:
        entries = [
            ToolInventoryEntry(
                schema_version="1.0",
                tool_name="internal-file-signature",
                status=ToolAvailabilityStatus.AVAILABLE,
                version="1.0.0",
                required_by_test_ids=["structural.file-signature.v1"],
            )
        ]
        for test_id, tool_name in (
            ("structural.exiftool-metadata.v1", "exiftool"),
            ("structural.ffprobe-container.v1", "ffprobe"),
            ("structural.mediainfo.v1", "mediainfo"),
        ):
            result = results[test_id]
            available = (
                result.status != ForensicTestStatus.PROVIDER_UNAVAILABLE
                and result.tool_version is not None
                and result.error_code != "START_FAILED"
            )
            entries.append(
                ToolInventoryEntry(
                    schema_version="1.0",
                    tool_name=tool_name,
                    status=(
                        ToolAvailabilityStatus.AVAILABLE
                        if available
                        else ToolAvailabilityStatus.UNAVAILABLE
                    ),
                    version=result.tool_version if available else None,
                    required_by_test_ids=[test_id],
                    status_reason=(
                        None if available else "The configured executable is unavailable."
                    ),
                )
            )
        return entries
