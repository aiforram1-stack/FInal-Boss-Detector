"""Application service for integrity-gated structural analysis and reports."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

from forensic_contracts import (
    ArtifactReference,
    Case,
    ForensicTestResult,
    ForensicTestStatus,
    IntegrityStatus,
    IntegrityVerification,
    ReportArtifact,
    ReportEvidenceReference,
    ReportManifest,
    StructuralAnalysisRun,
    StructuralAnalysisStatus,
    StructuralReport,
    StructuralReportCase,
    StructuralReportEvidence,
    StructuralSoftwareIdentity,
    TestCoverageEntry,
)
from forensic_evidence import StorageBackend
from forensic_structural import (
    IntegrityVerifier,
    LocalResultStorage,
    canonical_json_bytes,
    render_structural_html,
)
from forensic_structural.service import StructuralAnalysisEngine, StructuralEngineResult
from sqlalchemy.exc import SQLAlchemyError

from forensic_api.db.repositories import (
    ActiveStructuralAnalysisError,
    EvidenceAnalysisContext,
    Repository,
    StructuralArtifactInsert,
    StructuralReportInsert,
)
from forensic_api.errors import ApiError

ANALYSIS_PROFILE = "structural-default-v1"
APPLICATION_VERSION = "0.3.0"
ZERO_COMMIT = "0" * 40
RAW_TOOL_MAP = {
    "exiftool.json": ("structural.exiftool-metadata.v1", "exiftool"),
    "ffprobe.json": ("structural.ffprobe-container.v1", "ffprobe"),
    "mediainfo.json": ("structural.mediainfo.v1", "mediainfo"),
}


class StructuralAnalysisService:
    def __init__(
        self,
        *,
        repository: Repository,
        evidence_storage: StorageBackend,
        result_storage: LocalResultStorage,
        engine: StructuralAnalysisEngine,
        template_directory: Path,
        enabled: bool,
        git_commit: str | None,
    ) -> None:
        self.repository = repository
        self.integrity = IntegrityVerifier(evidence_storage)
        self.result_storage = result_storage
        self.engine = engine
        self.template_directory = template_directory
        self.enabled = enabled
        self.git_commit = git_commit

    def start(self, case_id: UUID, evidence_id: UUID) -> StructuralAnalysisRun:
        if not self.enabled:
            raise ApiError(503, "STRUCTURAL_ANALYSIS_DISABLED", "Structural analysis is disabled.")
        case, context = self._context(case_id, evidence_id)
        run_id = uuid4()
        started_at = datetime.now(UTC)
        try:
            self.repository.create_structural_run(
                run_id=run_id,
                case_id=case_id,
                evidence_id=evidence_id,
                analysis_profile=ANALYSIS_PROFILE,
                input_sha256=context.evidence.sha256,
                software_version=APPLICATION_VERSION,
                git_commit=self.git_commit,
                started_at=started_at,
            )
        except ActiveStructuralAnalysisError as exc:
            raise ApiError(
                409,
                "STRUCTURAL_ANALYSIS_ACTIVE",
                "A structural analysis is already active for this evidence.",
            ) from exc
        except SQLAlchemyError as exc:
            raise ApiError(503, "DATABASE_UNAVAILABLE", "Analysis storage is unavailable.") from exc

        check = self.integrity.verify(context.evidence)
        if check.verification.status != IntegrityStatus.VERIFIED:
            refused = self._integrity_refusal(
                case_id=case_id,
                context=context,
                run_id=run_id,
                started_at=started_at,
                verification=check.verification,
            )
            try:
                self.repository.finalize_structural_run(
                    run=refused, artifacts=[], report=None, tool_versions={}
                )
            except SQLAlchemyError as exc:
                raise ApiError(
                    503, "DATABASE_UNAVAILABLE", "Integrity failure could not be recorded."
                ) from exc
            raise ApiError(
                409,
                "EVIDENCE_INTEGRITY_FAILURE",
                "Structural analysis was refused because evidence integrity verification failed.",
            )
        assert check.evidence_path is not None

        try:
            engine_result = self.engine.analyze(
                evidence=context.evidence,
                client_mime_type=context.client_mime_type,
                evidence_path=check.evidence_path,
                integrity=check.verification,
                started_at=started_at,
            )
            return self._persist_success(
                case=case,
                context=context,
                run_id=run_id,
                started_at=started_at,
                integrity=check.verification,
                engine_result=engine_result,
            )
        except ApiError:
            raise
        except Exception as exc:
            self._record_internal_failure(
                case_id=case_id,
                context=context,
                run_id=run_id,
                started_at=started_at,
                integrity=check.verification,
            )
            raise ApiError(
                500,
                "STRUCTURAL_ANALYSIS_FAILED",
                "Structural analysis failed without modifying the evidence object.",
            ) from exc

    def list_runs(self, case_id: UUID, evidence_id: UUID) -> list[StructuralAnalysisRun]:
        self._context(case_id, evidence_id)
        try:
            return self.repository.list_structural_runs(case_id, evidence_id)
        except SQLAlchemyError as exc:
            raise ApiError(503, "DATABASE_UNAVAILABLE", "Analysis storage is unavailable.") from exc

    def report_bytes(self, case_id: UUID, *, html: bool) -> tuple[bytes, str]:
        try:
            case = self.repository.get_case(case_id)
            location = self.repository.latest_structural_report(case_id)
        except SQLAlchemyError as exc:
            raise ApiError(503, "DATABASE_UNAVAILABLE", "Report storage is unavailable.") from exc
        if case is None:
            raise ApiError(404, "CASE_NOT_FOUND", "The requested case was not found.")
        if location is None:
            raise ApiError(404, "STRUCTURAL_REPORT_NOT_FOUND", "No structural report is available.")
        uri = location.html_uri if html else location.json_uri
        expected_hash = location.html_sha256 if html else location.json_sha256
        try:
            content = self.result_storage.read_bytes(uri)
        except (OSError, ValueError) as exc:
            raise ApiError(
                503, "REPORT_UNAVAILABLE", "The structural report is unavailable."
            ) from exc
        if hashlib.sha256(content).hexdigest() != expected_hash:
            raise ApiError(
                503, "REPORT_INTEGRITY_FAILURE", "The structural report failed verification."
            )
        return content, "text/html; charset=utf-8" if html else "application/json"

    def _context(self, case_id: UUID, evidence_id: UUID) -> tuple[Case, EvidenceAnalysisContext]:
        try:
            case = self.repository.get_case(case_id)
            context = self.repository.get_evidence_analysis_context(case_id, evidence_id)
        except SQLAlchemyError as exc:
            raise ApiError(
                503, "DATABASE_UNAVAILABLE", "Evidence metadata is unavailable."
            ) from exc
        if case is None:
            raise ApiError(404, "CASE_NOT_FOUND", "The requested case was not found.")
        if context is None:
            raise ApiError(404, "EVIDENCE_NOT_FOUND", "The requested evidence was not found.")
        return case, context

    def _persist_success(
        self,
        *,
        case: Case,
        context: EvidenceAnalysisContext,
        run_id: UUID,
        started_at: datetime,
        integrity: IntegrityVerification,
        engine_result: StructuralEngineResult,
    ) -> StructuralAnalysisRun:
        artifact_records: list[StructuralArtifactInsert] = []
        artifact_references: dict[str, ArtifactReference] = {}
        versions = {item.tool_name: item.version for item in engine_result.tool_inventory}
        for name, content in sorted(engine_result.raw_artifacts.items()):
            test_id, tool_name = RAW_TOOL_MAP[name]
            stored = self.result_storage.put_bytes(context.evidence.case_id, run_id, name, content)
            artifact_id = uuid4()
            reference = ArtifactReference(
                schema_version="1.0",
                artifact_id=artifact_id,
                kind="structural-tool-output",
                storage_uri=stored.storage_uri,
                sha256=stored.sha256,
                byte_length=stored.byte_length,
                mime_type="application/json",
                parent_sha256=context.evidence.sha256,
                transformation_tool=tool_name,
                tool_version=versions.get(tool_name) or "version-not-reported",
                exact_parameters={"test_id": test_id, "output_format": "json"},
                lossy=False,
            )
            artifact_references[test_id] = reference
            artifact_records.append(
                StructuralArtifactInsert(
                    artifact_id=artifact_id,
                    kind=reference.kind,
                    storage_uri=stored.storage_uri,
                    sha256=stored.sha256,
                    byte_length=stored.byte_length,
                    mime_type=reference.mime_type,
                    tool_source=tool_name,
                )
            )
        tests = [
            result.model_copy(update={"artifacts": [artifact_references[result.test_name]]})
            if result.test_name in artifact_references
            else result
            for result in engine_result.test_results
        ]
        report_id = uuid4()
        report = StructuralReport(
            schema_version="1.0",
            report_id=report_id,
            analysis_run_id=run_id,
            case=StructuralReportCase(
                schema_version="1.0",
                case_id=case.case_id,
                status=case.status,
                privacy_mode=case.privacy_mode,
                claim=case.claim,
            ),
            evidence=StructuralReportEvidence(
                schema_version="1.0",
                evidence_id=context.evidence.evidence_id,
                filename=context.evidence.filename,
                mime_type=context.evidence.mime_type,
                client_mime_type=context.client_mime_type,
                byte_length=context.evidence.byte_length,
                sha256=context.evidence.sha256,
                sha512=context.evidence.sha512,
                storage_uri=context.evidence.storage_uri,
            ),
            integrity=integrity,
            tool_inventory=engine_result.tool_inventory,
            tests=tests,
            structural_summary=engine_result.summary,
            consistency_findings=engine_result.consistency_findings,
            warnings=sorted({warning for result in tests for warning in result.warnings}),
            limitations=[
                "Structural metadata can be absent, inaccurate, edited, or parser-dependent.",
                (
                    "This phase performs no neural inference, frame extraction, OSINT, "
                    "or authenticity verdict."
                ),
                (
                    "Tool unavailability and non-applicable tests are coverage states, "
                    "not evidence conclusions."
                ),
            ],
            generated_at=engine_result.completed_at,
            software=StructuralSoftwareIdentity(
                schema_version="1.0",
                application_version=APPLICATION_VERSION,
                git_commit=self.git_commit,
            ),
        )
        report_json = canonical_json_bytes(report)
        json_stored = self.result_storage.put_bytes(
            context.evidence.case_id, run_id, "report.json", report_json
        )
        stored_json = self.result_storage.read_bytes(json_stored.storage_uri)
        report_html = render_structural_html(stored_json, self.template_directory)
        html_stored = self.result_storage.put_bytes(
            context.evidence.case_id, run_id, "report.html", report_html
        )
        manifest = ReportManifest(
            schema_version="1.0",
            report_id=report_id,
            case_id=context.evidence.case_id,
            generated_at=engine_result.completed_at,
            generator_name="forensic-structural-report",
            generator_version=APPLICATION_VERSION,
            generator_repository_commit=self.git_commit or ZERO_COMMIT,
            evidence=[
                ReportEvidenceReference(
                    schema_version="1.0",
                    evidence_id=context.evidence.evidence_id,
                    sha256=context.evidence.sha256,
                    sha512=context.evidence.sha512,
                )
            ],
            forensic_test_result_ids=[item.test_result_id for item in tests],
            test_coverage=[
                TestCoverageEntry(
                    schema_version="1.0",
                    test_name=item.test_name,
                    status=item.status,
                    test_result_id=item.test_result_id,
                )
                for item in tests
            ],
            artifacts=[
                ReportArtifact(
                    schema_version="1.0",
                    format="json",
                    storage_uri=json_stored.storage_uri,
                    sha256=json_stored.sha256,
                    byte_length=json_stored.byte_length,
                ),
                ReportArtifact(
                    schema_version="1.0",
                    format="html",
                    storage_uri=html_stored.storage_uri,
                    sha256=html_stored.sha256,
                    byte_length=html_stored.byte_length,
                ),
            ],
        )
        for kind, stored, mime in (
            ("structural-report-json", json_stored, "application/json"),
            ("structural-report-html", html_stored, "text/html"),
        ):
            artifact_records.append(
                StructuralArtifactInsert(
                    artifact_id=uuid4(),
                    kind=kind,
                    storage_uri=stored.storage_uri,
                    sha256=stored.sha256,
                    byte_length=stored.byte_length,
                    mime_type=mime,
                    tool_source="forensic-structural-report",
                )
            )
        run = StructuralAnalysisRun(
            schema_version="1.0",
            analysis_run_id=run_id,
            case_id=context.evidence.case_id,
            evidence_id=context.evidence.evidence_id,
            analysis_profile=ANALYSIS_PROFILE,
            status=engine_result.status,
            input_sha256=context.evidence.sha256,
            started_at=started_at,
            completed_at=engine_result.completed_at,
            integrity=integrity,
            test_results=tests,
            summary=engine_result.summary,
            consistency_findings=engine_result.consistency_findings,
            report_manifest=manifest,
        )
        report_insert = StructuralReportInsert(
            report_id=report_id,
            case_id=context.evidence.case_id,
            evidence_id=context.evidence.evidence_id,
            json_uri=json_stored.storage_uri,
            json_sha256=json_stored.sha256,
            json_byte_length=json_stored.byte_length,
            html_uri=html_stored.storage_uri,
            html_sha256=html_stored.sha256,
            html_byte_length=html_stored.byte_length,
            manifest=manifest,
        )
        tool_versions: dict[str, tuple[str | None, str | None]] = {
            test_id: (tool_name, versions.get(tool_name))
            for _, (test_id, tool_name) in RAW_TOOL_MAP.items()
        }
        self.repository.finalize_structural_run(
            run=run,
            artifacts=artifact_records,
            report=report_insert,
            tool_versions=tool_versions,
        )
        return run

    @staticmethod
    def _integrity_refusal(
        *,
        case_id: UUID,
        context: EvidenceAnalysisContext,
        run_id: UUID,
        started_at: datetime,
        verification: IntegrityVerification,
    ) -> StructuralAnalysisRun:
        result = ForensicTestResult(
            schema_version="1.0",
            test_result_id=uuid4(),
            case_id=case_id,
            evidence_id=context.evidence.evidence_id,
            test_name="structural.evidence-integrity.v1",
            test_version="1.0.0",
            status=ForensicTestStatus.FAILED,
            status_reason=verification.status_reason or "Evidence integrity verification failed.",
            raw_outputs={
                "integrity_status": verification.status.value,
                "expected_sha256": verification.expected_sha256,
                "verified_sha256": verification.verified_sha256,
                "expected_byte_length": verification.expected_byte_length,
                "verified_byte_length": verification.verified_byte_length,
            },
        )
        return StructuralAnalysisRun(
            schema_version="1.0",
            analysis_run_id=run_id,
            case_id=case_id,
            evidence_id=context.evidence.evidence_id,
            analysis_profile=ANALYSIS_PROFILE,
            status=StructuralAnalysisStatus.REFUSED,
            input_sha256=context.evidence.sha256,
            started_at=started_at,
            completed_at=verification.completed_at,
            integrity=verification,
            test_results=[result],
        )

    def _record_internal_failure(
        self,
        *,
        case_id: UUID,
        context: EvidenceAnalysisContext,
        run_id: UUID,
        started_at: datetime,
        integrity: IntegrityVerification,
    ) -> None:
        completed_at = datetime.now(UTC)
        result = ForensicTestResult(
            schema_version="1.0",
            test_result_id=uuid4(),
            case_id=case_id,
            evidence_id=context.evidence.evidence_id,
            test_name="structural.analysis-internal.v1",
            test_version="1.0.0",
            status=ForensicTestStatus.FAILED,
            status_reason="The structural analysis service failed safely.",
        )
        run = StructuralAnalysisRun(
            schema_version="1.0",
            analysis_run_id=run_id,
            case_id=case_id,
            evidence_id=context.evidence.evidence_id,
            analysis_profile=ANALYSIS_PROFILE,
            status=StructuralAnalysisStatus.FAILED,
            input_sha256=context.evidence.sha256,
            started_at=started_at,
            completed_at=completed_at,
            integrity=integrity,
            test_results=[result],
        )
        try:
            self.repository.finalize_structural_run(
                run=run, artifacts=[], report=None, tool_versions={}
            )
        except (SQLAlchemyError, LookupError, RuntimeError):
            return
