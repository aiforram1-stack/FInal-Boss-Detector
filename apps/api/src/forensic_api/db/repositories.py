"""Bounded persistence operations and shared-contract mapping."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID, uuid4

from forensic_contracts import (
    Case,
    CaseStatus,
    EvidenceAsset,
    PrivacyMode,
    ReportManifest,
    StructuralAnalysisRun,
    StructuralAnalysisStatus,
)
from forensic_evidence import StoredBlob
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from forensic_api.db.models import (
    CaseRecord,
    EvidenceAssetRecord,
    EvidenceBlobRecord,
    StructuralAnalysisRunRecord,
    StructuralArtifactRecord,
    StructuralReportRecord,
    StructuralTestResultRecord,
)


def utc_now_text() -> str:
    return datetime.now(UTC).isoformat()


def to_case(record: CaseRecord) -> Case:
    return Case(
        schema_version=record.schema_version,
        case_id=UUID(record.case_id),
        created_at=datetime.fromisoformat(record.created_at),
        status=CaseStatus(record.status),
        claim=record.claim,
        privacy_mode=PrivacyMode(record.privacy_mode),
    )


def to_evidence(record: EvidenceAssetRecord, blob: EvidenceBlobRecord) -> EvidenceAsset:
    return EvidenceAsset(
        schema_version=record.schema_version,
        evidence_id=UUID(record.evidence_id),
        case_id=UUID(record.case_id),
        filename=record.original_filename,
        byte_length=blob.byte_length,
        mime_type=blob.detected_mime_type,
        sha256=blob.sha256,
        sha512=blob.sha512,
        storage_uri=blob.storage_uri,
        object_version=blob.object_version,
        created_at=datetime.fromisoformat(record.created_at),
    )


@dataclass(frozen=True, slots=True)
class EvidenceInsertResult:
    evidence: EvidenceAsset
    association_reused: bool


@dataclass(frozen=True, slots=True)
class EvidenceAnalysisContext:
    evidence: EvidenceAsset
    client_mime_type: str | None


@dataclass(frozen=True, slots=True)
class StructuralArtifactInsert:
    artifact_id: UUID
    kind: str
    storage_uri: str
    sha256: str
    byte_length: int
    mime_type: str
    tool_source: str


@dataclass(frozen=True, slots=True)
class StructuralReportInsert:
    report_id: UUID
    case_id: UUID
    evidence_id: UUID
    json_uri: str
    json_sha256: str
    json_byte_length: int
    html_uri: str
    html_sha256: str
    html_byte_length: int
    manifest: ReportManifest


@dataclass(frozen=True, slots=True)
class StoredReportLocation:
    json_uri: str
    json_sha256: str
    html_uri: str
    html_sha256: str


class ActiveStructuralAnalysisError(RuntimeError):
    pass


class Repository:
    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self.sessions = sessions

    def create_case(self, claim: str | None, privacy_mode: PrivacyMode) -> Case:
        now = utc_now_text()
        record = CaseRecord(
            case_id=str(uuid4()),
            schema_version="1.0",
            claim=claim,
            privacy_mode=privacy_mode.value,
            status=CaseStatus.CREATED.value,
            created_at=now,
            updated_at=now,
        )
        with self.sessions.begin() as session:
            session.add(record)
        return to_case(record)

    def get_case(self, case_id: UUID) -> Case | None:
        with self.sessions() as session:
            record = session.get(CaseRecord, str(case_id))
            return None if record is None else to_case(record)

    def list_evidence(self, case_id: UUID) -> list[EvidenceAsset]:
        statement = (
            select(EvidenceAssetRecord, EvidenceBlobRecord)
            .join(EvidenceBlobRecord, EvidenceAssetRecord.blob_sha256 == EvidenceBlobRecord.sha256)
            .where(EvidenceAssetRecord.case_id == str(case_id))
            .order_by(EvidenceAssetRecord.created_at, EvidenceAssetRecord.evidence_id)
        )
        with self.sessions() as session:
            return [to_evidence(asset, blob) for asset, blob in session.execute(statement)]

    def get_evidence(self, case_id: UUID, evidence_id: UUID) -> EvidenceAsset | None:
        statement = (
            select(EvidenceAssetRecord, EvidenceBlobRecord)
            .join(EvidenceBlobRecord, EvidenceAssetRecord.blob_sha256 == EvidenceBlobRecord.sha256)
            .where(
                EvidenceAssetRecord.case_id == str(case_id),
                EvidenceAssetRecord.evidence_id == str(evidence_id),
            )
        )
        with self.sessions() as session:
            row = session.execute(statement).one_or_none()
            return None if row is None else to_evidence(*row)

    def get_evidence_analysis_context(
        self, case_id: UUID, evidence_id: UUID
    ) -> EvidenceAnalysisContext | None:
        statement = (
            select(EvidenceAssetRecord, EvidenceBlobRecord)
            .join(EvidenceBlobRecord, EvidenceAssetRecord.blob_sha256 == EvidenceBlobRecord.sha256)
            .where(
                EvidenceAssetRecord.case_id == str(case_id),
                EvidenceAssetRecord.evidence_id == str(evidence_id),
            )
        )
        with self.sessions() as session:
            row = session.execute(statement).one_or_none()
            if row is None:
                return None
            asset, blob = row
            return EvidenceAnalysisContext(
                evidence=to_evidence(asset, blob), client_mime_type=asset.client_mime_type
            )

    def record_evidence(
        self,
        *,
        case_id: UUID,
        blob: StoredBlob,
        original_filename: str,
        client_mime_type: str | None,
    ) -> EvidenceInsertResult:
        now = utc_now_text()
        try:
            with self.sessions.begin() as session:
                case = session.get(CaseRecord, str(case_id))
                if case is None:
                    raise LookupError("case not found")
                existing = self._find_case_blob(session, case_id, blob.sha256)
                if existing is not None:
                    existing_asset, existing_blob = existing
                    return EvidenceInsertResult(to_evidence(existing_asset, existing_blob), True)
                current_blob = session.get(EvidenceBlobRecord, blob.sha256)
                if current_blob is None:
                    current_blob = EvidenceBlobRecord(
                        sha256=blob.sha256,
                        sha512=blob.sha512,
                        byte_length=blob.byte_length,
                        detected_mime_type=blob.detected_mime_type,
                        storage_uri=blob.storage_uri,
                        object_version=blob.object_version,
                        created_at=now,
                    )
                    session.add(current_blob)
                    session.flush()
                elif (
                    current_blob.sha512 != blob.sha512
                    or current_blob.byte_length != blob.byte_length
                    or current_blob.detected_mime_type != blob.detected_mime_type
                ):
                    raise RuntimeError("stored blob metadata mismatch")
                asset = EvidenceAssetRecord(
                    evidence_id=str(uuid4()),
                    schema_version="1.0",
                    case_id=str(case_id),
                    blob_sha256=blob.sha256,
                    original_filename=original_filename,
                    client_mime_type=client_mime_type,
                    created_at=now,
                )
                session.add(asset)
                case.status = CaseStatus.SEALED.value
                case.updated_at = now
            return EvidenceInsertResult(to_evidence(asset, current_blob), False)
        except IntegrityError:
            with self.sessions() as session:
                existing = self._find_case_blob(session, case_id, blob.sha256)
                if existing is None:
                    raise
                asset, stored_blob = existing
                return EvidenceInsertResult(to_evidence(asset, stored_blob), True)

    def _find_case_blob(
        self, session: Session, case_id: UUID, sha256: str
    ) -> tuple[EvidenceAssetRecord, EvidenceBlobRecord] | None:
        statement = (
            select(EvidenceAssetRecord, EvidenceBlobRecord)
            .join(EvidenceBlobRecord, EvidenceAssetRecord.blob_sha256 == EvidenceBlobRecord.sha256)
            .where(
                EvidenceAssetRecord.case_id == str(case_id),
                EvidenceAssetRecord.blob_sha256 == sha256,
            )
        )
        row = session.execute(statement).one_or_none()
        return None if row is None else (row[0], row[1])

    def compensate_missing_object(self, evidence_id: UUID, sha256: str) -> None:
        with self.sessions.begin() as session:
            asset = session.get(EvidenceAssetRecord, str(evidence_id))
            case_id = None if asset is None else asset.case_id
            session.execute(
                delete(EvidenceAssetRecord).where(
                    EvidenceAssetRecord.evidence_id == str(evidence_id)
                )
            )
            remaining = session.scalar(
                select(EvidenceAssetRecord.evidence_id)
                .where(EvidenceAssetRecord.blob_sha256 == sha256)
                .limit(1)
            )
            if remaining is None:
                session.execute(
                    delete(EvidenceBlobRecord).where(EvidenceBlobRecord.sha256 == sha256)
                )
            if case_id is not None:
                case_has_evidence = session.scalar(
                    select(EvidenceAssetRecord.evidence_id)
                    .where(EvidenceAssetRecord.case_id == case_id)
                    .limit(1)
                )
                if case_has_evidence is None:
                    case = session.get(CaseRecord, case_id)
                    if case is not None:
                        case.status = CaseStatus.CREATED.value
                        case.updated_at = utc_now_text()

    def referenced_blob_hashes(self) -> set[str]:
        with self.sessions() as session:
            return set(session.scalars(select(EvidenceBlobRecord.sha256)))

    def create_structural_run(
        self,
        *,
        run_id: UUID,
        case_id: UUID,
        evidence_id: UUID,
        analysis_profile: str,
        input_sha256: str,
        software_version: str,
        git_commit: str | None,
        started_at: datetime,
    ) -> None:
        record = StructuralAnalysisRunRecord(
            analysis_run_id=str(run_id),
            schema_version="1.0",
            case_id=str(case_id),
            evidence_id=str(evidence_id),
            analysis_profile=analysis_profile,
            status=StructuralAnalysisStatus.RUNNING.value,
            input_sha256=input_sha256,
            software_version=software_version,
            git_commit=git_commit,
            started_at=started_at.isoformat(),
            completed_at=None,
            terminal_json=None,
        )
        try:
            with self.sessions.begin() as session:
                session.add(record)
        except IntegrityError as exc:
            with self.sessions() as session:
                active = session.scalar(
                    select(StructuralAnalysisRunRecord.analysis_run_id).where(
                        StructuralAnalysisRunRecord.evidence_id == str(evidence_id),
                        StructuralAnalysisRunRecord.analysis_profile == analysis_profile,
                        StructuralAnalysisRunRecord.status
                        == StructuralAnalysisStatus.RUNNING.value,
                    )
                )
            if active is not None:
                raise ActiveStructuralAnalysisError("an active structural run exists") from exc
            raise

    def finalize_structural_run(
        self,
        *,
        run: StructuralAnalysisRun,
        artifacts: list[StructuralArtifactInsert],
        report: StructuralReportInsert | None,
        tool_versions: dict[str, tuple[str | None, str | None]],
    ) -> None:
        now = utc_now_text()
        with self.sessions.begin() as session:
            record = session.get(StructuralAnalysisRunRecord, str(run.analysis_run_id))
            if record is None:
                raise LookupError("structural run not found")
            if record.status != StructuralAnalysisStatus.RUNNING.value:
                raise RuntimeError("structural run is already terminal")
            for result in run.test_results:
                tool_name, tool_version = tool_versions.get(result.test_name, (None, None))
                session.add(
                    StructuralTestResultRecord(
                        result_id=str(result.test_result_id),
                        analysis_run_id=str(run.analysis_run_id),
                        test_id=result.test_name,
                        test_version=result.test_version,
                        status=result.status.value,
                        tool_name=tool_name,
                        tool_version=tool_version,
                        runtime_ms=result.runtime_ms,
                        result_json=result.model_dump_json(),
                        created_at=now,
                    )
                )
            for artifact in artifacts:
                session.add(
                    StructuralArtifactRecord(
                        artifact_id=str(artifact.artifact_id),
                        analysis_run_id=str(run.analysis_run_id),
                        kind=artifact.kind,
                        storage_uri=artifact.storage_uri,
                        sha256=artifact.sha256,
                        byte_length=artifact.byte_length,
                        mime_type=artifact.mime_type,
                        tool_source=artifact.tool_source,
                        created_at=now,
                    )
                )
            if report is not None:
                session.add(
                    StructuralReportRecord(
                        report_id=str(report.report_id),
                        schema_version="1.0",
                        analysis_run_id=str(run.analysis_run_id),
                        case_id=str(report.case_id),
                        evidence_id=str(report.evidence_id),
                        report_json_uri=report.json_uri,
                        report_json_sha256=report.json_sha256,
                        report_json_bytes=report.json_byte_length,
                        report_html_uri=report.html_uri,
                        report_html_sha256=report.html_sha256,
                        report_html_bytes=report.html_byte_length,
                        manifest_json=report.manifest.model_dump_json(),
                        created_at=now,
                    )
                )
            record.status = run.status.value
            record.completed_at = None if run.completed_at is None else run.completed_at.isoformat()
            record.terminal_json = run.model_dump_json()
            if run.status in {
                StructuralAnalysisStatus.COMPLETED,
                StructuralAnalysisStatus.PARTIAL,
            }:
                case = session.get(CaseRecord, str(run.case_id))
                if case is not None:
                    case.status = CaseStatus.ANALYZED.value
                    case.updated_at = now

    def list_structural_runs(self, case_id: UUID, evidence_id: UUID) -> list[StructuralAnalysisRun]:
        statement = (
            select(StructuralAnalysisRunRecord)
            .where(
                StructuralAnalysisRunRecord.case_id == str(case_id),
                StructuralAnalysisRunRecord.evidence_id == str(evidence_id),
            )
            .order_by(
                StructuralAnalysisRunRecord.started_at.desc(),
                StructuralAnalysisRunRecord.analysis_run_id.desc(),
            )
        )
        with self.sessions() as session:
            records = list(session.scalars(statement))
        runs: list[StructuralAnalysisRun] = []
        for record in records:
            if record.terminal_json is not None:
                runs.append(StructuralAnalysisRun.model_validate_json(record.terminal_json))
            else:
                runs.append(
                    StructuralAnalysisRun(
                        schema_version=record.schema_version,
                        analysis_run_id=UUID(record.analysis_run_id),
                        case_id=UUID(record.case_id),
                        evidence_id=UUID(record.evidence_id),
                        analysis_profile=record.analysis_profile,
                        status=StructuralAnalysisStatus.RUNNING,
                        input_sha256=record.input_sha256,
                        started_at=datetime.fromisoformat(record.started_at),
                    )
                )
        return runs

    def latest_structural_report(self, case_id: UUID) -> StoredReportLocation | None:
        statement = (
            select(StructuralReportRecord)
            .where(StructuralReportRecord.case_id == str(case_id))
            .order_by(
                StructuralReportRecord.created_at.desc(), StructuralReportRecord.report_id.desc()
            )
            .limit(1)
        )
        with self.sessions() as session:
            record = session.scalar(statement)
        if record is None:
            return None
        return StoredReportLocation(
            json_uri=record.report_json_uri,
            json_sha256=record.report_json_sha256,
            html_uri=record.report_html_uri,
            html_sha256=record.report_html_sha256,
        )
