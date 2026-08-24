"""Bounded persistence operations and shared-contract mapping."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID, uuid4

from forensic_contracts import Case, CaseStatus, EvidenceAsset, PrivacyMode
from forensic_evidence import StoredBlob
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from forensic_api.db.models import CaseRecord, EvidenceAssetRecord, EvidenceBlobRecord


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
