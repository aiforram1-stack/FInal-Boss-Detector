"""Case application service."""

from __future__ import annotations

from uuid import UUID

from forensic_contracts import Case, EvidenceAsset, PrivacyMode
from sqlalchemy.exc import SQLAlchemyError

from forensic_api.db.repositories import Repository
from forensic_api.errors import ApiError


class CaseService:
    def __init__(self, repository: Repository) -> None:
        self.repository = repository

    def create(self, claim: str | None, privacy_mode: PrivacyMode) -> Case:
        try:
            return self.repository.create_case(claim, privacy_mode)
        except SQLAlchemyError as exc:
            raise ApiError(503, "DATABASE_UNAVAILABLE", "Case storage is unavailable.") from exc

    def get(self, case_id: UUID) -> Case:
        try:
            case = self.repository.get_case(case_id)
        except SQLAlchemyError as exc:
            raise ApiError(503, "DATABASE_UNAVAILABLE", "Case storage is unavailable.") from exc
        if case is None:
            raise ApiError(404, "CASE_NOT_FOUND", "The requested case was not found.")
        return case

    def detail(self, case_id: UUID) -> tuple[Case, list[EvidenceAsset]]:
        case = self.get(case_id)
        try:
            return case, self.repository.list_evidence(case_id)
        except SQLAlchemyError as exc:
            raise ApiError(503, "DATABASE_UNAVAILABLE", "Case storage is unavailable.") from exc

    def evidence(self, case_id: UUID, evidence_id: UUID) -> EvidenceAsset:
        self.get(case_id)
        try:
            evidence = self.repository.get_evidence(case_id, evidence_id)
        except SQLAlchemyError as exc:
            raise ApiError(
                503, "DATABASE_UNAVAILABLE", "Evidence metadata is unavailable."
            ) from exc
        if evidence is None:
            raise ApiError(404, "EVIDENCE_NOT_FOUND", "The requested evidence was not found.")
        return evidence
