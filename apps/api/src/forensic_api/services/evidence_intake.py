"""Compensating transaction across immutable storage and SQLite metadata."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from uuid import UUID

from forensic_contracts import EvidenceAsset
from forensic_evidence import (
    EmptyEvidenceError,
    ExistingObjectMismatchError,
    InvalidStoragePathError,
    ReadableStream,
    StorageBackend,
    StoragePromotionError,
    StorageReadError,
    StorageUnavailableError,
    StorageWriteError,
    UnsupportedMediaTypeError,
    UploadTooLargeError,
)
from sqlalchemy.exc import SQLAlchemyError

from forensic_api.db.repositories import Repository
from forensic_api.errors import ApiError

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class IntakeResult:
    evidence: EvidenceAsset
    content_deduplicated: bool
    association_reused: bool


class EvidenceIntakeService:
    def __init__(self, repository: Repository, storage: StorageBackend) -> None:
        self.repository = repository
        self.storage = storage

    def ingest(
        self,
        *,
        case_id: UUID,
        stream: ReadableStream,
        original_filename: str | None,
        client_mime_type: str | None,
    ) -> IntakeResult:
        try:
            case = self.repository.get_case(case_id)
        except SQLAlchemyError as exc:
            raise ApiError(503, "DATABASE_UNAVAILABLE", "Case storage is unavailable.") from exc
        if case is None:
            raise ApiError(404, "CASE_NOT_FOUND", "The requested case was not found.")
        filename = self._validate_filename(original_filename)
        declared_type = self._validate_declared_type(client_mime_type)
        try:
            blob = self.storage.put_stream(stream)
        except UploadTooLargeError as exc:
            raise ApiError(
                413, "UPLOAD_TOO_LARGE", "The submitted evidence exceeds the configured limit."
            ) from exc
        except EmptyEvidenceError as exc:
            raise ApiError(400, "EMPTY_EVIDENCE", "An evidence file must contain bytes.") from exc
        except UnsupportedMediaTypeError as exc:
            raise ApiError(
                415, "UNSUPPORTED_MEDIA_TYPE", "The evidence byte signature is not allowed."
            ) from exc
        except StorageReadError as exc:
            raise ApiError(
                400, "UPLOAD_INTERRUPTED", "The evidence stream could not be read."
            ) from exc
        except (
            ExistingObjectMismatchError,
            InvalidStoragePathError,
            StoragePromotionError,
            StorageUnavailableError,
            StorageWriteError,
        ) as exc:
            raise ApiError(503, "STORAGE_UNAVAILABLE", "Evidence storage is unavailable.") from exc

        try:
            inserted = self.repository.record_evidence(
                case_id=case_id,
                blob=blob,
                original_filename=filename,
                client_mime_type=declared_type,
            )
        except (LookupError, SQLAlchemyError, RuntimeError) as exc:
            logger.error("evidence metadata transaction failed", exc_info=False)
            raise ApiError(
                503, "DATABASE_UNAVAILABLE", "Evidence metadata could not be committed."
            ) from exc

        if not self.storage.contains(blob.sha256, expected_size=blob.byte_length):
            try:
                self.repository.compensate_missing_object(
                    inserted.evidence.evidence_id, blob.sha256
                )
            except SQLAlchemyError:
                logger.error("evidence consistency compensation failed", exc_info=False)
            raise ApiError(
                503,
                "EVIDENCE_CONSISTENCY_FAILURE",
                "Evidence preservation could not be verified.",
            )
        return IntakeResult(
            evidence=inserted.evidence,
            content_deduplicated=not blob.content_created,
            association_reused=inserted.association_reused,
        )

    @staticmethod
    def _validate_filename(filename: str | None) -> str:
        if filename is None or not filename or len(filename) > 255:
            raise ApiError(422, "INVALID_FILENAME", "A valid evidence filename is required.")
        if any(ord(character) < 32 or ord(character) == 127 for character in filename):
            raise ApiError(422, "INVALID_FILENAME", "The evidence filename contains controls.")
        return filename

    @staticmethod
    def _validate_declared_type(client_mime_type: str | None) -> str | None:
        if client_mime_type is None:
            return None
        if len(client_mime_type) > 127 or any(
            ord(character) < 32 or ord(character) == 127 for character in client_mime_type
        ):
            raise ApiError(422, "INVALID_CLIENT_MIME", "The declared media type is invalid.")
        return client_mime_type
