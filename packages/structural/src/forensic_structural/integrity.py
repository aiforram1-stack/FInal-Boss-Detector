"""Read-only integrity verification before structural analysis."""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from forensic_contracts import EvidenceAsset, IntegrityStatus, IntegrityVerification
from forensic_evidence import InvalidStoragePathError, StorageBackend


@dataclass(frozen=True, slots=True)
class IntegrityCheck:
    verification: IntegrityVerification
    evidence_path: Path | None


class IntegrityVerifier:
    def __init__(self, storage: StorageBackend, *, chunk_bytes: int = 1024 * 1024) -> None:
        if chunk_bytes < 1:
            raise ValueError("chunk_bytes must be positive")
        self.storage = storage
        self.chunk_bytes = chunk_bytes

    def verify(self, evidence: EvidenceAsset) -> IntegrityCheck:
        started_at = datetime.now(UTC)
        try:
            path = self.storage.resolve_uri(evidence.storage_uri, expected_sha256=evidence.sha256)
            if not path.exists():
                return self._failure(
                    evidence,
                    started_at,
                    IntegrityStatus.OBJECT_MISSING,
                    "The preserved evidence object is unavailable.",
                )
            sha256, sha512, byte_length = self._hash_read_only(path)
        except (InvalidStoragePathError, OSError, ValueError):
            return self._failure(
                evidence,
                started_at,
                IntegrityStatus.OBJECT_MISSING,
                "The preserved evidence object could not be resolved safely.",
            )

        status = IntegrityStatus.VERIFIED
        reason: str | None = None
        if byte_length != evidence.byte_length:
            status = IntegrityStatus.SIZE_MISMATCH
            reason = "The preserved evidence byte length does not match its database record."
        elif sha256 != evidence.sha256 or sha512 != evidence.sha512:
            status = IntegrityStatus.HASH_MISMATCH
            reason = "The preserved evidence digest does not match its database record."
        verification = IntegrityVerification(
            schema_version="1.0",
            evidence_id=evidence.evidence_id,
            expected_sha256=evidence.sha256,
            verified_sha256=sha256,
            expected_sha512=evidence.sha512,
            verified_sha512=sha512,
            expected_byte_length=evidence.byte_length,
            verified_byte_length=byte_length,
            status=status,
            started_at=started_at,
            completed_at=datetime.now(UTC),
            status_reason=reason,
        )
        return IntegrityCheck(
            verification=verification,
            evidence_path=path if status == IntegrityStatus.VERIFIED else None,
        )

    def _hash_read_only(self, path: Path) -> tuple[str, str, int]:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        sha256 = hashlib.sha256()
        sha512 = hashlib.sha512()
        byte_length = 0
        with os.fdopen(descriptor, "rb") as evidence_file:
            mode = os.fstat(evidence_file.fileno()).st_mode
            if not stat.S_ISREG(mode):
                raise OSError("evidence object is not a regular file")
            while chunk := evidence_file.read(self.chunk_bytes):
                byte_length += len(chunk)
                sha256.update(chunk)
                sha512.update(chunk)
        return sha256.hexdigest(), sha512.hexdigest(), byte_length

    @staticmethod
    def _failure(
        evidence: EvidenceAsset,
        started_at: datetime,
        status: IntegrityStatus,
        reason: str,
    ) -> IntegrityCheck:
        return IntegrityCheck(
            verification=IntegrityVerification(
                schema_version="1.0",
                evidence_id=evidence.evidence_id,
                expected_sha256=evidence.sha256,
                expected_sha512=evidence.sha512,
                expected_byte_length=evidence.byte_length,
                status=status,
                started_at=started_at,
                completed_at=datetime.now(UTC),
                status_reason=reason,
            ),
            evidence_path=None,
        )
