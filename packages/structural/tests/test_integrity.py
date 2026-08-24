from __future__ import annotations

import stat
from pathlib import Path

from forensic_contracts import IntegrityStatus
from forensic_structural.integrity import IntegrityVerifier

from .helpers import PNG, stored_evidence


def test_valid_integrity_and_verifier_never_modifies_original(tmp_path: Path) -> None:
    backend, evidence, path = stored_evidence(tmp_path)
    before = path.read_bytes()
    before_mode = path.stat().st_mode
    check = IntegrityVerifier(backend, chunk_bytes=7).verify(evidence)
    assert check.verification.status == IntegrityStatus.VERIFIED
    assert check.evidence_path == path
    assert path.read_bytes() == before == PNG
    assert path.stat().st_mode == before_mode
    assert path.stat().st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH) == 0


def test_tampered_object_is_refused(tmp_path: Path) -> None:
    backend, evidence, path = stored_evidence(tmp_path)
    path.chmod(0o600)
    path.write_bytes(b"X" * len(PNG))
    path.chmod(0o444)
    check = IntegrityVerifier(backend).verify(evidence)
    assert check.verification.status == IntegrityStatus.HASH_MISMATCH
    assert check.evidence_path is None
    assert check.verification.verified_sha256 != evidence.sha256


def test_missing_object_is_refused(tmp_path: Path) -> None:
    backend, evidence, path = stored_evidence(tmp_path)
    path.unlink()
    check = IntegrityVerifier(backend).verify(evidence)
    assert check.verification.status == IntegrityStatus.OBJECT_MISSING
    assert check.evidence_path is None


def test_database_size_mismatch_is_refused(tmp_path: Path) -> None:
    backend, evidence, _ = stored_evidence(tmp_path)
    inconsistent = evidence.model_copy(update={"byte_length": evidence.byte_length + 1})
    check = IntegrityVerifier(backend).verify(inconsistent)
    assert check.verification.status == IntegrityStatus.SIZE_MISMATCH
    assert check.verification.verified_byte_length == evidence.byte_length


def test_mismatched_logical_uri_is_not_resolved(tmp_path: Path) -> None:
    backend, evidence, _ = stored_evidence(tmp_path)
    inconsistent = evidence.model_copy(update={"storage_uri": f"local-sha256://{'c' * 64}"})
    check = IntegrityVerifier(backend).verify(inconsistent)
    assert check.verification.status == IntegrityStatus.OBJECT_MISSING
