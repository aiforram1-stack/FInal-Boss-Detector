"""Create-only local content-addressed evidence storage."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from pathlib import Path
from typing import BinaryIO
from uuid import uuid4

from forensic_evidence.base import (
    EmptyEvidenceError,
    ExistingObjectMismatchError,
    InvalidStoragePathError,
    ReadableStream,
    StoragePromotionError,
    StorageReadError,
    StorageUnavailableError,
    StorageWriteError,
    StoredBlob,
    UnsupportedMediaTypeError,
    UploadTooLargeError,
)
from forensic_evidence.media_types import detect_media_type

SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
SIGNATURE_BYTES = 8192


class LocalContentAddressedStorage:
    """Application-enforced append-only storage for local development.

    New objects are promoted with an atomic hard link. A link operation never
    replaces an existing destination, so concurrent duplicate uploads converge
    on the same immutable content object.
    """

    def __init__(
        self,
        root: Path,
        *,
        max_upload_bytes: int,
        upload_chunk_bytes: int,
        allowed_media_types: frozenset[str],
    ) -> None:
        if max_upload_bytes < 1 or upload_chunk_bytes < 1:
            raise ValueError("upload size and chunk size must be positive")
        if upload_chunk_bytes > max_upload_bytes:
            raise ValueError("upload chunk size cannot exceed maximum upload size")
        unresolved_root = root.expanduser()
        if unresolved_root.exists() and unresolved_root.is_symlink():
            raise InvalidStoragePathError("storage root cannot be a symbolic link")
        try:
            unresolved_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        except OSError as exc:
            raise StorageUnavailableError("storage root cannot be created") from exc
        self.root = unresolved_root.resolve()
        self.max_upload_bytes = max_upload_bytes
        self.upload_chunk_bytes = upload_chunk_bytes
        self.allowed_media_types = allowed_media_types
        self.content_root = self.root / "sha256"
        self.staging_root = self.root / ".staging"
        self._ensure_directory(self.content_root)
        self._ensure_directory(self.staging_root)

    def _ensure_directory(self, directory: Path) -> None:
        try:
            relative = directory.relative_to(self.root)
        except ValueError as exc:
            raise InvalidStoragePathError("storage directory escaped configured root") from exc
        current = self.root
        for part in relative.parts:
            current = current / part
            try:
                current.mkdir(mode=0o700)
            except FileExistsError:
                pass
            except OSError as exc:
                raise StorageUnavailableError("storage directory is unavailable") from exc
            try:
                mode = current.lstat().st_mode
            except OSError as exc:
                raise StorageUnavailableError("storage directory cannot be inspected") from exc
            if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
                raise InvalidStoragePathError("storage path contains a non-directory component")

    def _safe_candidate(self, candidate: Path) -> Path:
        try:
            candidate.relative_to(self.root)
        except ValueError as exc:
            raise InvalidStoragePathError("storage path escaped configured root") from exc
        resolved_parent = candidate.parent.resolve(strict=False)
        if resolved_parent != self.root and self.root not in resolved_parent.parents:
            raise InvalidStoragePathError("storage path resolved outside configured root")
        return candidate

    def path_for_sha256(self, sha256: str) -> Path:
        if not SHA256_RE.fullmatch(sha256):
            raise ValueError("invalid SHA-256")
        return self._safe_candidate(self.content_root / sha256[:2] / sha256[2:4] / sha256)

    def resolve_uri(self, storage_uri: str, *, expected_sha256: str) -> Path:
        """Resolve only the exact logical URI recorded for an expected content hash."""

        if storage_uri != f"local-sha256://{expected_sha256}":
            raise InvalidStoragePathError("storage URI does not match expected evidence hash")
        path = self.path_for_sha256(expected_sha256)
        try:
            mode = path.lstat().st_mode
        except FileNotFoundError:
            return path
        except OSError as exc:
            raise InvalidStoragePathError("evidence object cannot be inspected") from exc
        if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
            raise InvalidStoragePathError("evidence object is not a regular file")
        resolved = path.resolve(strict=True)
        try:
            resolved.relative_to(self.root)
        except ValueError as exc:
            raise InvalidStoragePathError("evidence object resolved outside storage root") from exc
        return resolved

    def _new_staging_path(self) -> Path:
        return self._safe_candidate(self.staging_root / f"{uuid4()}.part")

    def _open_staging(self, path: Path) -> BinaryIO:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags, 0o600)
            return os.fdopen(descriptor, "wb")
        except OSError as exc:
            raise StorageWriteError("staging file cannot be created") from exc

    def _write_chunk(self, output: BinaryIO, chunk: bytes) -> None:
        written = output.write(chunk)
        if written != len(chunk):
            raise OSError("short staging write")

    def _stream_to_staging(
        self, stream: ReadableStream, staging_path: Path
    ) -> tuple[str, str, int, bytes]:
        sha256 = hashlib.sha256()
        sha512 = hashlib.sha512()
        prefix = bytearray()
        total = 0
        try:
            with self._open_staging(staging_path) as output:
                while True:
                    try:
                        chunk = stream.read(self.upload_chunk_bytes)
                    except Exception as exc:
                        raise StorageReadError("upload stream could not be read") from exc
                    if not chunk:
                        break
                    if not isinstance(chunk, bytes):
                        raise StorageReadError("upload stream returned non-byte data")
                    total += len(chunk)
                    if total > self.max_upload_bytes:
                        raise UploadTooLargeError("upload exceeds configured maximum")
                    if len(prefix) < SIGNATURE_BYTES:
                        prefix.extend(chunk[: SIGNATURE_BYTES - len(prefix)])
                    sha256.update(chunk)
                    sha512.update(chunk)
                    try:
                        self._write_chunk(output, chunk)
                    except OSError as exc:
                        raise StorageWriteError("staging file could not be written") from exc
                try:
                    output.flush()
                    os.fsync(output.fileno())
                    os.fchmod(
                        output.fileno(),
                        stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH,
                    )
                except OSError as exc:
                    raise StorageWriteError(
                        "staging file could not be synchronized and sealed"
                    ) from exc
        except (StorageReadError, StorageWriteError, UploadTooLargeError):
            raise
        if total == 0:
            raise EmptyEvidenceError("zero-byte evidence is not accepted")
        return sha256.hexdigest(), sha512.hexdigest(), total, bytes(prefix)

    def _hash_existing(self, path: Path) -> tuple[str, str, int]:
        sha256 = hashlib.sha256()
        sha512 = hashlib.sha512()
        total = 0
        try:
            with path.open("rb") as existing:
                while chunk := existing.read(self.upload_chunk_bytes):
                    total += len(chunk)
                    sha256.update(chunk)
                    sha512.update(chunk)
        except OSError as exc:
            raise ExistingObjectMismatchError("existing object cannot be verified") from exc
        return sha256.hexdigest(), sha512.hexdigest(), total

    def _verify_existing(self, path: Path, sha256: str, sha512: str, size: int) -> None:
        try:
            mode = path.lstat().st_mode
        except OSError as exc:
            raise ExistingObjectMismatchError("existing object cannot be inspected") from exc
        if not stat.S_ISREG(mode):
            raise ExistingObjectMismatchError("existing content path is not a regular file")
        actual_sha256, actual_sha512, actual_size = self._hash_existing(path)
        if (actual_sha256, actual_sha512, actual_size) != (sha256, sha512, size):
            raise ExistingObjectMismatchError("existing content object does not match upload")

    def _promote(self, staging_path: Path, sha256: str, sha512: str, size: int) -> bool:
        destination = self.path_for_sha256(sha256)
        self._ensure_directory(destination.parent)
        try:
            os.link(staging_path, destination, follow_symlinks=False)
            created = True
        except FileExistsError:
            self._verify_existing(destination, sha256, sha512, size)
            return False
        except OSError as exc:
            raise StoragePromotionError("evidence object could not be promoted") from exc

        return created

    def put_stream(self, stream: ReadableStream) -> StoredBlob:
        staging_path = self._new_staging_path()
        try:
            sha256, sha512, byte_length, prefix = self._stream_to_staging(stream, staging_path)
            detected_mime_type = detect_media_type(prefix)
            if detected_mime_type is None or detected_mime_type not in self.allowed_media_types:
                raise UnsupportedMediaTypeError("media type is not supported")
            content_created = self._promote(staging_path, sha256, sha512, byte_length)
            return StoredBlob(
                sha256=sha256,
                sha512=sha512,
                byte_length=byte_length,
                detected_mime_type=detected_mime_type,
                storage_uri=f"local-sha256://{sha256}",
                object_version=sha256,
                content_created=content_created,
            )
        finally:
            try:
                staging_path.unlink(missing_ok=True)
            except OSError as exc:
                raise StorageWriteError("staging file could not be removed") from exc

    def contains(self, sha256: str, *, expected_size: int | None = None) -> bool:
        path = self.path_for_sha256(sha256)
        try:
            mode = path.lstat().st_mode
            if not stat.S_ISREG(mode):
                return False
            return expected_size is None or path.stat().st_size == expected_size
        except OSError:
            return False

    def iter_content_hashes(self) -> set[str]:
        hashes: set[str] = set()
        if not self.content_root.exists():
            return hashes
        for path in self.content_root.glob("*/*/*"):
            if SHA256_RE.fullmatch(path.name) and path.is_file() and not path.is_symlink():
                hashes.add(path.name)
        return hashes

    def healthcheck(self) -> bool:
        try:
            self._ensure_directory(self.content_root)
            self._ensure_directory(self.staging_root)
            return os.access(self.staging_root, os.W_OK | os.X_OK)
        except (InvalidStoragePathError, StorageUnavailableError, OSError):
            return False
