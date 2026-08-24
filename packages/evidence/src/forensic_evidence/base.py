"""Storage interfaces and stable evidence-intake failures."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


class StorageError(RuntimeError):
    """Base class for errors that prevent authoritative local preservation."""


class UploadTooLargeError(StorageError):
    pass


class EmptyEvidenceError(StorageError):
    pass


class UnsupportedMediaTypeError(StorageError):
    pass


class StorageReadError(StorageError):
    pass


class StorageWriteError(StorageError):
    pass


class StoragePromotionError(StorageError):
    pass


class ExistingObjectMismatchError(StorageError):
    pass


class InvalidStoragePathError(StorageError):
    pass


class StorageUnavailableError(StorageError):
    pass


class ReadableStream(Protocol):
    """Minimum bounded-read interface accepted by the storage backend."""

    def read(self, size: int = -1) -> bytes: ...


@dataclass(frozen=True, slots=True)
class StoredBlob:
    sha256: str
    sha512: str
    byte_length: int
    detected_mime_type: str
    storage_uri: str
    object_version: str
    content_created: bool


class StorageBackend(Protocol):
    def put_stream(self, stream: ReadableStream) -> StoredBlob: ...

    def contains(self, sha256: str, *, expected_size: int | None = None) -> bool: ...

    def path_for_sha256(self, sha256: str) -> Path: ...

    def resolve_uri(self, storage_uri: str, *, expected_sha256: str) -> Path: ...

    def iter_content_hashes(self) -> set[str]: ...

    def healthcheck(self) -> bool: ...
