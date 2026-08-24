from __future__ import annotations

import hashlib
import io
import stat
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from forensic_evidence import (
    InvalidStoragePathError,
    LocalContentAddressedStorage,
    StorageWriteError,
    UnsupportedMediaTypeError,
    UploadTooLargeError,
)

PNG = b"\x89PNG\r\n\x1a\n" + b"generated-phase-2-fixture" * 8


def storage(root: Path, *, maximum: int = 4096, chunk: int = 17) -> LocalContentAddressedStorage:
    return LocalContentAddressedStorage(
        root,
        max_upload_bytes=maximum,
        upload_chunk_bytes=chunk,
        allowed_media_types=frozenset({"image/png"}),
    )


def test_hash_path_uri_permissions_and_no_filename_input(tmp_path: Path) -> None:
    backend = storage(tmp_path / "evidence")
    result = backend.put_stream(io.BytesIO(PNG))
    expected = hashlib.sha256(PNG).hexdigest()
    path = backend.path_for_sha256(expected)

    assert path == backend.root / "sha256" / expected[:2] / expected[2:4] / expected
    assert path.read_bytes() == PNG
    assert result.sha512 == hashlib.sha512(PNG).hexdigest()
    assert result.storage_uri == f"local-sha256://{expected}"
    assert str(tmp_path) not in result.storage_uri
    assert path.stat().st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH) == 0
    assert list(backend.staging_root.iterdir()) == []


def test_rejects_unsupported_and_oversized_and_cleans_staging(tmp_path: Path) -> None:
    backend = storage(tmp_path / "evidence", maximum=len(PNG) - 1)
    with pytest.raises(UploadTooLargeError):
        backend.put_stream(io.BytesIO(PNG))
    assert list(backend.staging_root.iterdir()) == []

    backend = storage(tmp_path / "other")
    with pytest.raises(UnsupportedMediaTypeError):
        backend.put_stream(io.BytesIO(b"plain text"))
    assert list(backend.staging_root.iterdir()) == []


def test_simulated_write_failure_cleans_staging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = storage(tmp_path / "evidence")

    def fail_write(*_: object) -> None:
        raise OSError("simulated disk failure")

    monkeypatch.setattr(backend, "_write_chunk", fail_write)
    with pytest.raises(StorageWriteError):
        backend.put_stream(io.BytesIO(PNG))
    assert list(backend.staging_root.iterdir()) == []


class BoundedStream:
    def __init__(self, content: bytes) -> None:
        self.content = io.BytesIO(content)
        self.requests: list[int] = []

    def read(self, size: int = -1) -> bytes:
        self.requests.append(size)
        if size < 0:
            raise AssertionError("unbounded read requested")
        return self.content.read(size)


def test_stream_reads_are_bounded(tmp_path: Path) -> None:
    backend = storage(tmp_path / "evidence", chunk=13)
    stream = BoundedStream(PNG)
    backend.put_stream(stream)
    assert stream.requests
    assert set(stream.requests) == {13}


def test_concurrent_duplicate_promotion_never_overwrites(tmp_path: Path) -> None:
    backend = storage(tmp_path / "evidence")
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: backend.put_stream(io.BytesIO(PNG)), range(2)))
    assert sorted(item.content_created for item in results) == [False, True]
    assert backend.path_for_sha256(results[0].sha256).read_bytes() == PNG
    assert len(backend.iter_content_hashes()) == 1


@pytest.mark.parametrize("unsafe_hash", ["../escape", "/absolute", "A" * 64, "a" * 63])
def test_invalid_hash_cannot_resolve_path(tmp_path: Path, unsafe_hash: str) -> None:
    backend = storage(tmp_path / "evidence")
    with pytest.raises(ValueError):
        backend.path_for_sha256(unsafe_hash)


def test_resolve_uri_requires_exact_expected_hash(tmp_path: Path) -> None:
    backend = storage(tmp_path / "evidence")
    result = backend.put_stream(io.BytesIO(PNG))
    assert backend.resolve_uri(
        result.storage_uri, expected_sha256=result.sha256
    ) == backend.path_for_sha256(result.sha256)
    with pytest.raises(InvalidStoragePathError, match="does not match"):
        backend.resolve_uri(f"local-sha256://{'c' * 64}", expected_sha256=result.sha256)
